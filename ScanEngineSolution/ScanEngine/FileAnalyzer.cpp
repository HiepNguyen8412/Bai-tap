#include "pch.h"

#include "FileAnlyzer.h"

#include <algorithm>
#include <array>
#include <cwctype>
#include <vector>

namespace
{
	// Mỗi lần đọc 64kb dữ liệu.
	constexpr DWORD READ_BUFFER_SIZE = 64 * 1024;

	// Chuyển mã lỗi Win32 thành trạng thái của Engine.
	EngineStatus MapFileError(DWORD errorCode)
	{
		switch (errorCode)
		{
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND:
		case ERROR_INVALID_NAME:
			return EngineStatus::FileNotFound;

		case ERROR_ACCESS_DENIED:
		case ERROR_SHARING_VIOLATION:
			return EngineStatus::AccessDenied;

		default:
			return EngineStatus::OpenFileFailed;
		}
	}

	// Kiểm tra quá trình scan đã vượt quá timeout chưa.
	//
	// timeoutMs == 0 nghĩa là không giới hạn thời gian.
	bool HasTimedout(
		ULONGLONG scanStartTick,
		uint32_t timeoutMs)
	{
		if (timeoutMs == 0)
		{
			return false;
		}

		const ULONGLONG elapsedTime =
			GetTickCount64() - scanStartTick;

		return elapsedTime >= timeoutMs;
	}

	// Gửi progress về phía chương trình gọi Engine.
	//
	// Callback trả TRUE  -> tiếp tục scan.
	// Callback trả FALSE -> hủy scan.
	bool ReportProgress(
		EngineProgressCallback callback,
		void* userContext,
		EngineScanStage stage,
		uint32_t percent,
		EngineStatus status,
		const wchar_t* message
	)
	{
		// Callback không bắt buộc phải có.
		if (callback == nullptr)
		{
			return true;
		}

		EngineProgressInfoV1 progressInfo{};

		progressInfo.structSize =
			sizeof(EngineProgressInfoV1);

		progressInfo.apiVersion =
			ENGINE_API_VERSION_1;

		progressInfo.stage = stage;

		// Không cho progress vượt quá 100%.
		progressInfo.progressPercent =
			min<uint32_t>(percent, 100);

		progressInfo.status = status;
		progressInfo.result = nullptr;
		progressInfo.message = message;

		return callback(
			&progressInfo,
			userContext) != FALSE;
	}

	bool IsPathSeparator(wchar_t character)
	{
		return character == L'\\' ||
			character == L'/';
	}
}

namespace ScanEngineInternal
{
	// ========================================================
	// Chuyển đường dẫn tương đối thành đường dẫn đầy đủ
	// ========================================================

	EngineStatus NormalizeFilePath(
		const wchar_t* inputPath,
		wstring& normalizedPath,
		DWORD& win32Error)
	{
		normalizedPath.clear();
		win32Error = ERROR_SUCCESS;

		if (inputPath == nullptr ||
			inputPath[0] == L'\0')
		{
			return EngineStatus::InvalidArgument;
		}

		// Lấy kích thước buffer cần thiết.
		const DWORD requiredLength =
			GetFullPathNameW(
				inputPath,
				0,
				nullptr,
				nullptr);

		if (requiredLength == 0)
		{
			win32Error = GetLastError();
			return EngineStatus::InvalidArgument;
		}

		vector<wchar_t> buffer(
			static_cast<size_t>(requiredLength) + 1,
			L'\0');

		const DWORD actualLength =
			GetFullPathNameW(
				inputPath,
				static_cast<DWORD>(buffer.size()),
				buffer.data(),
				nullptr);

		if (actualLength == 0)
		{
			win32Error = GetLastError();
			return EngineStatus::InvalidArgument;
		}

		if (actualLength >= buffer.size())
		{
			win32Error = ERROR_INSUFFICIENT_BUFFER;
			return EngineStatus::InternalError;
		}

		normalizedPath.assign(
			buffer.data(),
			actualLength);

		// Đồng nhất dấu / thành \.
		replace(
			normalizedPath.begin(),
			normalizedPath.end(),
			L'/',
			L'\\');

		return EngineStatus::Success;
	}

	// ========================================================
	// Đọc kích thước và lastWriteTime của file
	// ========================================================

	EngineStatus ReadFilemetadata(
		const wstring& path,
		FileMetadata& metadata,
		DWORD& win32Error)
	{
		metadata = {};
		win32Error = ERROR_SUCCESS;

		if (path.empty())
		{
			return EngineStatus::InvalidArgument;
		}

		WIN32_FILE_ATTRIBUTE_DATA fileData{};

		if (!GetFileAttributesExW(
			path.c_str(),
			GetFileExInfoStandard,
			&fileData))
		{
			win32Error = GetLastError();
			return MapFileError(win32Error);
		}

		// EngineScanFile chỉ nhận file, không nhận thư mục.
		if ((fileData.dwFileAttributes &
			FILE_ATTRIBUTE_DIRECTORY) != 0)
		{
			win32Error = ERROR_DIRECTORY;
			return EngineStatus::InvalidArgument;
		}

		// Ghép HighPart và LowPart để có kích thước 64-bit.
		ULARGE_INTEGER fileSize{};

		fileSize.HighPart =
			fileData.nFileSizeHigh;

		fileSize.LowPart =
			fileData.nFileSizeLow;

		metadata.fileSize =
			fileSize.QuadPart;

		// Chuyển FILETIME thành số nguyên 64-bit.
		ULARGE_INTEGER lastWriteTime{};

		lastWriteTime.HighPart =
			fileData.ftLastWriteTime.dwHighDateTime;

		lastWriteTime.LowPart =
			fileData.ftLastWriteTime.dwLowDateTime;

		metadata.lastWriteTime =
			lastWriteTime.QuadPart;

		return EngineStatus::Success;
	}

	// ========================================================
	// Kiểm tra file có nằm ngoài ổ C:\ hay không
	// ========================================================

	bool IsOutsideCDrive(
		const wstring& path)
	{
		if (path.empty())
		{
			return true;
		}

		size_t drivePosition = 0;
		
		// Xử lý các đường dẫn dạng:
		//
		// \\?\\C:\Folder\File.exe
		// \\.\\C:\Folder\File.exe
		if (path.size() >= 7 &&
			path[0] == L'\\' &&
			path[1] == L'\\' &&
			(path[2] == L'?' ||
				path[2] == L'.') &&
			path[3] == L'\\')
		{
			drivePosition = 4;
		}

		// Đường dẫn ổ đĩa phải có dạng:
		//
		// C:\...
		if (path.size() < drivePosition + 3 ||
			path[drivePosition + 1] != L':' ||
			!IsPathSeparator(
				path[drivePosition + 2]))
		{
			// Đường dẫn UNC hoặc đường dẫn không thuộc ổ đĩa.
			return true;
		}

		const wchar_t driveLetter =
			static_cast<wchar_t>(
				towupper(
					path[drivePosition]));
		return driveLetter != L'C';
	}

	// ========================================================
	// Kiểm tra phần mở rộng nguy hiểm
	// ========================================================

	bool HasRiskyExtension(
		const wstring& path)
	{
		if (path.empty())
		{
			return false;
		}

		const size_t slashPosition =
			path.find_last_of(L'\\');

		const size_t dotPosition =
			path.find_last_of(L'.');
		
		// Không có phần mở rộng.
		if (dotPosition == wstring::npos)
		{
			return false;
		}

		// Dấu chấm nằm trong tên thư mục chứ không nằm trong tên file.
		if (slashPosition != wstring::npos &&
			dotPosition < slashPosition)
		{
			return false;
		}

		wstring extension =
			path.substr(dotPosition);

		// Chuyển extension về chữ thường.
		transform(
			extension.begin(),
			extension.end(),
			extension.begin(),
			[](wchar_t character)
			{
				return static_cast<wchar_t>(
					towlower(character));
			});

		static const array<wstring, 6>
			riskyExtensions =
		{
			L".exe",
			L".dll",
			L".sys",
			L".js",
			L".vbs",
			L".ps1"
		};

		return find(
			riskyExtensions.begin(),
			riskyExtensions.end(),
			extension) != riskyExtensions.end();
	}

	// ========================================================
	// Đọc file và tính Shannon entropy
	// ========================================================

	EngineStatus CalcuateFileEntropy(
		const wstring& path,
		uint64_t maxBytes,
		double& entropy,
		DWORD& win32Error,
		EngineProgressCallback callback,
		void* userContext,
		uint32_t startProgress,
		uint32_t endProgress,
		uint32_t progressIntervalMs,
		ULONGLONG scanStartTick,
		uint32_t timeoutMs)
	{
		entropy = 0.0;
		win32Error = ERROR_SUCCESS;

		if (path.empty() ||
			maxBytes == 0 ||
			startProgress >> endProgress ||
			endProgress > 100)
		{
			return EngineStatus::InvalidArgument;
		}

		if (scanStartTick == 0)
		{
			scanStartTick = GetTickCount64();
		}

		if (HasTimedout(
			scanStartTick,
			timeoutMs))
		{
			return EngineStatus::Timeout;
		}

		HANDLE fileHandle =
			CreateFileW(
				path.c_str(),
				GENERIC_READ,

				// Cho phép đọc file ngay cả khi file đang được tiến trình khác mở.
				FILE_SHARE_READ |
					FILE_SHARE_WRITE |
					FILE_SHARE_DELETE,
			)
	}
}
