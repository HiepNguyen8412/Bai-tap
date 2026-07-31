#pragma once

#include "EngineApi.h"

#include <Windows.h>
#include <cstdint>
#include <string>

using namespace std;

// Dùng namespace để phân biệt chúng với API công khai như EngineInitalize, EngineScanFile
namespace ScanEngineInternal
{
	// Metadata dùng để xây dựng kết quả scan 
	// và cache key ở Service sau này.
	struct FileMetadata
	{
		uint64_t fileSize{ 0 };
		uint64_t lastWriteTime{ 0 };
	};

	// Chuyển đường dẫn đầu vào thành đường dẫn đầy đủ,
	// Ví dụ: 
	//		Test.exe
	// Thành:
	//		C:\Project\test.exe
	//
	// Hàm trả EngineStatus::Success nếu thành công.
	EngineStatus NormalizeFilePath(
		const wchar_t* inputPath,
		wstring& normallizedPath,
		DWORD& win32Error
	);

	// Kiểm tra extension thuộc:
	//
	// .exe .dll .sys .js .vbs .ps1
	bool HasRiskyExtension(
		const wstring& path
	);

	// Đọc tối đa maxBytes byte từ file và tính entropy.
	//
	// callback được gọi trong lúc đọc dữ liệu để:
	// - gửi progress
	// - kiểm tra cancel
	//
	// startProgress và endProgress xác định vùng progress
	// dành cho quá trình đọc file, ví dụ 20% đến 70%.
	EngineStatus CalculateFileEntropy(
		const wstring& path,
		uint64_t maxBytes,
		double& entropy,
		DWORD& win32Error,

		EngineProgressCallback callback,
		void* userContext,

		uint32_t startProgress,
		uint32_t endProgress,
		uint32_t prohressIntervalMs,

		ULONGLONG scanStartTick,
		uint32_t timeoutMs
	);
}