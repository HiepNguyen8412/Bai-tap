#include "pch.h"
#include "EngineApi.h"

#include <atomic>

using namespace std;

namespace
{
	// Trạng thái dùng chung của Engine.
	//atomic giúp nhiều Thread kiểm tra trạng thái an toàn.
	atomic_bool g_initialized{ false };
}

// ============================================================
// Khởi tạo Engine
// ============================================================

SCANENGINE_API EngineStatus WINAPI EngineInitialize(
	const char* configJsonUtf8)
{
	// Hiện tại chưa xử lý JSON config.
	// Bổ sung phần này sau.
	UNREFERENCED_PARAMETER(configJsonUtf8);

	bool expected = false;

	// Chỉ chuyển trạng thái từ false thành true.
	// Nếu giá trị hiện tại đã là true thì Engine đã được khởi tạo.
	if (!g_initialized.compare_exchange_strong(
		expected,
		true))
	{
		return EngineStatus::AlreadyInitialized;
	}

	return EngineStatus::Success;
}

// ============================================================
// Lấy phiên bản Engine
// ============================================================

SCANENGINE_API EngineStatus WINAPI EngineScanFile(
	const wchar_t* path,
	const EngineScanOptionsV1* options,
	EngineProgressCallback callback,
	void* userContext)
{
	UNREFERENCED_PARAMETER(callback);
	UNREFERENCED_PARAMETER(userContext);

	// Không được scan trước khi Initianlize.
	if (!g_initialized.load())
	{
		return EngineStatus::NotInitialized;
	}

	// Kiểm tra tham số cơ bản,
	if (path == nullptr ||
		path[0] == L'/0' ||
		options == nullptr)
	{
		return EngineStatus::InvalidArgument;
	}

	// Chưa cài đặt chức năng scan thực tế.
	return EngineStatus::InternalError;
}