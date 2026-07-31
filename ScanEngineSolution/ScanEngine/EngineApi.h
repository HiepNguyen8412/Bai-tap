#pragma once

#include <Windows.h>
#include <cstdint>

// Phiên bản API 1.0
#define ENGINE_API_VERSION_1 0x00010000u
#define ENGINE_VERSION_STRING "1.0.0"

// Khi build ScanEngine.dll thì export hàm.
// Khi Service hoặc chương trình test sử dụng thì import hàm.
#ifdef SCANENGINE_EXPORTS
#define SCANENGINE_API extern "C" __declspec(dllexport)
#else
#define SCANENGINE_API extern "C" __declspec(dllimport)
#endif

// Mã trạng thái trả về từ Engine
enum class EngineStatus : std::uint32_t
{
    Success = 0,

    InvalidArgument,
    InvalidApiVersion,
    InvalidStructureSize,

    NotInitialized,
    AlreadyInitialized,

    FileNotFound,
    AccessDenied,
    OpenFileFailed,
    ReadFileFailed,

    Timeout,
    Cancelled,

    InternalError
};

// Giai đoạn hiện tại của quá trình scan
enum class EngineScanStage : std::uint32_t
{
    Starting = 0,
    OpeningFile,
    ReadingMetadata,
    ReadingContent,
    CalculatingEntropy,
    ApplyingRules,
    BuildingResult,
    Completed,
    Cancelled,
    Failed
};

// Kết luận cuối cùng
enum class EngineVerdict : std::uint32_t
{
    Safe = 0,
    Suspicious,
    Malicious
};

// Các rule đã khớp
enum EngineRuleFlags : std::uint32_t
{
    ENGINE_RULE_NONE = 0x00000000,

    ENGINE_RULE_OUTSIDE_C_DRIVE = 0x00000001,
    ENGINE_RULE_RISKY_EXTENSION = 0x00000002,
    ENGINE_RULE_LARGE_FILE = 0x00000004,
    ENGINE_RULE_HIGH_ENTROPY = 0x00000008
};

// Tùy chọn truyền vào khi scan
struct EngineScanOptionsV1
{
    std::uint32_t structSize;
    std::uint32_t apiVersion;

    std::uint32_t timeoutMs;

    double entropyThreshold;

    std::uint64_t maxEntropyBytes;

    std::uint32_t progressIntervalMs;

    std::uint32_t reserved;
};

// Kết quả cuối cùng
struct EngineScanResultV1
{
    std::uint32_t structSize;
    std::uint32_t apiVersion;

    EngineVerdict verdict;

    std::uint32_t riskScore;
    std::uint32_t matchedRules;
    std::uint32_t win32Error;

    std::uint64_t fileSize;
    std::uint64_t lastWriteTime;

    double entropy;

    std::uint64_t scanDurationMs;

    wchar_t description[256];
};

// Dữ liệu progress gửi về callback
struct EngineProgressInfoV1
{
    std::uint32_t structSize;
    std::uint32_t apiVersion;

    EngineScanStage stage;

    // Giá trị từ 0 đến 100
    std::uint32_t progressPercent;

    EngineStatus status;

    // Chỉ có kết quả khi scan hoàn tất
    const EngineScanResultV1* result;

    // Chỉ hợp lệ trong thời gian callback đang chạy
    const wchar_t* message;
};

// Callback trả TRUE để tiếp tục scan.
// Trả FALSE để yêu cầu hủy scan.
using EngineProgressCallback =
BOOL(WINAPI*)(
    const EngineProgressInfoV1* progressInfo,
    void* userContext
    );

// Khởi tạo Engine
SCANENGINE_API EngineStatus WINAPI EngineInitialize(
    const char* configJsonUtf8
);

// Scan một file
SCANENGINE_API EngineStatus WINAPI EngineScanFile(
    const wchar_t* path,
    const EngineScanOptionsV1* options,
    EngineProgressCallback callback,
    void* userContext
);

// Lấy phiên bản Engine
SCANENGINE_API const char* WINAPI EngineGetVersion();

// Dừng Engine
SCANENGINE_API void WINAPI EngineShutdown();