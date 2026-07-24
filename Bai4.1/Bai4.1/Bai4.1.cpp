// ================================================
// PE Parser - Basic CFF Explorer Clone
// Ngôn ngữ: C++17
// Windows API + Standard Library
// ================================================

#include <windows.h>
#include <winnt.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <fstream>

class PEParser {
private:
    // fileBuffer
    // Lưu toàn bộ nội dung file PE dưới dạng mảng BYTE.
    // Sau khi đọc file xong:
    // fileBuffer
    // | MZ | DOS Header | DOS Stub | PE | Sections | ... |
    // Mọi Header phía sau đều chỉ là con trỏ trỏ vào vùng nhớ này.

    mutable std::vector<BYTE> fileBuffer;
    PIMAGE_DOS_HEADER pDosHeader = nullptr;
    PIMAGE_NT_HEADERS pNtHeaders = nullptr;
    PIMAGE_FILE_HEADER pFileHeader = nullptr;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = nullptr;

    static void PrintSectionTitle(const std::string& title) {
        std::cout << "\n" << std::string(72, '=') << "\n";
        std::cout << "=== " << title << " ===\n";
        std::cout << std::string(72, '=') << "\n";
    }

public:
    bool LoadPEFile(const std::string& filePath) {
        // Mở file PE ở chế độ nhị phân và đặt con trỏ file ở cuối
        // để lấy kích thước file nhanh bằng tellg().
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file) {
            std::cerr << "[-] Khong mo duoc file!\n";
            return false;
        }

        size_t fileSize = file.tellg();
        fileBuffer.resize(fileSize);
        file.seekg(0);
        file.read(reinterpret_cast<char*>(fileBuffer.data()), fileSize);

        if (fileBuffer.size() < sizeof(IMAGE_DOS_HEADER)) return false;

        pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(fileBuffer.data());
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "[-] Khong phai PE file (thieu 'MZ')\n";
            return false;
        }

        if (pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > fileBuffer.size()) return false;

        pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(fileBuffer.data() + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            std::cerr << "[-] Khong tim thay PE Signature ('PE\\0\\0')\n";
            return false;
        }

        pFileHeader = &pNtHeaders->FileHeader;
        pOptionalHeader = &pNtHeaders->OptionalHeader;

        std::cout << "[+] Load PE file thanh cong: " << filePath << "\n";
        return true;
    }

    DWORD RVAtoOffset(DWORD rva) const {
        if (rva == 0) return 0;

        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD i = 0; i < pFileHeader->NumberOfSections; ++i) {
            if (rva >= pSection[i].VirtualAddress &&
                rva < pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize) {
                return pSection[i].PointerToRawData + (rva - pSection[i].VirtualAddress);
            }
        }
        return 0;
    }

    // ====================== PARSE FUNCTIONS ======================

    void ParseDOSHeader() const {
        PrintSectionTitle("IMAGE_DOS_HEADER");
        std::cout << std::left << std::setw(30) << "Field" << "Value\n";
        std::cout << std::string(72, '-') << "\n";

        auto p = [&](const char* n, auto v) {
            std::cout << std::left << std::setw(30) << n << "0x" << std::hex << v << std::dec << "\n";
        };

        p("e_magic", pDosHeader->e_magic);
        p("e_lfanew", pDosHeader->e_lfanew);
    }

    void ParseNTHeaders() const {
        PrintSectionTitle("IMAGE_NT_HEADERS");
        std::cout << std::left << std::setw(30) << "Signature"
            << "0x" << std::hex << pNtHeaders->Signature << " (PE\\0\\0)\n" << std::dec;
    }

    void ParseFileHeader() const {
        PrintSectionTitle("IMAGE_FILE_HEADER");
        std::cout << std::left << std::setw(30) << "Machine" << "0x" << std::hex << pFileHeader->Machine << std::dec << "\n";
        std::cout << std::left << std::setw(30) << "NumberOfSections" << pFileHeader->NumberOfSections << "\n";
        std::cout << std::left << std::setw(30) << "TimeDateStamp" << "0x" << std::hex << pFileHeader->TimeDateStamp << std::dec << "\n";
        std::cout << std::left << std::setw(30) << "Characteristics" << "0x" << std::hex << pFileHeader->Characteristics << std::dec << "\n";
    }

    void ParseOptionalHeader() const {
        PrintSectionTitle("IMAGE_OPTIONAL_HEADER");
        std::cout << std::left << std::setw(30) << "Magic" << "0x" << std::hex << pOptionalHeader->Magic << std::dec << "\n";
        std::cout << std::left << std::setw(30) << "AddressOfEntryPoint" << "0x" << std::hex << pOptionalHeader->AddressOfEntryPoint << std::dec << "\n";
        std::cout << std::left << std::setw(30) << "ImageBase" << "0x" << std::hex << pOptionalHeader->ImageBase << std::dec << "\n";
        std::cout << std::left << std::setw(30) << "SectionAlignment" << pOptionalHeader->SectionAlignment << "\n";
        std::cout << std::left << std::setw(30) << "FileAlignment" << pOptionalHeader->FileAlignment << "\n";
        std::cout << std::left << std::setw(30) << "SizeOfImage" << pOptionalHeader->SizeOfImage << "\n";
        std::cout << std::left << std::setw(30) << "Subsystem" << pOptionalHeader->Subsystem << "\n";
        std::cout << std::left << std::setw(30) << "DllCharacteristics" << "0x" << std::hex << pOptionalHeader->DllCharacteristics << std::dec << "\n";
    }

    void ParseDataDirectories() const {
        PrintSectionTitle("DATA DIRECTORIES");
        const char* names[] = {
            "Export", "Import", "Resource", "Exception", "Security",
            "Base Relocation", "Debug", "Architecture", "GlobalPtr", "TLS",
            "Load Config", "Bound Import", "IAT", "Delay Import", "CLR", "Reserved"
        };

        std::cout << std::left << std::setw(6) << "Idx"
            << std::setw(18) << "Directory"
            << std::setw(14) << "RVA"
            << "Size\n";
        std::cout << std::string(72, '-') << "\n";

        for (int i = 0; i < 16; ++i) {
            auto& d = pOptionalHeader->DataDirectory[i];
            if (d.VirtualAddress == 0) continue;
            std::cout << std::left << std::setw(6) << i
                << std::setw(18) << names[i]
                << "0x" << std::hex << std::setw(10) << d.VirtualAddress << std::dec
                << "0x" << std::hex << d.Size << std::dec << "\n";
        }
    }

    void ParseSections() const {
        PrintSectionTitle("SECTION HEADERS");
        const PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNtHeaders);

        std::cout << std::left << std::setw(6) << "#"
            << std::setw(12) << "Name"
            << std::setw(14) << "VirtAddr"
            << std::setw(12) << "VirtSize"
            << std::setw(12) << "RawOff"
            << std::setw(12) << "RawSize"
            << "Characteristics\n";
        std::cout << std::string(72, '-') << "\n";

        for (WORD i = 0; i < pFileHeader->NumberOfSections; ++i) {
            std::cout << std::left << std::setw(6) << i + 1
                << std::setw(12) << reinterpret_cast<const char*>(pSec[i].Name)
                << "0x" << std::hex << std::setw(10) << pSec[i].VirtualAddress << std::dec
                << std::setw(12) << pSec[i].Misc.VirtualSize
                << "0x" << std::hex << std::setw(10) << pSec[i].PointerToRawData << std::dec
                << std::setw(12) << pSec[i].SizeOfRawData
                << "0x" << std::hex << pSec[i].Characteristics << std::dec << "\n";
        }
    }

    // ====================== EXPORT DIRECTORY ======================
    void ParseExportDirectory() const {
        auto& dir = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dir.VirtualAddress == 0) {
            std::cout << "\n=== EXPORT DIRECTORY: Khong co ===\n";
            return;
        }

        DWORD offset = RVAtoOffset(dir.VirtualAddress);
        if (offset == 0) return;

        const IMAGE_EXPORT_DIRECTORY* pExport =
            reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(fileBuffer.data() + offset);

        PrintSectionTitle("EXPORT DIRECTORY");
        const char* dllName = reinterpret_cast<const char*>(fileBuffer.data() + RVAtoOffset(pExport->Name));
        std::cout << std::left << std::setw(30) << "DLL Name" << (dllName ? dllName : "(null)") << "\n";
        std::cout << std::left << std::setw(30) << "Ordinal Base" << pExport->Base << "\n";
        std::cout << std::left << std::setw(30) << "Number of Functions" << pExport->NumberOfFunctions << "\n";
        std::cout << std::left << std::setw(30) << "Number of Names" << pExport->NumberOfNames << "\n";

        const DWORD* nameRVA = reinterpret_cast<const DWORD*>(fileBuffer.data() + RVAtoOffset(pExport->AddressOfNames));
        const WORD* ordinals = reinterpret_cast<const WORD*>(fileBuffer.data() + RVAtoOffset(pExport->AddressOfNameOrdinals));
        const DWORD* functions = reinterpret_cast<const DWORD*>(fileBuffer.data() + RVAtoOffset(pExport->AddressOfFunctions));

        std::cout << "\n";
        if (pExport->NumberOfNames == 0) {
            std::cout << "No named exports found." << "\n";
            return;
        }

        std::cout << std::left << std::setw(10) << "Ordinal"
            << std::setw(14) << "RVA"
            << "Name\n";
        std::cout << std::string(72, '-') << "\n";
        for (DWORD i = 0; i < pExport->NumberOfNames; ++i) {
            const char* name = reinterpret_cast<const char*>(fileBuffer.data() + RVAtoOffset(nameRVA[i]));
            DWORD ordinal = ordinals[i] + pExport->Base;
            DWORD rva = functions[ordinals[i]];
            std::cout << std::left << std::setw(10) << ordinal
                << "0x" << std::hex << std::setw(10) << rva << std::dec
                << (name ? name : "(null)") << "\n";
        }
    }

    // ====================== IMPORT DIRECTORY ======================
    void ParseImportDirectory() const {
        auto& dir = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (dir.VirtualAddress == 0) {
            std::cout << "\n=== IMPORT DIRECTORY: Khong co ===\n";
            return;
        }

        PrintSectionTitle("IMPORT DIRECTORY");
        DWORD offset = RVAtoOffset(dir.VirtualAddress);
        if (offset == 0) return;

        const IMAGE_IMPORT_DESCRIPTOR* pImport =
            reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(fileBuffer.data() + offset);

        while (pImport->Name != 0) {
            const char* dllName = reinterpret_cast<const char*>(fileBuffer.data() + RVAtoOffset(pImport->Name));
            std::cout << "\nDLL: " << (dllName ? dllName : "(null)") << "\n";
            std::cout << std::left << std::setw(10) << "Type" << "Name/Ordinal\n";
            std::cout << std::string(72, '-') << "\n";

            DWORD thunkRVA = pImport->OriginalFirstThunk ? pImport->OriginalFirstThunk : pImport->FirstThunk;
            const IMAGE_THUNK_DATA* pThunk =
                reinterpret_cast<const IMAGE_THUNK_DATA*>(fileBuffer.data() + RVAtoOffset(thunkRVA));

            while (pThunk->u1.AddressOfData != 0) {
                if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
                    std::cout << std::left << std::setw(10) << "Ordinal"
                        << IMAGE_ORDINAL(pThunk->u1.Ordinal) << "\n";
                }
                else {
                    const IMAGE_IMPORT_BY_NAME* pImportByName =
                        reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(fileBuffer.data() + RVAtoOffset((DWORD)pThunk->u1.AddressOfData));
                    const char* importName = pImportByName ? reinterpret_cast<const char*>(pImportByName->Name) : "(null)";
                    std::cout << std::left << std::setw(10) << "Name" << importName << "\n";
                }
                ++pThunk;
            }
            ++pImport;
        }
    }

    // ====================== RESOURCE DIRECTORY (Basic) ======================
    void ParseResourceDirectory() const {
        auto& dir = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
        if (dir.VirtualAddress == 0) {
            std::cout << "\n=== RESOURCE DIRECTORY: Khong co ===\n";
            return;
        }

        PrintSectionTitle("RESOURCE DIRECTORY");
        std::cout << std::left << std::setw(24) << "Resource RVA" << "0x" << std::hex << dir.VirtualAddress << std::dec << "\n";
        std::cout << std::left << std::setw(24) << "Resource Size" << "0x" << std::hex << dir.Size << std::dec << "\n";
        std::cout << "(Basic resource tree parsing not implemented)\n";
    }

    // ====================== RELOCATION DIRECTORY ======================
    void ParseRelocationDirectory() const {
        auto& dir = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (dir.VirtualAddress == 0) {
            std::cout << "\n=== RELOCATION DIRECTORY: Khong co ===\n";
            return;
        }

        PrintSectionTitle("BASE RELOCATION DIRECTORY");
        DWORD offset = RVAtoOffset(dir.VirtualAddress);
        if (offset == 0) return;
        DWORD size = dir.Size;
        const BYTE* pReloc = fileBuffer.data() + offset;

        std::cout << std::left << std::setw(22) << "VirtualAddress" << "SizeOfBlock\n";
        std::cout << std::string(72, '-') << "\n";
        while (size > 0) {
            const IMAGE_BASE_RELOCATION* pBlock =
                reinterpret_cast<const IMAGE_BASE_RELOCATION*>(pReloc);

            if (pBlock->SizeOfBlock == 0) break;

            std::cout << std::left << std::setw(22) << std::hex << std::showbase << std::internal << std::setw(12)
                << pBlock->VirtualAddress << std::noshowbase << std::dec << std::setw(12)
                << pBlock->SizeOfBlock << "\n";

            size -= pBlock->SizeOfBlock;
            pReloc += pBlock->SizeOfBlock;
        }
    }

    void Run(const std::string& filePath) {
        if (!LoadPEFile(filePath)) return;

        ParseDOSHeader();
        ParseNTHeaders();
        ParseFileHeader();
        ParseOptionalHeader();
        ParseDataDirectories();
        ParseSections();
        ParseExportDirectory();
        ParseImportDirectory();
        ParseResourceDirectory();
        ParseRelocationDirectory();

        std::cout << "\n=== Parse PE file hoan tat! ===\n";
    }
};

int wmain() {
    std::string path;
    std::cout << "=== PE Parser (Basic CFF Explorer) ===\n";
    std::cout << "Nhap duong dan file .exe hoac .dll: ";
    std::getline(std::cin, path);

    PEParser parser;
    parser.Run(path);

    system("pause");
    return 0;
}

//C:\Windows\System32\notepad.exe
//C:\Windows\System32\calc.exe