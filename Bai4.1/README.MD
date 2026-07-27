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

using namespace std;

class PEParser {
private:
    // fileBuffer
    // Lưu toàn bộ nội dung file PE dưới dạng mảng BYTE.
    // Sau khi đọc file xong:
    // fileBuffer
    // | MZ | DOS Header | DOS Stub | PE | Sections | ... |
    // Mọi Header phía sau đều chỉ là con trỏ trỏ vào vùng nhớ này.

    mutable vector<BYTE> fileBuffer;
    PIMAGE_DOS_HEADER pDosHeader = nullptr;
    PIMAGE_NT_HEADERS pNtHeaders = nullptr;
    PIMAGE_FILE_HEADER pFileHeader = nullptr;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = nullptr;

    static void PrintSectionTitle(const string& title) {
        cout << "\n" << string(72, '=') << "\n";
        cout << "=== " << title << " ===\n";
        cout << string(72, '=') << "\n";
    }

public:
    bool LoadPEFile(const string& filePath) {
        // Mở file PE ở chế độ nhị phân và đặt con trỏ file ở cuối
        // để lấy kích thước file nhanh bằng tellg().
        ifstream file(filePath, ios::binary | ios::ate);
        if (!file) {
            cerr << "[-] Khong mo duoc file!\n";
            return false;
        }

        size_t fileSize = file.tellg();
        fileBuffer.resize(fileSize);
        file.seekg(0);
        file.read(reinterpret_cast<char*>(fileBuffer.data()), fileSize);

        if (fileBuffer.size() < sizeof(IMAGE_DOS_HEADER)) return false;

        pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(fileBuffer.data());
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            cerr << "[-] Khong phai PE file (thieu 'MZ')\n";
            return false;
        }

        if (pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > fileBuffer.size()) return false;

        pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(fileBuffer.data() + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            cerr << "[-] Khong tim thay PE Signature ('PE\\0\\0')\n";
            return false;
        }

        pFileHeader = &pNtHeaders->FileHeader;
        pOptionalHeader = &pNtHeaders->OptionalHeader;

        cout << "[+] Load PE file thanh cong: " << filePath << "\n";
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
        cout << left << setw(30) << "Field" << "Value\n";
        cout << string(72, '-') << "\n";

        auto p = [&](const char* n, auto v) {
            cout << left << setw(30) << n << "0x" << hex << v << dec << "\n";
        };

        p("e_magic", pDosHeader->e_magic);
        p("e_lfanew", pDosHeader->e_lfanew);
    }

    void ParseNTHeaders() const {
        PrintSectionTitle("IMAGE_NT_HEADERS");
        cout << left << setw(30) << "Signature"
            << "0x" << hex << pNtHeaders->Signature << " (PE\\0\\0)\n" << dec;
    }

    void ParseFileHeader() const {
        PrintSectionTitle("IMAGE_FILE_HEADER");
        cout << left << setw(30) << "Machine" << "0x" << hex << pFileHeader->Machine << dec << "\n";
        cout << left << setw(30) << "NumberOfSections" << pFileHeader->NumberOfSections << "\n";
        cout << left << setw(30) << "TimeDateStamp" << "0x" << hex << pFileHeader->TimeDateStamp << dec << "\n";
        cout << left << setw(30) << "Characteristics" << "0x" << hex << pFileHeader->Characteristics << dec << "\n";
    }

    void ParseOptionalHeader() const {
        PrintSectionTitle("IMAGE_OPTIONAL_HEADER");
        cout << left << setw(30) << "Magic" << "0x" << hex << pOptionalHeader->Magic << dec << "\n";
        cout << left << setw(30) << "AddressOfEntryPoint" << "0x" << hex << pOptionalHeader->AddressOfEntryPoint << dec << "\n";
        cout << left << setw(30) << "ImageBase" << "0x" << hex << pOptionalHeader->ImageBase << dec << "\n";
        cout << left << setw(30) << "SectionAlignment" << pOptionalHeader->SectionAlignment << "\n";
        cout << left << setw(30) << "FileAlignment" << pOptionalHeader->FileAlignment << "\n";
        cout << left << setw(30) << "SizeOfImage" << pOptionalHeader->SizeOfImage << "\n";
        cout << left << setw(30) << "Subsystem" << pOptionalHeader->Subsystem << "\n";
        cout << left << setw(30) << "DllCharacteristics" << "0x" << hex << pOptionalHeader->DllCharacteristics << dec << "\n";
    }

    void ParseDataDirectories() const {
        PrintSectionTitle("DATA DIRECTORIES");
        const char* names[] = {
            "Export", "Import", "Resource", "Exception", "Security",
            "Base Relocation", "Debug", "Architecture", "GlobalPtr", "TLS",
            "Load Config", "Bound Import", "IAT", "Delay Import", "CLR", "Reserved"
        };

        cout << left << setw(6) << "Idx"
            << setw(18) << "Directory"
            << setw(14) << "RVA"
            << "Size\n";
        cout << string(72, '-') << "\n";

        for (int i = 0; i < 16; ++i) {
            auto& d = pOptionalHeader->DataDirectory[i];
            if (d.VirtualAddress == 0) continue;
            cout << left << setw(6) << i
                << setw(18) << names[i]
                << "0x" << hex << setw(10) << d.VirtualAddress << dec
                << "0x" << hex << d.Size << dec << "\n";
        }
    }

    void ParseSections() const {
        PrintSectionTitle("SECTION HEADERS");
        const PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNtHeaders);

        cout << left << setw(6) << "#"
            << setw(12) << "Name"
            << setw(14) << "VirtAddr"
            << setw(12) << "VirtSize"
            << setw(12) << "RawOff"
            << setw(12) << "RawSize"
            << "Characteristics\n";
        cout << string(72, '-') << "\n";

        for (WORD i = 0; i < pFileHeader->NumberOfSections; ++i) {
            cout << left << setw(6) << i + 1
                << setw(12) << reinterpret_cast<const char*>(pSec[i].Name)
                << "0x" << hex << setw(10) << pSec[i].VirtualAddress << dec
                << setw(12) << pSec[i].Misc.VirtualSize
                << "0x" << hex << setw(10) << pSec[i].PointerToRawData << dec
                << setw(12) << pSec[i].SizeOfRawData
                << "0x" << hex << pSec[i].Characteristics << dec << "\n";
        }
    }

    // ====================== EXPORT DIRECTORY ======================
    void ParseExportDirectory() const {
        auto& dir = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dir.VirtualAddress == 0) {
            cout << "\n=== EXPORT DIRECTORY: Khong co ===\n";
            return;
        }

        DWORD offset = RVAtoOffset(dir.VirtualAddress);
        if (offset == 0) return;

        const IMAGE_EXPORT_DIRECTORY* pExport =
            reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(fileBuffer.data() + offset);

        PrintSectionTitle("EXPORT DIRECTORY");
        const char* dllName = reinterpret_cast<const char*>(fileBuffer.data() + RVAtoOffset(pExport->Name));
        cout << left << setw(30) << "DLL Name" << (dllName ? dllName : "(null)") << "\n";
        cout << left << setw(30) << "Ordinal Base" << pExport->Base << "\n";
        cout << left << setw(30) << "Number of Functions" << pExport->NumberOfFunctions << "\n";
        cout << left << setw(30) << "Number of Names" << pExport->NumberOfNames << "\n";

        const DWORD* nameRVA = reinterpret_cast<const DWORD*>(fileBuffer.data() + RVAtoOffset(pExport->AddressOfNames));
        const WORD* ordinals = reinterpret_cast<const WORD*>(fileBuffer.data() + RVAtoOffset(pExport->AddressOfNameOrdinals));
        const DWORD* functions = reinterpret_cast<const DWORD*>(fileBuffer.data() + RVAtoOffset(pExport->AddressOfFunctions));

        cout << "\n";
        if (pExport->NumberOfNames == 0) {
            cout << "No named exports found." << "\n";
            return;
        }

        cout << left << setw(10) << "Ordinal"
            << setw(14) << "RVA"
            << "Name\n";
        cout << string(72, '-') << "\n";
        for (DWORD i = 0; i < pExport->NumberOfNames; ++i) {
            const char* name = reinterpret_cast<const char*>(fileBuffer.data() + RVAtoOffset(nameRVA[i]));
            DWORD ordinal = ordinals[i] + pExport->Base;
            DWORD rva = functions[ordinals[i]];
            cout << left << setw(10) << ordinal
                << "0x" << hex << setw(10) << rva << dec
                << (name ? name : "(null)") << "\n";
        }
    }

    // ====================== IMPORT DIRECTORY ======================
    void ParseImportDirectory() const {
        auto& dir = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (dir.VirtualAddress == 0) {
            cout << "\n=== IMPORT DIRECTORY: Khong co ===\n";
            return;
        }

        PrintSectionTitle("IMPORT DIRECTORY");
        DWORD offset = RVAtoOffset(dir.VirtualAddress);
        if (offset == 0) return;

        const IMAGE_IMPORT_DESCRIPTOR* pImport =
            reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(fileBuffer.data() + offset);

        while (pImport->Name != 0) {
            const char* dllName = reinterpret_cast<const char*>(fileBuffer.data() + RVAtoOffset(pImport->Name));
            cout << "\nDLL: " << (dllName ? dllName : "(null)") << "\n";
            cout << left << setw(10) << "Type" << "Name/Ordinal\n";
            cout << string(72, '-') << "\n";

            DWORD thunkRVA = pImport->OriginalFirstThunk ? pImport->OriginalFirstThunk : pImport->FirstThunk;
            const IMAGE_THUNK_DATA* pThunk =
                reinterpret_cast<const IMAGE_THUNK_DATA*>(fileBuffer.data() + RVAtoOffset(thunkRVA));

            while (pThunk->u1.AddressOfData != 0) {
                if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
                    cout << left << setw(10) << "Ordinal"
                        << IMAGE_ORDINAL(pThunk->u1.Ordinal) << "\n";
                }
                else {
                    const IMAGE_IMPORT_BY_NAME* pImportByName =
                        reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(fileBuffer.data() + RVAtoOffset((DWORD)pThunk->u1.AddressOfData));
                    const char* importName = pImportByName ? reinterpret_cast<const char*>(pImportByName->Name) : "(null)";
                    cout << left << setw(10) << "Name" << importName << "\n";
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
            cout << "\n=== RESOURCE DIRECTORY: Khong co ===\n";
            return;
        }

        PrintSectionTitle("RESOURCE DIRECTORY");
        cout << left << setw(24) << "Resource RVA" << "0x" << hex << dir.VirtualAddress << dec << "\n";
        cout << left << setw(24) << "Resource Size" << "0x" << hex << dir.Size << dec << "\n";
        cout << "(Basic resource tree parsing not implemented)\n";
    }

    // ====================== RELOCATION DIRECTORY ======================
    void ParseRelocationDirectory() const {
        auto& dir = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (dir.VirtualAddress == 0) {
            cout << "\n=== RELOCATION DIRECTORY: Khong co ===\n";
            return;
        }

        PrintSectionTitle("BASE RELOCATION DIRECTORY");
        DWORD offset = RVAtoOffset(dir.VirtualAddress);
        if (offset == 0) return;
        DWORD size = dir.Size;
        const BYTE* pReloc = fileBuffer.data() + offset;

        cout << left << setw(22) << "VirtualAddress" << "SizeOfBlock\n";
        cout << string(72, '-') << "\n";
        while (size > 0) {
            const IMAGE_BASE_RELOCATION* pBlock =
                reinterpret_cast<const IMAGE_BASE_RELOCATION*>(pReloc);

            if (pBlock->SizeOfBlock == 0) break;

            cout << left << setw(22) << hex << showbase << internal << setw(12)
                << pBlock->VirtualAddress << noshowbase << dec << setw(12)
                << pBlock->SizeOfBlock << "\n";

            size -= pBlock->SizeOfBlock;
            pReloc += pBlock->SizeOfBlock;
        }
    }

    void Run(const string& filePath) {
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

        cout << "\n=== Parse PE file hoan tat! ===\n";
    }
};

int wmain() {
    string path;
    cout << "=== PE Parser (Basic CFF Explorer) ===\n";
    cout << "Nhap duong dan file .exe hoac .dll: ";
    getline(cin, path);

    PEParser parser;
    parser.Run(path);

    system("pause");
    return 0;
}

//C:\Windows\System32\notepad.exe
//C:\Windows\System32\calc.exe
