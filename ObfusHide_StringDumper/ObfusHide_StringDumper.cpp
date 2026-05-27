#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <windows.h>

using namespace std;

void printHeader() {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);
    cout << "   ____  __    ____           __  ___     __         _____ __       _             ____                                 \n";
    cout << "  / __ \\/ /_  / __/_  _______/ / / (_)___/ /__      / ___// /______(_)___  ____ _/ __ \\__  ______ ___  ____  ___  _____\n";
    cout << " / / / / __ \\/ /_/ / / / ___/ /_/ / / __  / _ \\     \\__ \\/ __/ ___/ / __ \\/ __ `/ / / / / / / __ `__ \\/ __ \\/ _ \\/ ___/\n";
    cout << "/ /_/ / /_/ / __/ /_/ (__  ) __  / / /_/ /  __/    ___/ / /_/ /  / / / / / /_/ / /_/ / /_/ / / / / / / /_/ /  __/ /    \n";
    cout << "\\____/_.___/_/  \\__,_/____/_/ /_/_/\\__,_/\\___/____/____/\\__/_/  /_/_/ /_/\\__, /_____/\\__,_/_/ /_/ /_/ .___/\\___/_/     \n";
    cout << "                                            /_____/                     /____/                     /_/                 \n\n";
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
}

// Function to convert a File Offset to a Virtual Address (VA) by parsing PE headers
uint64_t fileOffsetToVA(const vector<unsigned char>& d, size_t fileOffset) {
    if (d.size() < sizeof(IMAGE_DOS_HEADER)) return 0;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)d.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    if (dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > d.size()) return 0;

    PIMAGE_NT_HEADERS32 ntHeader32 = (PIMAGE_NT_HEADERS32)(d.data() + dosHeader->e_lfanew);
    uint64_t imageBase = 0;
    WORD numSections = 0;
    PIMAGE_SECTION_HEADER section = nullptr;

    if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        imageBase = ntHeader32->OptionalHeader.ImageBase;
        numSections = ntHeader32->FileHeader.NumberOfSections;
        section = IMAGE_FIRST_SECTION(ntHeader32);
    }
    else if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        PIMAGE_NT_HEADERS64 ntHeader64 = (PIMAGE_NT_HEADERS64)(d.data() + dosHeader->e_lfanew);
        imageBase = ntHeader64->OptionalHeader.ImageBase;
        numSections = ntHeader64->FileHeader.NumberOfSections;
        section = IMAGE_FIRST_SECTION(ntHeader64);
    }
    else {
        return 0; // Unknown format
    }

    for (int i = 0; i < numSections; i++, section++) {
        DWORD rawSize = section->SizeOfRawData;
        DWORD rawOffset = section->PointerToRawData;

        if (fileOffset >= rawOffset && fileOffset < rawOffset + rawSize) {
            DWORD rva = (DWORD)(fileOffset - rawOffset) + section->VirtualAddress;
            return imageBase + rva;
        }
    }

    // If it's in the headers
    if (fileOffset < ntHeader32->OptionalHeader.SizeOfHeaders) {
        return imageBase + fileOffset;
    }

    return 0; // Could not map
}

int main(int argc, char* argv[]) {
    printHeader();
    if (argc < 2) {
        cout << "Usage: " << argv[0] << " <path_to_exe>\n";
        return 1;
    }

    ifstream file(argv[1], ios::binary | ios::ate);
    if (!file.is_open()) return 1;

    streamsize size = file.tellg();
    file.seekg(0, ios::beg);

    if (size <= 0) return 1;

    vector<unsigned char> d(size);
    if (!file.read(reinterpret_cast<char*>(d.data()), size)) return 1;

    size_t s = d.size();
    int matchCount = 0;

    cout << "[+] Scanning file: " << argv[1] << " (" << s << " bytes)\n\n";

    // Core detection loop
    for (size_t j = 0; j + 4 < s; j++) {
        int ser = 0;
        size_t k = j;
        string decrypted_str = "";

        while (k + 4 <= s) {
            if (d[k] == 0xC6 && d[k + 1] == 0x45) { // mov [rbp+YY], XX
                decrypted_str += (char)d[k + 3];
                ser++; k += 4;
            }
            else if (k + 5 <= s && d[k] == 0xC6 && d[k + 1] == 0x44 && d[k + 2] == 0x24) { // mov [rsp+YY], XX
                decrypted_str += (char)d[k + 4];
                ser++; k += 5;
            }
            else if (k + 8 <= s && d[k] == 0xB8 && d[k + 2] == 0x00 && d[k + 3] == 0x00 && d[k + 4] == 0x00 && d[k + 5] == 0x88 && d[k + 6] == 0x45) {
                decrypted_str += (char)d[k + 1];
                ser++; k += 8;
            }
            else if (k + 11 <= s && d[k] == 0xB8 && d[k + 2] == 0x00 && d[k + 3] == 0x00 && d[k + 4] == 0x00 && d[k + 5] == 0x88 && d[k + 6] == 0x85) {
                decrypted_str += (char)d[k + 1];
                ser++; k += 11;
            }
            else break;
        }

        if (ser >= 4) {
            matchCount++;
            string display_str = "";
            for (char c : decrypted_str) {
                if (c >= 32 && c <= 126) {
                    display_str += c;
                }
            }

            // Convert File Offset to Virtual Address (VA) for x64dbg
            uint64_t va = fileOffsetToVA(d, j);

            if (va != 0) {
                cout << "[VA: 0x" << setfill('0') << setw(16) << hex << uppercase << va
                    << " | File Offset: 0x" << setw(8) << j << "] -> \"" << display_str << "\"\n";
            }
            else {
                cout << "[File Offset: 0x" << setfill('0') << setw(8) << hex << uppercase << j
                    << "] -> \"" << display_str << "\"\n";
            }

            j = k - 1;
        }
    }

    cout << "\n[+] Found " << dec << matchCount << " hidden strings.\n";
    return 0;
}
