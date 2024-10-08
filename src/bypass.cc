#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <memory>
#include <stdexcept>

namespace utils {

    std::wstring stringToWString(const std::string& str) {
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), NULL, 0);
        std::wstring wstr(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), &wstr[0], size_needed);
        return wstr;
    }

    std::string wstringToString(const std::wstring& wstr) {
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
        std::string str(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), &str[0], size_needed, NULL, NULL);
        return str;
    }

    void printError(const std::string& context) {
        std::cerr << context << " Error code: " << GetLastError() << std::endl;
    }

    void handleError(const std::string& context) {
        printError(context);
        throw std::runtime_error(context + " failed.");
    }
}

class ProcessMemoryManager {
public:
    explicit ProcessMemoryManager(const std::wstring& processName)
        : processName(processName), hProcess(nullptr), pid(0) {}

    ~ProcessMemoryManager() {
        cleanUp();
    }

    bool findProcessIdByName() {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            utils::printError("CreateToolhelp32Snapshot");
            return false;
        }

        bool found = false;
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (wcscmp(pe32.szExeFile, processName.c_str()) == 0) {
                    pid = pe32.th32ProcessID;
                    found = true;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return found;
    }

    bool openProcessHandle() {
        if (pid == 0) {
            std::cerr << "Invalid process ID." << std::endl;
            return false;
        }

        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (hProcess == nullptr) {
            utils::printError("OpenProcess");
            return false;
        }

        return true;
    }

    void clearSubString(const std::string& subString) {
        if (hProcess == nullptr) {
            std::cerr << "Invalid process handle." << std::endl;
            return;
        }

        MEMORY_BASIC_INFORMATION memInfo;
        LPBYTE addr = nullptr;
        std::wstring wSubString = utils::stringToWString(subString);

        while (VirtualQueryEx(hProcess, addr, &memInfo, sizeof(memInfo)) == sizeof(memInfo)) {
            if (memInfo.State == MEM_COMMIT &&
                (memInfo.Type == MEM_MAPPED || memInfo.Type == MEM_PRIVATE)) {

                std::vector<char> buffer(memInfo.RegionSize);
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer.data(), memInfo.RegionSize, &bytesRead)) {
                    clearStringInBuffer(buffer, subString, wSubString, bytesRead, memInfo.BaseAddress);
                } else {
                    utils::printError("ReadProcessMemory");
                    // Continue processing next memory regions
                }
            }
            addr += memInfo.RegionSize;
        }
    }

private:
    void clearStringInBuffer(std::vector<char>& buffer, const std::string& subString, const std::wstring& wSubString, SIZE_T bytesRead, LPVOID baseAddress) {
        for (SIZE_T i = 0; i <= bytesRead - subString.size(); ++i) {
            if (std::string(buffer.data() + i, subString.size()) == subString) {
                modifyMemoryProtectionAndWrite(baseAddress, i, subString.size(), buffer.data() + i, "ASCII");
            }

            if (i <= bytesRead - wSubString.size() * 2) {
                if (std::wstring((wchar_t*)(buffer.data() + i), wSubString.size()) == wSubString) {
                    modifyMemoryProtectionAndWrite(baseAddress, i, wSubString.size() * 2, buffer.data() + i, "Unicode");
                }
            }
        }
    }

    void modifyMemoryProtectionAndWrite(LPVOID baseAddress, SIZE_T offset, SIZE_T size, const void* data, const std::string& type) {
        DWORD oldProtect;
        if (VirtualProtectEx(hProcess, (LPBYTE)baseAddress + offset, size, PAGE_READWRITE, &oldProtect)) {
            std::fill((char*)((LPBYTE)baseAddress + offset), (char*)((LPBYTE)baseAddress + offset + size), 0);
            WriteProcessMemory(hProcess, (LPBYTE)baseAddress + offset, data, size, nullptr);
            VirtualProtectEx(hProcess, (LPBYTE)baseAddress + offset, size, oldProtect, &oldProtect);
            if (type == "ASCII") {
                std::cout << "Cleared ASCII string at address: " << std::hex << (uintptr_t)baseAddress + offset << std::endl;
            } else {
                std::wcout << L"Cleared Unicode string at address: " << std::hex << (uintptr_t)baseAddress + offset << std::endl;
            }
        } else {
            utils::printError("VirtualProtectEx");
        }
    }

    void cleanUp() {
        if (hProcess != nullptr) {
            CloseHandle(hProcess);
            hProcess = nullptr;
        }
    }

    std::wstring processName;
    HANDLE hProcess;
    DWORD pid;
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <process_name> <substring_to_clear>" << std::endl;
        return 1;
    }

    std::wstring processName = utils::stringToWString(argv[1]);
    std::string subString = argv[2];

    try {
        ProcessMemoryManager manager(processName);

        if (manager.findProcessIdByName()) {
            if (manager.openProcessHandle()) {
                manager.clearSubString(subString);
                std::wcout << L"Cleared all occurrences of '" << utils::stringToWString(subString)
                    << L"' from " << processName << L" process memory." << std::endl;
            } else {
                std::cerr << "Failed to open process." << std::endl;
                return 1;
            }
        } else {
            std::cerr << "Failed to find process." << std::endl;
            return 1;
        }
    } catch (const std::exception& ex) {
        std::cerr << "Exception: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
