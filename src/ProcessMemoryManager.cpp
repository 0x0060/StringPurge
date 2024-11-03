#include "ProcessMemoryManager.h"
#include "Utils.h"
#include "Logger.h"
#include <tlhelp32.h>
#include <vector>
#include <algorithm>

ProcessMemoryManager::ProcessMemoryManager(const std::wstring& processName)
    : processName(processName), hProcess(nullptr), pid(0) {}

ProcessMemoryManager::~ProcessMemoryManager() {
    cleanUp();
}

bool ProcessMemoryManager::findProcessIdByName() {
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
                Logger::log(LogLevel::INFO, "Found process ID: " + std::to_string(pid));
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return found;
}

bool ProcessMemoryManager::openProcessHandle() {
    if (pid == 0) {
        Logger::log(LogLevel::ERROR, "Invalid process ID.");
        return false;
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == nullptr) {
        utils::printError("OpenProcess");
        return false;
    }

    Logger::log(LogLevel::SYSTEM, "Opened process handle.");
    return true;
}

void ProcessMemoryManager::clearSubString(const std::string& subString) {
    if (hProcess == nullptr) {
        Logger::log(LogLevel::ERROR, "Invalid process handle.");
        return;
    }

    MEMORY_BASIC_INFORMATION memInfo;
    LPBYTE addr = nullptr;
    std::wstring wSubString = utils::stringToWString(subString);

    Logger::log(LogLevel::MEMORY, "Starting memory scan for substring clearing.");

    while (VirtualQueryEx(hProcess, addr, &memInfo, sizeof(memInfo)) == sizeof(memInfo)) {
        if (memInfo.State == MEM_COMMIT &&
            (memInfo.Type == MEM_MAPPED || memInfo.Type == MEM_PRIVATE)) {

            std::vector<char> buffer(memInfo.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer.data(), memInfo.RegionSize, &bytesRead)) {
                clearStringInBuffer(buffer, subString, wSubString, bytesRead, memInfo.BaseAddress);
            } else {
                utils::printError("ReadProcessMemory");
            }
        }
        addr += memInfo.RegionSize;
    }

    Logger::log(LogLevel::MEMORY, "Completed memory scan.");
}

void ProcessMemoryManager::clearStringInBuffer(std::vector<char>& buffer, const std::string& subString, const std::wstring& wSubString, SIZE_T bytesRead, LPVOID baseAddress) {
    for (SIZE_T i = 0; i <= bytesRead - subString.size(); ++i) {
        if (std::string(buffer.data() + i, subString.size()) == subString) {
            Logger::log(LogLevel::DEBUG, "Found ASCII substring at offset " + std::to_string(i));
            modifyMemoryProtectionAndWrite(baseAddress, i, subString.size(), buffer.data() + i, "ASCII");
        }

        if (i <= bytesRead - wSubString.size() * 2) {
            if (std::wstring((wchar_t*)(buffer.data() + i), wSubString.size()) == wSubString) {
                Logger::log(LogLevel::DEBUG, "Found Unicode substring at offset " + std::to_string(i));
                modifyMemoryProtectionAndWrite(baseAddress, i, wSubString.size() * 2, buffer.data() + i, "Unicode");
            }
        }
    }
}

void ProcessMemoryManager::modifyMemoryProtectionAndWrite(LPVOID baseAddress, SIZE_T offset, SIZE_T size, const void* data, const std::string& type) {
    DWORD oldProtect;
    LPBYTE targetAddress = static_cast<LPBYTE>(baseAddress) + offset;

    if (VirtualProtectEx(hProcess, targetAddress, size, PAGE_READWRITE, &oldProtect)) {
        std::fill_n(static_cast<char*>(targetAddress), size, 0);
        WriteProcessMemory(hProcess, targetAddress, data, size, nullptr);
        
        VirtualProtectEx(hProcess, targetAddress, size, oldProtect, &oldProtect);

        if (type == "ASCII") {
            Logger::log(LogLevel::MEMORY, "Cleared ASCII string at address: " + std::to_string(reinterpret_cast<uintptr_t>(targetAddress)));
        } else {
            Logger::log(LogLevel::MEMORY, "Cleared Unicode string at address: " + std::to_string(reinterpret_cast<uintptr_t>(targetAddress)));
        }
    } else {
        utils::printError("VirtualProtectEx");
    }
}

void ProcessMemoryManager::cleanUp() {
    if (hProcess != nullptr) {
        CloseHandle(hProcess);
        Logger::log(LogLevel::SYSTEM, "Closed process handle.");
        hProcess = nullptr;
    }
}