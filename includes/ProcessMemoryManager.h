#ifndef PROCESSMEMORYMANAGER_H
#define PROCESSMEMORYMANAGER_H

#include <windows.h>
#include <string>

class ProcessMemoryManager {
public:
    explicit ProcessMemoryManager(const std::wstring& processName);
    ~ProcessMemoryManager();

    bool findProcessIdByName();
    bool openProcessHandle();
    void clearSubString(const std::string& subString);

private:
    void clearStringInBuffer(std::vector<char>& buffer, const std::string& subString, const std::wstring& wSubString, SIZE_T bytesRead, LPVOID baseAddress);
    void modifyMemoryProtectionAndWrite(LPVOID baseAddress, SIZE_T offset, SIZE_T size, const void* data, const std::string& type);
    void cleanUp();

    std::wstring processName;
    HANDLE hProcess;
    DWORD pid;
};

#endif
