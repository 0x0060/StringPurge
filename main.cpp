#include "ProcessMemoryManager.h"
#include "Utils.h"
#include "Logger.h"
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        Logger::log(LogLevel::ERROR, "Usage: <program_name> <process_name> <substring_to_clear>");
        std::cerr << "Usage: " << argv[0] << " <process_name> <substring_to_clear>" << std::endl;
        return 1;
    }

    std::wstring processName = utils::stringToWString(argv[1]);
    std::string subString = argv[2];

    Logger::log(LogLevel::INFO, "Starting Process Memory Manager for process: " + std::string(argv[1]));

    try {
        ProcessMemoryManager manager(processName);

        if (!manager.findProcessIdByName()) {
            Logger::log(LogLevel::ERROR, "Failed to find process with name: " + std::string(argv[1]));
            return 1;
        }

        if (!manager.openProcessHandle()) {
            Logger::log(LogLevel::ERROR, "Failed to open process handle.");
            return 1;
        }

        Logger::log(LogLevel::MEMORY, "Attempting to clear substring: " + subString);
        manager.clearSubString(subString);

        Logger::log(LogLevel::INFO, "Cleared all occurrences of '" + subString + "' from process memory.");
        std::wcout << L"Cleared all occurrences of '" << utils::stringToWString(subString)
                   << L"' from " << processName << L" process memory." << std::endl;

    } catch (const std::exception& ex) {
        Logger::log(LogLevel::ERROR, "Exception: " + std::string(ex.what()));
        std::cerr << "Exception: " << ex.what() << std::endl;
        return 1;
    }

    Logger::log(LogLevel::INFO, "Process Memory clean completed successfully.");
    return 0;
}
