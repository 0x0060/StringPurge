#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

enum class LogLevel {
    INFO,
    ERROR,
    DEBUG,
    SYSTEM,
    MEMORY
};

class Logger {
public:
    static void log(LogLevel level, const std::string& message);

private:
    static std::string getCurrentTime();
    static std::string logLevelToString(LogLevel level);
};

#endif
