#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <windows.h>
#include <cstdarg>
#include <cstdio>

class Logger {
public:
    enum class LogLevel {
        Info,
        Success,
        Error,
        Warning
    };

    static void Init(const std::string& /*labelText*/, WORD labelColor, WORD infoColor, WORD successColor, WORD errorColor, WORD warningColor) {
        hConsole_ = GetStdHandle(STD_OUTPUT_HANDLE);
        labelColor_ = labelColor;
        infoColor_ = infoColor;
        successColor_ = successColor;
        errorColor_ = errorColor;
        warningColor_ = warningColor;
    }

    static void Log(LogLevel level, const char* format, ...) {
        va_list args;
        va_start(args, format);
        char buffer[1024];
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);

        SetConsoleTextAttribute(hConsole_, FOREGROUND_WHITE | FOREGROUND_INTENSITY);
        std::cout << "[";
        SetConsoleTextAttribute(hConsole_, GetColorForLogLevel(level));
        std::cout << LogLevelToSymbol(level);
        SetConsoleTextAttribute(hConsole_, FOREGROUND_WHITE | FOREGROUND_INTENSITY);
        std::cout << "] ";

        SetConsoleTextAttribute(hConsole_, FOREGROUND_WHITE);
        std::cout << buffer << std::endl;

        SetConsoleTextAttribute(hConsole_, originalColor_);
    }

private:
    static HANDLE hConsole_;
    static WORD labelColor_;
    static WORD infoColor_;
    static WORD successColor_;
    static WORD errorColor_;
    static WORD warningColor_;
    static WORD originalColor_;
    static const WORD FOREGROUND_WHITE = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

    static std::string LogLevelToSymbol(LogLevel level) {
        switch (level) {
        case LogLevel::Info: return "~";
        case LogLevel::Success: return "+";
        case LogLevel::Error: return "-";
        case LogLevel::Warning: return "!";
        default: return "?";
        }
    }

    static WORD GetColorForLogLevel(LogLevel level) {
        switch (level) {
        case LogLevel::Info: return infoColor_;
        case LogLevel::Success: return successColor_;
        case LogLevel::Error: return errorColor_;
        case LogLevel::Warning: return warningColor_;
        default: return originalColor_;
        }
    }
};

HANDLE Logger::hConsole_ = nullptr;
WORD Logger::labelColor_ = 0;
WORD Logger::infoColor_ = 0;
WORD Logger::successColor_ = 0;
WORD Logger::errorColor_ = 0;
WORD Logger::warningColor_ = 0;
WORD Logger::originalColor_ = []() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    return consoleInfo.wAttributes;
    }();

#define LOG_INFO(format, ...) Logger::Log(Logger::LogLevel::Info, format, ##__VA_ARGS__)
#define LOG_SUCCESS(format, ...) Logger::Log(Logger::LogLevel::Success, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) Logger::Log(Logger::LogLevel::Error, format, ##__VA_ARGS__)
#define LOG_WARNING(format, ...) Logger::Log(Logger::LogLevel::Warning, format, ##__VA_ARGS__)

#endif
