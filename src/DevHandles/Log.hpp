#pragma once

#include <mutex>
#include <iostream>
#include <system_error>

namespace logger
{
    inline bool LogErrors = false;
    inline std::mutex LogLock;
}

#define LOG_ERROR(...) if (logger::LogErrors) {             \
    std::lock_guard<std::mutex> $lock(logger::LogLock);     \
    std::wcerr << __VA_ARGS__ << "\n";                      \
}

#define LOG_WIN_ERROR($error, ...) if (logger::LogErrors) { \
    std::error_code $ec($error, std::system_category());    \
    std::lock_guard<std::mutex> $lock(logger::LogLock);     \
    std::wcerr << __VA_ARGS__                               \
        << ", error " << std::dec << $error                 \
        << ": " << $ec.message().c_str() << "\n";           \
}

#define LOG(...) {                                          \
    std::lock_guard<std::mutex> $lock(logger::LogLock);     \
    std::wcout << __VA_ARGS__ << "\n";                      \
}
