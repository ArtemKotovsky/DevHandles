#pragma once

#include <mutex>
#include <iostream>
#include <system_error>

namespace logger
{
    inline bool sLogErrors = false;
    inline std::mutex sLogLock;
}

#define LOG_ERROR(...) if (logger::sLogErrors) {            \
    std::lock_guard<std::mutex> $lock(logger::sLogLock);    \
    std::wcerr << __VA_ARGS__ << "\n";                      \
}

#define LOG_WIN_ERROR($error, ...) if (logger::sLogErrors) {    \
    std::error_code $ec($error, std::system_category());        \
    std::lock_guard<std::mutex> $lock(logger::sLogLock);        \
    std::wcerr << __VA_ARGS__                                   \
        << ", error " << std::dec << $error                     \
        << ": " << $ec.message().c_str() << "\n";               \
}

#define LOG(...) {                                          \
    std::lock_guard<std::mutex> $lock(logger::sLogLock);    \
    std::wcerr << __VA_ARGS__ << "\n";                      \
}
