#pragma once

#include <mutex>
#include <iostream>
#include <system_error>

namespace logger
{
    inline bool LogErrors = false;
    inline std::mutex LogLock;
}

#define $_LOG($out, ...) {                                  \
    std::lock_guard<std::mutex> $lock(logger::LogLock);     \
    if ($out.rdstate() != std::ios_base::goodbit) {         \
        $out.clear();                                       \
        $out << "\n";                                       \
    }                                                       \
    $out << __VA_ARGS__;                                    \
}

#define LOG_ERROR(...) if (logger::LogErrors) {             \
    $_LOG(std::wcerr, __VA_ARGS__ << std::endl);            \
}

#define LOG_WIN_ERROR($error, ...) if (logger::LogErrors) { \
    std::error_code $ec($error, std::system_category());    \
    $_LOG(std::wcerr, __VA_ARGS__                           \
        << ", error " << std::dec << $error                 \
        << ": " << $ec.message().c_str() << std::endl);     \
}

#define LOG(...) {                                          \
    $_LOG(std::wcout, __VA_ARGS__ << std::endl);            \
}
