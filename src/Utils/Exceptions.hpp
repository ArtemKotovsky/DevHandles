#pragma once

#include <sstream>
#include <system_error>

#ifdef _DEBUG
#define THROW_FUNC << "[" << __FUNCTION__ "]: "
#else 
#define THROW_FUNC 
#endif

#define THROW_IF($cond, $mess) if ($cond) { THROW($mess); }
#define THROW($mess) {                      \
    std::stringstream $st;                  \
    $st THROW_FUNC << $mess;                \
    throw std::runtime_error($st.str());    \
}

#define THROW_WIN_IF($cond, $mess) if ($cond) { THROW_WIN($mess); }
#define THROW_WIN_IF2($cond) if ($cond) { THROW_WIN(#$cond); }
#define THROW_WIN($mess) THROW_WIN_ERROR(::GetLastError(), $mess);
#define THROW_WIN_ERROR($error, $mess) {                        \
    DWORD $lastError = $error;                                  \
    std::error_code $ec($lastError, std::system_category());    \
    std::stringstream $st;                                      \
    $st THROW_FUNC << $mess;                                    \
    throw std::system_error($ec, $st.str());                    \
}
