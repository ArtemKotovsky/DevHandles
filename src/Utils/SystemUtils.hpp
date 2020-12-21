#pragma once

#include <string>
#include <Windows.h>

namespace utils
{
    void EnablePrivilege(const wchar_t* name);
    std::wstring GetProcessFilename(HANDLE processHandle);
    std::wstring GetProcessName(HANDLE processHandle);
    std::wstring GetTime(const wchar_t* format);

    SYSTEMTIME SystemFileTimeToLocalTime(uint64_t systemFileTime);
}
