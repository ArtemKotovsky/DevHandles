#pragma once

#include <string>
#include <Windows.h>

namespace utils
{
    void EnablePrivilege(const wchar_t* name);
    std::wstring GetProcessName(HANDLE processHandle);
    std::wstring GetTime(const wchar_t* format);
}
