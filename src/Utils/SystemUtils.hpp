#pragma once

#include <string>
#include <Windows.h>

namespace utils
{
    void EnablePrivilege(const std::wstring& name);
    std::wstring GetProcessName(HANDLE processHandle);

    std::wstring GetCurrentTime();
    std::wstring SystemFileTimeToLocalTimeString(uint64_t systemFileTime);
}
