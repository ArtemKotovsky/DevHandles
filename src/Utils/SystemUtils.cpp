#include "SystemUtils.hpp"
#include "ScopedHandle.hpp"
#include "Exceptions.hpp"

#include <Psapi.h>
#include <filesystem>
#include <iostream>

namespace utils
{
    using Handle = ScopedHandle<HANDLE, decltype(::CloseHandle), ::CloseHandle, nullptr>;

    void EnablePrivilege(const wchar_t* name)
    {
        Handle hToken;
        TOKEN_PRIVILEGES priv = { 1, {0, 0, SE_PRIVILEGE_ENABLED} };
        THROW_WIN_IF2(!LookupPrivilegeValue(0, name, &priv.Privileges[0].Luid));
        THROW_WIN_IF2(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken));
        THROW_WIN_IF2(!AdjustTokenPrivileges(hToken, FALSE, &priv, sizeof(priv), 0, 0));
    }

    std::wstring GetProcessName(HANDLE processHandle)
    {
        std::wstring name;
        name.resize(4096);
        name.resize(GetProcessImageFileName(processHandle, 
            name.data(), 
            static_cast<DWORD>(name.size())));
        return std::filesystem::path(name).filename();
    }

    std::wstring GetTime(const wchar_t* format)
    {
        std::tm localTime = { 0 };
        auto timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

        if (0 == localtime_s(&localTime, &timestamp))
        {
            std::wstringstream st;
            st << std::put_time(&localTime, format) << " ";
            return st.str();
        }

        return std::wstring();
    }
}