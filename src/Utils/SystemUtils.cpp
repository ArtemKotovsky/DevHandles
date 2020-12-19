#include "SystemUtils.hpp"
#include "ScopedHandle.hpp"
#include "Exceptions.hpp"

#include <Psapi.h>
#include <filesystem>
#include <iostream>

namespace utils
{
    using Handle = ScopedHandle<HANDLE, decltype(::CloseHandle), ::CloseHandle, nullptr>;

    void EnablePrivilege(const std::wstring& name)
    {
        Handle hToken;
        TOKEN_PRIVILEGES priv = { 1, {0, 0, SE_PRIVILEGE_ENABLED} };
        THROW_WIN_IF2(!LookupPrivilegeValue(0, name.c_str(), &priv.Privileges[0].Luid));
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

    std::wstring GetCurrentTime()
    {
        std::tm localTime = { 0 };
        auto timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

        if (0 == localtime_s(&localTime, &timestamp))
        {
            std::wstringstream st;
            st << std::put_time(&localTime, L"%H:%M:%S") << " ";
            return st.str();
        }

        return std::wstring();
    }

    static SYSTEMTIME SystemFileTimeToLocalTime(uint64_t systemFileTime)
    {
        LARGE_INTEGER li{};
        li.QuadPart = systemFileTime;

        FILETIME ftSystemTime{ 0 };
        ftSystemTime.dwHighDateTime = li.HighPart;
        ftSystemTime.dwLowDateTime = li.LowPart;

        FILETIME ftLocalTime{ 0 };
        SYSTEMTIME localTime{ 0 };
        THROW_WIN_IF2(!FileTimeToLocalFileTime(&ftSystemTime, &ftLocalTime));
        THROW_WIN_IF2(!FileTimeToSystemTime(&ftLocalTime, &localTime));

        return localTime;
    }

    std::wstring SystemFileTimeToLocalTimeString(uint64_t systemFileTime)
    {
        SYSTEMTIME localTime = SystemFileTimeToLocalTime(systemFileTime);

        std::wstringstream st;
        st << std::dec << std::setw(2) << std::setfill(L'0') << localTime.wHour << ":";
        st << std::dec << std::setw(2) << std::setfill(L'0') << localTime.wMinute << ":";
        st << std::dec << std::setw(2) << std::setfill(L'0') << localTime.wSecond << " ";
        st << std::dec << std::setw(4) << std::setfill(L'0') << localTime.wYear << ":";
        st << std::dec << std::setw(2) << std::setfill(L'0') << localTime.wMonth << "-";
        st << std::dec << std::setw(2) << std::setfill(L'0') << localTime.wDay;

        return st.str();
    }
}