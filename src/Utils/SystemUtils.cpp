#include "SystemUtils.hpp"
#include "ScopedHandle.hpp"
#include "Exceptions.hpp"
#include "Ntdll.h"

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

    std::wstring GetProcessFilename(HANDLE processHandle)
    {
        std::wstring name;
        name.resize(4096);
        name.resize(GetProcessImageFileName(processHandle,
            name.data(),
            static_cast<DWORD>(name.size())));
        return name;
    }

    std::wstring GetProcessName(HANDLE processHandle)
    {
        return std::filesystem::path(GetProcessFilename(processHandle)).filename();
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

    SYSTEMTIME SystemFileTimeToLocalTime(uint64_t systemFileTime)
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

    bool IsProcessSuspended(HANDLE processHandle)
    {
        PROCESS_EXTENDED_BASIC_INFORMATION pebi{};
        ULONG returnedLength = 0;
        NTSTATUS status = NtQueryInformationProcess(processHandle, ProcessBasicInformation, &pebi, sizeof(pebi), &returnedLength);

        if (NT_ERROR(status))
        {
            return false;
        }

        if (returnedLength != sizeof(pebi))
        {
            return false;
        }

        return !!pebi.u.s.IsFrozen;
    }
}