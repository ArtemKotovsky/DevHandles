#pragma once

#include <vector>
#include <optional>
#include <string>
#include "Ntdll.h"

#pragma comment(lib, "ntdll.lib")

namespace hndl
{
    class SystemHandles
    {
    public:
        std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> GetSystemHandles();
        std::optional<OBJECT_BASIC_INFORMATION> GetBasicInformation(HANDLE handle);
        std::wstring GetTypeName(HANDLE handle);
        std::wstring GetObjectName(HANDLE handle, ULONG grantedAccess);

    private:
        NTSTATUS QueryObject(HANDLE handle, OBJECT_INFORMATION_CLASS objectInformationClass);
        std::wstring UsToString(const UNICODE_STRING& str) const;

    private:
        std::vector<char> m_bufferCache;
    };
}
