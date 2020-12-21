#pragma once

#include <vector>
#include <optional>
#include <string>
#include <functional>

#include "Ntdll.h"

#pragma comment(lib, "ntdll.lib")

namespace hndl
{
    class SystemHandleImpl
    {
    public:
        SystemHandleImpl() = default;
        virtual ~SystemHandleImpl() = default;

        std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> GetSystemHandles();
        std::optional<OBJECT_BASIC_INFORMATION> GetBasicInformation(HANDLE handle);
        std::wstring GetTypeName(HANDLE handle);
        std::wstring GetObjectName(HANDLE handle, ULONG grantedAccess);

    private:
        NTSTATUS QueryObject(HANDLE handle, OBJECT_INFORMATION_CLASS objectInformationClass);
        std::wstring UsToString(const UNICODE_STRING& str) const;

        virtual NTSTATUS QueryObjectFn(
            _In_ HANDLE handle,
            _In_ OBJECT_INFORMATION_CLASS OobjectInformationClass,
            _Out_opt_ PVOID objectInformation,
            _In_ ULONG objectInformationLength,
            _Out_opt_ PULONG returnLength) = 0;

    private:
        std::vector<char> m_bufferCache;
    };
}
