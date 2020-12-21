#include "SystemHandles.hpp"
#include "Ntdll.h"

namespace hndl
{
    NTSTATUS SystemHandles::QueryObjectFn(
        _In_ HANDLE handle,
        _In_ OBJECT_INFORMATION_CLASS objectInformationClass,
        _Out_opt_ PVOID objectInformation,
        _In_ ULONG objectInformationLength,
        _Out_opt_ PULONG returnLength)
    {
        return NtQueryObject(handle,
            objectInformationClass,
            objectInformation,
            objectInformationLength,
            returnLength);
    }
}
