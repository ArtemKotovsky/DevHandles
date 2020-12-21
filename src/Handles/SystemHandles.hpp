#pragma once

#include "SystemHandleImpl.hpp"

namespace hndl
{
    class SystemHandles : public SystemHandleImpl
    {
    public:
        SystemHandles() = default;

    private:
        virtual NTSTATUS QueryObjectFn(
            _In_ HANDLE handle,
            _In_ OBJECT_INFORMATION_CLASS objectInformationClass,
            _Out_opt_ PVOID objectInformation,
            _In_ ULONG objectInformationLength,
            _Out_opt_ PULONG returnLength) override;
    };
}
