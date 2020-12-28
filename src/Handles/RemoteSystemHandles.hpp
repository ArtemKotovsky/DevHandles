#pragma once

#include "SystemHandleImpl.hpp"

namespace hndl
{
    class RemoteSystemHandles : public SystemHandleImpl
    {
    public:
        RemoteSystemHandles();
        ~RemoteSystemHandles();

        RemoteSystemHandles(const RemoteSystemHandles&) = delete;
        RemoteSystemHandles& operator=(const RemoteSystemHandles&) = delete;

        RemoteSystemHandles(RemoteSystemHandles&&) noexcept;
        RemoteSystemHandles& operator=(RemoteSystemHandles&&) noexcept;

        bool AttachToProcess(uint32_t pid);
        bool IsAttached() const;

    private:
        NTSTATUS RemoteQueryObject(HANDLE handle,
            OBJECT_INFORMATION_CLASS objectInformationClass,
            PVOID objectInformation,
            ULONG objectInformationLength,
            PULONG returnLength) const;

        NTSTATUS ExecQueryObject(HANDLE handle,
            OBJECT_INFORMATION_CLASS objectInformationClass,
            ULONG objectInformationLength,
            PULONG returnLength) const;
        
        NTSTATUS PrepareJitExceptionHandler(
            ) const;

        NTSTATUS PrepareJitCode(ULONG64 handle,
            ULONG64 objectInformationClass,
            ULONG64 objectInformation,
            ULONG64 objectInformationLength,
            ULONG64 returnLengthPtr,
            ULONG64 statusPtr) const;

        NTSTATUS PrepareJitCode64(ULONG64 handle,
            ULONG64 objectInformationClass,
            ULONG64 objectInformation,
            ULONG64 objectInformationLength,
            ULONG64 returnLengthPtr,
            ULONG64 statusPtr) const;

        NTSTATUS PrepareJitCode86(ULONG64 handle,
            ULONG64 objectInformationClass,
            ULONG64 objectInformation,
            ULONG64 objectInformationLength,
            ULONG64 returnLengthPtr,
            ULONG64 statusPtr) const;

        DWORD RunRemoteThread() const;

        void RelocateUnicodeString(UNICODE_STRING& us, 
            LONG_PTR base, 
            LONG_PTR remoteBase,
            SIZE_T size) const;

        NTSTATUS RelocateObjectInformation(
            OBJECT_INFORMATION_CLASS objectInformationClass,
            PVOID objectInformation,
            ULONG objectInformationLength, 
            PVOID remoteBase) const;

        virtual NTSTATUS QueryObjectFn(
            _In_ HANDLE handle,
            _In_ OBJECT_INFORMATION_CLASS objectInformationClass,
            _Out_opt_ PVOID objectInformation,
            _In_ ULONG objectInformationLength,
            _Out_opt_ PULONG returnLength) override;

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };
}
