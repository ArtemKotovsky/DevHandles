#include "SystemDirectoryEnum.hpp"
#include "Exceptions.hpp"

namespace hndl
{
    SystemDirectoryEnum::SystemDirectoryEnum(std::wstring directory)
    {
        UNICODE_STRING path{};
        RtlInitUnicodeString(&path, directory.data());

        OBJECT_ATTRIBUTES objectAttributes{};
        InitializeObjectAttributes(&objectAttributes, &path, OBJ_CASE_INSENSITIVE, 0, 0);

        NTSTATUS status = NtOpenDirectoryObject(
            &m_directoryHandle,
            DIRECTORY_QUERY,
            &objectAttributes);

        if (NT_ERROR(status))
        {
            THROW_WIN_ERROR(RtlNtStatusToDosError(status),
                "NtOpenDirectoryObject 0x" << std::hex << status);
        }
    }

    void SystemDirectoryEnum::Enum(EnumDirCb callback)
    {
        m_dirCache.resize(1024 * 128);
    
        ULONG index = 0;
        ULONG prevIndex = 0;
        ULONG bytesReturned = 0;
    
        NTSTATUS status = NtQueryDirectoryObject(
            m_directoryHandle,
            m_dirCache.data(),
            static_cast<ULONG>(m_dirCache.size()),
            FALSE,
            TRUE,
            &index,
            &bytesReturned);
    
        while (NT_SUCCESS(status))
        {
            const ULONG count = index - prevIndex;
            auto info = reinterpret_cast<POBJECT_DIRECTORY_INFORMATION>(m_dirCache.data());
    
            for (ULONG i = 0; i < count; ++i)
            {
                if (!callback(info[i].TypeName, info[i].Name))
                {
                    return;
                }
            }
    
            prevIndex = index;
            status = NtQueryDirectoryObject(
                m_directoryHandle,
                m_dirCache.data(),
                static_cast<ULONG>(m_dirCache.size()),
                FALSE,
                FALSE,
                &index,
                &bytesReturned);
        }
    
        if (STATUS_NO_MORE_ENTRIES != status && NT_ERROR(status))
        {
            THROW_WIN_ERROR(RtlNtStatusToDosError(status),
                "NtQueryDirectoryObject 0x" << std::hex << status);
        }
    }

    bool SystemDirectoryEnum::IsSymbolicLinkType(const UNICODE_STRING& type) const
    {
        WCHAR symlink[] = L"SymbolicLink";
        UNICODE_STRING symlinkTypeName{};
        RtlInitUnicodeString(&symlinkTypeName, symlink);

        return (0 == RtlCompareUnicodeString(&type, &symlinkTypeName, FALSE));
    }

    void SystemDirectoryEnum::ResolveSymbolicLink(UNICODE_STRING& symlink, std::wstring& linkTarget) const
    {
        OBJECT_ATTRIBUTES objectAttributes{};
        InitializeObjectAttributes(&objectAttributes, 
            &symlink, 
            OBJ_CASE_INSENSITIVE, 
            m_directoryHandle.get(), 
            NULL);
    
        NtHandle symlinkHandle;
        NTSTATUS status = NtOpenSymbolicLinkObject(
            &symlinkHandle,
            SYMBOLIC_LINK_QUERY,
            &objectAttributes);
    
        if (NT_ERROR(status))
        {
            THROW_WIN_ERROR(RtlNtStatusToDosError(status),
                "NtOpenSymbolicLinkObject 0x" << std::hex << status);
        }
    
        for (;;)
        {
            ULONG returnedLength = 0;
            UNICODE_STRING symlinkTargetUs{ 0 };
            symlinkTargetUs.Buffer = linkTarget.data();
            symlinkTargetUs.Length = 0;
            symlinkTargetUs.MaximumLength = static_cast<USHORT>(linkTarget.size() * sizeof(std::wstring::value_type));
    
            status = NtQuerySymbolicLinkObject(symlinkHandle, &symlinkTargetUs, &returnedLength);
    
            if (STATUS_BUFFER_TOO_SMALL == status)
            {
                linkTarget.resize(returnedLength / sizeof(symlinkTargetUs.Buffer[0]));
                continue;
            }
            
            if (NT_ERROR(status))
            {
                THROW_WIN_ERROR(RtlNtStatusToDosError(status),
                    "NtQuerySymbolicLinkObject 0x" << std::hex << status);
            }
    
            linkTarget.resize(symlinkTargetUs.Length / sizeof(symlinkTargetUs.Buffer[0]));
            break;
        }
    }
}
