#include "SystemHandles.hpp"
#include "Exceptions.hpp"

namespace hndl
{
    std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> SystemHandles::GetSystemHandles()
    {
        ULONG size = 4096;
        m_bufferCache.resize(size);

        for (;;)
        {
            NTSTATUS status = NtQuerySystemInformation(
                SystemHandleInformation,
                m_bufferCache.data(),
                static_cast<ULONG>(m_bufferCache.size()),
                &size);

            if (NT_SUCCESS(status))
            {
                break;
            }

            if (STATUS_INFO_LENGTH_MISMATCH == status)
            {
                size *= 2;
                m_bufferCache.resize(size);
                continue;
            }

            THROW("NtQuerySystemInformation error 0x" << std::hex << status);
        }

        auto sys = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(m_bufferCache.data());

        return std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO>(
            &sys->Handles[0],
            &sys->Handles[sys->NumberOfHandles]);
    }

    std::optional<OBJECT_BASIC_INFORMATION> SystemHandles::GetBasicInformation(HANDLE handle)
    {
        OBJECT_BASIC_INFORMATION basicInfo{ 0 };
        ULONG returnedLength = 0;
        NTSTATUS status = NtQueryObject(handle,
            ObjectBasicInformation,
            &basicInfo,
            sizeof(basicInfo),
            &returnedLength);

        if (NT_ERROR(status))
        {
            return {};
        }

        return basicInfo;
    }

    std::wstring SystemHandles::GetTypeName(HANDLE handle)
    {
        NTSTATUS status = QueryObject(handle, ObjectTypeInformation);

        if (NT_ERROR(status))
        {
            return std::wstring();
        }

        auto type = reinterpret_cast<POBJECT_TYPE_INFORMATION>(m_bufferCache.data());
        return UsToString(type->TypeName);
    }

    std::wstring SystemHandles::GetObjectName(HANDLE handle, ULONG grantedAccess)
    {
        // Query the object name
        // unless it has one of that access values on which NtQueryObject could hang
        if (grantedAccess == 0x0012019f ||
            grantedAccess == 0x001a019f ||
            grantedAccess == 0x00120189 ||
            grantedAccess == 0x00100000) 
        {
            return std::wstring();
        }

        NTSTATUS status = QueryObject(handle, ObjectNameInformation);

        if (NT_ERROR(status))
        {
            return std::wstring();
        }

        auto name = reinterpret_cast<POBJECT_NAME_INFORMATION>(m_bufferCache.data());
        return UsToString(name->Name);
    }

    NTSTATUS SystemHandles::QueryObject(HANDLE handle, OBJECT_INFORMATION_CLASS objectInformationClass)
    {
        ULONG size = 4096;
        m_bufferCache.resize(size);

        for (;;)
        {
            NTSTATUS status = NtQueryObject(
                handle,
                objectInformationClass,
                m_bufferCache.data(),
                static_cast<ULONG>(m_bufferCache.size()),
                &size);

            if (STATUS_INFO_LENGTH_MISMATCH == status)
            {
                size *= 2;
                m_bufferCache.resize(size);
                continue;
            }

            if (NT_SUCCESS(status))
            {
                m_bufferCache.resize(size);
            }

            return status;
        }
    }

    std::wstring SystemHandles::UsToString(const UNICODE_STRING& str) const
    {
        return std::wstring(&str.Buffer[0], &str.Buffer[str.Length / sizeof(str.Buffer[0])]);
    }
}
