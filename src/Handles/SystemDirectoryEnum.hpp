#pragma once

#include <vector>
#include <functional>

#include "ScopedHandle.hpp"
#include "Ntdll.h"

#pragma comment(lib, "ntdll.lib")

namespace hndl
{
    class SystemDirectoryEnum
    {
    public:
        using NtHandle = utils::ScopedHandle<HANDLE, decltype(::NtClose), ::NtClose, nullptr>;
        using EnumDirCb = std::function<bool(UNICODE_STRING& /*type*/, UNICODE_STRING& /*name*/)>; // ret false to stop enumeration

    public:
        explicit SystemDirectoryEnum(std::wstring directory);
        void Enum(EnumDirCb cb);

        bool IsSymbolicLinkType(const UNICODE_STRING& type) const;
        void ResolveSymbolicLink(UNICODE_STRING& symlink, std::wstring& linkTarget) const;

    private:
        std::vector<char> m_dirCache;
        NtHandle m_directoryHandle;
    };
}
