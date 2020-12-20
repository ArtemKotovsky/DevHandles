#include "DeviceSymlinks.hpp"
#include "SystemDirectoryEnum.hpp"

namespace hndl
{
    void DeviceSymlinks::Refresh()
    {
        SystemDirectoryEnum systemDir(L"\\GLOBAL??");

        std::wstring symlink;
        std::wstring symlinkTarget;

        systemDir.Enum([&](UNICODE_STRING& type, UNICODE_STRING& name) -> bool
        {
            if (systemDir.IsSymbolicLinkType(type))
            {
                systemDir.ResolveSymbolicLink(name, symlinkTarget);
                symlink.assign(&name.Buffer[0], &name.Buffer[name.Length / sizeof(name.Buffer[0])]);
                m_deviceToSymlink[symlinkTarget] = symlink;
            }

            return true;
        });
    }

    std::wstring DeviceSymlinks::TryGetSymlinkByDevice(const std::wstring& deviceName) const
    {
        if (!deviceName.empty())
        {
            auto it = m_deviceToSymlink.find(deviceName);

            if (m_deviceToSymlink.end() != it)
            {
                return (*it).second;
            }
        }

        return std::wstring();
    }
}
