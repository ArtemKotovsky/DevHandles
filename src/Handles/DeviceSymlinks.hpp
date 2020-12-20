#pragma once

#include <vector>
#include <unordered_map>
#include <string>

namespace hndl
{
    class DeviceSymlinks
    {
    public:
        void Refresh();
        std::wstring TryGetSymlinkByDevice(const std::wstring& deviceName) const;

    private:
        std::unordered_map<std::wstring, std::wstring> m_deviceToSymlink;
    };
}
