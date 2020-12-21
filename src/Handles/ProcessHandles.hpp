#pragma once

#include <string>
#include <vector>
#include <functional>

namespace hndl
{
    struct ProcessHandleInfo
    {
        size_t ObjectId = 0;
        int64_t CreationTime = 0;
        int64_t HandleRefCount = -1;
        uint32_t HandleValue = 0;
        uint32_t OwnerProcessId = 0;
        std::wstring ObjectName;
        std::wstring ObjectType;
        std::wstring DeviceName;
        std::wstring ProcessName;
    };

    std::wostream& operator<<(std::wostream& out, const ProcessHandleInfo& h);

    class ProcessHandles
    {
    public:
        using ErrorCallback = std::function<void(std::wstring message, uint32_t win32Error)>;

    public:
        void Refresh();

        std::vector<ProcessHandleInfo> Update();
        const std::vector<ProcessHandleInfo>& GetHandles();

        void SetErrorCallback(ErrorCallback callback);
        void SetIncludeProcessFilter(const std::vector<std::wstring>& processFilter);
        void SetExcludeProcessFilter(const std::vector<std::wstring>& processFilter);

    private:
        void CallErrorCallback(std::wstring message, uint32_t win32Error);
        void Refresh(std::vector<ProcessHandleInfo>& handles);
        void RefreshDeviceName(std::vector<ProcessHandleInfo>& handles) const;
        bool IsFilteredProcessName(const std::wstring& processName) const;

    private:
        ErrorCallback m_errorCallback;
        std::vector<ProcessHandleInfo> m_handles;
        std::vector<std::wstring> m_includeProcessFilter;
        std::vector<std::wstring> m_excludeProcessFilter;
    };
}
