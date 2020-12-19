#pragma once

#include <string>
#include <functional>
#include <unordered_map>

namespace hndl
{
    struct ProcessHandleInfo
    {
        size_t ObjectId = 0;
        uint32_t OwnerProcessId = 0;
        uint32_t HandleRefCount = 0;
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

    private:
        void CallErrorCallback(std::wstring message, uint32_t win32Error);
        void Refresh(std::vector<ProcessHandleInfo>& handles);

    private:
        ErrorCallback m_errorCallback;
        std::vector<ProcessHandleInfo> m_handles;
    };
}
