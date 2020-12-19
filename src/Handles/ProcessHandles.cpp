#include "ProcessHandles.hpp"
#include "SystemHandles.hpp"
#include "SystemUtils.hpp"
#include "ScopedHandle.hpp"
#include "Exceptions.hpp"

#include <unordered_set>
#include <Windows.h>

#define LOG_WIN_ERROR(...) {                \
    DWORD $error = GetLastError();          \
    std::wstringstream $msg;                \
    $msg << __VA_ARGS__;                    \
    CallErrorCallback($msg.str(), $error);  \
}

namespace hndl
{
    using Handle = utils::ScopedHandle<HANDLE, decltype(::CloseHandle), ::CloseHandle, nullptr>;

    std::wostream& operator<<(std::wostream& out, const ProcessHandleInfo& h)
    {
        out << std::dec;
        out << h.ProcessName << " (" << h.OwnerProcessId << ") ";
        out << "[Ref=" << h.HandleRefCount << "] ";
        out << h.ObjectType << " " << h.ObjectName << " " << h.DeviceName;
        return out;
    }

    void ProcessHandles::SetErrorCallback(ErrorCallback callback)
    {
        m_errorCallback = callback;
    }

    void ProcessHandles::CallErrorCallback(std::wstring message, uint32_t win32Error)
    {
        if (m_errorCallback)
        {
            m_errorCallback(message, win32Error);
        }
    }

    void ProcessHandles::Refresh()
    {
        Refresh(m_handles);
    }

    std::vector<ProcessHandleInfo> ProcessHandles::Update()
    {
        std::vector<ProcessHandleInfo> handles;
        Refresh(handles);

        using key = std::tuple<size_t, uint32_t>;

        struct key_hash 
        {
            size_t operator()(const key& k) const
            {
                return std::get<0>(k) ^ std::get<1>(k);
            }
        };
        
        std::unordered_set<key, key_hash> oldCache;

        for (const auto& h : m_handles)
        {
            oldCache.insert({ h.ObjectId, h.OwnerProcessId });
        }

        std::vector<ProcessHandleInfo> newHandles;

        for (const auto& h : handles)
        {
            if (oldCache.end() == oldCache.find({ h.ObjectId, h.OwnerProcessId }))
            {
                newHandles.push_back(h);
            }
        }

        m_handles.swap(handles);
        return newHandles;
    }

    void ProcessHandles::Refresh(std::vector<ProcessHandleInfo>& outHandles)
    {
        std::unordered_map<DWORD, Handle> procCache;
        std::unordered_map<DWORD, std::wstring> procNameCache;

        SystemHandles system;
        auto handles = system.GetSystemHandles();
        outHandles.clear();

        for (const auto& handle : handles)
        {
            auto processHandle = procCache.find(handle.UniqueProcessId);

            if (procCache.end() == processHandle)
            {
                Handle process = OpenProcess(
                    PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                    FALSE,
                    handle.UniqueProcessId);

                if (!process)
                {
                    LOG_WIN_ERROR("Cannot open process " << handle.UniqueProcessId);
                }
                else
                {
                    procNameCache[handle.UniqueProcessId] = GetProcessName(process);
                }

                processHandle = procCache.insert({
                    handle.UniqueProcessId,
                    std::move(process)
                    }).first;
            }

            if (!processHandle->second)
            {
                // process handle was not opened
                continue;
            }

            Handle dupObjHandle;
            if (!DuplicateHandle(processHandle->second,
                reinterpret_cast<HANDLE>(handle.HandleValue),
                GetCurrentProcess(),
                &dupObjHandle,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS))
            {
                LOG_WIN_ERROR("Cannot duplicate process " << handle.UniqueProcessId << " handle");
                continue;
            }

            auto basicInfo = system.GetBasicInformation(dupObjHandle);

            if (!basicInfo)
            {
                LOG_WIN_ERROR("Cannot get process " << handle.UniqueProcessId << " handle basic info");
                continue;
            }

            ProcessHandleInfo handleInfo;
            handleInfo.ObjectId = reinterpret_cast<size_t>(handle.Object);
            handleInfo.OwnerProcessId = handle.UniqueProcessId;
            handleInfo.HandleRefCount = basicInfo->HandleCount - 1;
            handleInfo.ProcessName = procNameCache[handle.UniqueProcessId];
            handleInfo.ObjectType = system.GetTypeName(dupObjHandle);
            handleInfo.ObjectName = system.GetObjectName(dupObjHandle, handle.GrantedAccess);

            outHandles.push_back(handleInfo);
        }
    }

    const std::vector<ProcessHandleInfo>& ProcessHandles::GetHandles()
    {
        return m_handles;
    }
}
