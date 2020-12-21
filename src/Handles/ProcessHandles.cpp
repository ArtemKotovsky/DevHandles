#include "ProcessHandles.hpp"
#include "SystemHandles.hpp"
#include "RemoteSystemHandles.hpp"
#include "DeviceSymlinks.hpp"
#include "SystemUtils.hpp"
#include "ScopedHandle.hpp"
#include "Exceptions.hpp"

#include <unordered_set>
#include <iomanip>
#include <Windows.h>
#include <shlwapi.h>

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
        out << "[Handle=" << std::hex << h.HandleValue << "] ";
        if (h.CreationTime)
        {
            SYSTEMTIME localTime = utils::SystemFileTimeToLocalTime(h.CreationTime);

            out << "[Time=";
            out << std::dec << std::setw(2) << std::setfill(L'0') << localTime.wHour << ":";
            out << std::dec << std::setw(2) << std::setfill(L'0') << localTime.wMinute << ":";
            out << std::dec << std::setw(2) << std::setfill(L'0') << localTime.wSecond << " ";
            out << std::dec << std::setw(2) << std::setfill(L'0') << localTime.wDay << "-";
            out << std::dec << std::setw(2) << std::setfill(L'0') << localTime.wMonth << "-";
            out << std::dec << std::setw(4) << std::setfill(L'0') << localTime.wYear;
            out << "] ";
        }
        out << h.ObjectType << " " << h.ObjectName << " " << h.DeviceName;
        return out;
    }

    void ProcessHandles::SetErrorCallback(ErrorCallback callback)
    {
        m_errorCallback = callback;
    }

    void ProcessHandles::SetProcessFilter(const std::vector<std::wstring>& processFilter)
    {
        m_processFilter = processFilter;
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

    const std::vector<ProcessHandleInfo>& ProcessHandles::GetHandles()
    {
        return m_handles;
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
        std::unordered_set<DWORD> filteredProcessCache;
        std::unordered_map<DWORD, RemoteSystemHandles> remoteProcCache;

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
                    std::wstring processName = GetProcessName(process);

                    if (IsFilteredProcessName(processName))
                    {
                        filteredProcessCache.insert(handle.UniqueProcessId);
                    }

                    procNameCache.emplace(handle.UniqueProcessId, std::move(processName));
                }

                processHandle = procCache.insert({
                    handle.UniqueProcessId,
                    std::move(process)
                    }).first;
            }

            if (!processHandle->second)
            {
                // process handle was not opened
                // the error has already been logged
                continue;
            }

            if (filteredProcessCache.end() == filteredProcessCache.find(handle.UniqueProcessId))
            {
                continue;
            }

            ProcessHandleInfo handleInfo;
            handleInfo.ObjectId = reinterpret_cast<size_t>(handle.Object);
            handleInfo.OwnerProcessId = handle.UniqueProcessId;
            handleInfo.ProcessName = procNameCache[handle.UniqueProcessId];
            handleInfo.HandleValue = handle.HandleValue;

            Handle dupObjHandle;
            if (!DuplicateHandle(processHandle->second,
                reinterpret_cast<HANDLE>(handle.HandleValue),
                GetCurrentProcess(),
                &dupObjHandle,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS))
            {
                auto remoteProc = remoteProcCache.find(handle.UniqueProcessId);

                if (remoteProcCache.end() == remoteProc)
                {
                    remoteProc = remoteProcCache.insert({
                        handle.UniqueProcessId,
                        RemoteSystemHandles()
                        }).first;

                    remoteProc->second.AttachToProcess(
                        handle.UniqueProcessId);
                }

                if (!remoteProc->second.IsAttached())
                {
                    LOG_WIN_ERROR("Cannot duplicate process " << handle.UniqueProcessId << " handle");
                    continue;
                }

                const HANDLE objectHandle = reinterpret_cast<HANDLE>(handle.HandleValue);

                handleInfo.ObjectType = remoteProc->second.GetTypeName(objectHandle);
                handleInfo.ObjectName = remoteProc->second.GetObjectName(objectHandle, handle.GrantedAccess);

                if (auto basicInfo = remoteProc->second.GetBasicInformation(objectHandle))
                {
                    handleInfo.HandleRefCount = basicInfo->HandleCount;
                    handleInfo.CreationTime = basicInfo->CreationTime.QuadPart;
                }
            }
            else
            {
                handleInfo.ObjectType = system.GetTypeName(dupObjHandle);
                handleInfo.ObjectName = system.GetObjectName(dupObjHandle, handle.GrantedAccess);

                if (auto basicInfo = system.GetBasicInformation(dupObjHandle))
                {
                    handleInfo.HandleRefCount = basicInfo->HandleCount - 1;
                    handleInfo.CreationTime = basicInfo->CreationTime.QuadPart;
                }
            }

            outHandles.push_back(handleInfo);
        }

        RefreshDeviceName(outHandles);
    }

    void ProcessHandles::RefreshDeviceName(std::vector<ProcessHandleInfo>& handles) const
    {
        DeviceSymlinks symlinks;
        symlinks.Refresh();

        for (auto handle : handles)
        {
            handle.DeviceName = symlinks.TryGetSymlinkByDevice(handle.ObjectName);
        }
    }

    bool ProcessHandles::IsFilteredProcessName(const std::wstring& processName) const
    {
        for (const auto& mask : m_processFilter)
        {
            if (PathMatchSpecW(processName.c_str(), mask.c_str()))
            {
                return true;
            }
        }

        return m_processFilter.empty();
    }
}
