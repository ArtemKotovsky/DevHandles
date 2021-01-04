#include "ProcessHandles.hpp"
#include "SystemHandles.hpp"
#include "RemoteSystemHandles.hpp"
#include "DeviceSymlinks.hpp"
#include "SystemUtils.hpp"
#include "ScopedHandle.hpp"
#include "Exceptions.hpp"

#include <unordered_set>
#include <future>
#include <list>
#include <iomanip>
#include <windows.h>
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
        out << h.ProcessName << " (" << std::dec << h.OwnerProcessId << ") ";
        out << "[Ref=" << std::dec << h.HandleRefCount << "] ";
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

    void ProcessHandles::SetIncludeProcessFilter(const std::vector<std::wstring>& processFilter)
    {
        m_includeProcessFilter = processFilter;
    }

    void ProcessHandles::SetExcludeProcessFilter(const std::vector<std::wstring>& processFilter)
    {
        m_excludeProcessFilter = processFilter;
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

    void ProcessHandles::Refresh(std::vector<ProcessHandleInfo>& outHandles2)
    {
        std::unordered_map<DWORD, Handle> procCache;
        std::unordered_map<DWORD, std::wstring> procNameCache;
        std::unordered_set<DWORD> filteredProcessCache;

        std::list<std::thread> threads;
        std::mutex outHandlesLock;
        std::unordered_map<uint32_t, ProcessHandleInfo> outHandles;
        uint32_t outHandleId = 0;

        SystemHandles system;
        auto handles = system.GetSystemHandles();

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
                else if (utils::IsProcessSuspended(process))
                {
                    LOG_WIN_ERROR("Process " << GetProcessName(process) << " (" << handle.UniqueProcessId << ") is suspended");
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
            const uint32_t id = ++outHandleId;

            if (!DuplicateHandle(processHandle->second,
                reinterpret_cast<HANDLE>(handle.HandleValue),
                GetCurrentProcess(),
                &dupObjHandle,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS))
            {
                auto task = std::async(std::launch::async, [&outHandles, &outHandlesLock, this](
                    ProcessHandleInfo handleInfo,
                    uint32_t handleId)
                {
                    RemoteSystemHandles remoteHandle;

                    if (!remoteHandle.AttachToProcess(handleInfo.OwnerProcessId))
                    {
                        LOG_WIN_ERROR("Cannot open process " << handleInfo.OwnerProcessId);
                        LOG_WIN_ERROR("Cannot duplicate process " << handleInfo.OwnerProcessId << " handle");
                        return;
                    }

                    const HANDLE objectHandle = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(handleInfo.HandleValue));

                    handleInfo.ObjectType = remoteHandle.GetTypeName(objectHandle);

                    if (auto basicInfo = remoteHandle.GetBasicInformation(objectHandle))
                    {
                        handleInfo.HandleRefCount = basicInfo->HandleCount;
                        handleInfo.CreationTime = basicInfo->CreationTime.QuadPart;
                    }

                    {
                        std::lock_guard<std::mutex> lock(outHandlesLock);
                        outHandles[handleId] = handleInfo;
                    }

                    std::wstring objectName = remoteHandle.GetObjectName(objectHandle);
                    std::lock_guard<std::mutex> lock(outHandlesLock);
                    outHandles[handleId].ObjectName.swap(objectName);

                }, std::move(handleInfo), id);
                
                task.wait();
            }
            else
            {
                handleInfo.ObjectType = system.GetTypeName(dupObjHandle);

                if (auto basicInfo = system.GetBasicInformation(dupObjHandle))
                {
                    handleInfo.HandleRefCount = basicInfo->HandleCount - 1;
                    handleInfo.CreationTime = basicInfo->CreationTime.QuadPart;
                }

                {
                    std::lock_guard<std::mutex> lock(outHandlesLock);
                    outHandles[id] = handleInfo;
                }

                if (handle.GrantedAccess == 0x0012019f ||
                    handle.GrantedAccess == 0x001a019f ||
                    handle.GrantedAccess == 0x00120189 || 
                    handle.GrantedAccess == 0x00120089 ||
                    handle.GrantedAccess == 0x00120116)
                {
                    auto task = std::thread([&outHandlesLock, &outHandles, this](
                        Handle dupObjHandle,
                        uint32_t id)
                    {
                        std::wstring objectName = SystemHandles().GetObjectName(dupObjHandle);
                        std::lock_guard<std::mutex> lock(outHandlesLock);
                        outHandles[id].ObjectName.swap(objectName);
                
                    }, std::move(dupObjHandle), id);

                    threads.push_back(std::move(task));
                }
                else
                {
                    std::wstring objectName = SystemHandles().GetObjectName(dupObjHandle);
                    std::lock_guard<std::mutex> lock(outHandlesLock);
                    outHandles[id].ObjectName.swap(objectName);
                }
            }
        }

        if (!threads.empty())
        {
            bool needWait = true;

            for (auto& thread : threads)
            {
                if (needWait)
                {
                    if (WAIT_TIMEOUT == WaitForSingleObject(thread.native_handle(), 1000))
                    {
                        needWait = false;
                        TerminateThread(thread.native_handle(), 1);
                    }
                }
                else
                {
                    if (WAIT_OBJECT_0 != WaitForSingleObject(thread.native_handle(), 0))
                    {
                        TerminateThread(thread.native_handle(), 1);
                    }
                }

                thread.join();
            }
        }

        outHandles2.clear();
        outHandles2.reserve(outHandles.size());

        for (auto& h : outHandles)
        {
            outHandles2.push_back(std::move(h.second));
        }

        RefreshDeviceName(outHandles2);
    }

    void ProcessHandles::RefreshDeviceName(std::vector<ProcessHandleInfo>& handles) const
    {
        DeviceSymlinks symlinks;
        symlinks.Refresh();

        for (auto& handle : handles)
        {
            handle.DeviceName = symlinks.TryGetSymlinkByDevice(handle.ObjectName);
        }
    }

    bool ProcessHandles::IsFilteredProcessName(const std::wstring& processName) const
    {
        for (const auto& mask : m_excludeProcessFilter)
        {
            if (PathMatchSpecW(processName.c_str(), mask.c_str()))
            {
                return false;
            }
        }

        for (const auto& mask : m_includeProcessFilter)
        {
            if (PathMatchSpecW(processName.c_str(), mask.c_str()))
            {
                return true;
            }
        }

        return m_includeProcessFilter.empty();
    }
}
