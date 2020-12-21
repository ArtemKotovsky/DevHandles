#include <iomanip>
#include <Windows.h>
#include <shlwapi.h>

#include "Log.hpp"
#include "CommanLine.hpp"
#include "ProcessHandles.hpp"
#include "SystemUtils.hpp"

#pragma comment(lib, "Shlwapi.lib")

namespace
{
    struct CL : public utils::CommandLine<CL>
    {
        CL(int argc, wchar_t** argv)
        {
            std::wstring value;

            for (int i = 1; i < argc; ++i)
            {
                if (TryParseArg(L"--filter=", argv[i], value))
                {
                    Filters = Split(value, L';', false);
                }
                else if (TryParseArg(L"--process=", argv[i], value))
                {
                    Process = Split(value, L';', false);
                }
                else if (TryParseArg(L"--verbose", argv[i], value)
                      || TryParseArg(L"-v", argv[i], value))
                {
                    logger::LogErrors = true;
                }
                else if (TryParseArg(L"--timeout=", argv[i], value))
                {
                    if (!TryParseNumber(value, Timeout))
                    {
                        THROW("Invalid timeout value");
                    }
                }
                else
                {
                    LOG("Unknown option '" << argv[i] << "'");
                    THROW("Unknown option");
                }
            }
        }

        static void Help()
        {
            LOG("Usage:");
            LOG("   --filter=[wildcard-mask-list] - objects filter, splitter is ';', default is *");
            LOG("   --process=[wildcard-mask-list] - process names, splitter is ';', default is *");
            LOG("   --timeout=[seconds] - enables monitoring by timeout");
            LOG("   --verbose,-v - extra logging");
            LOG("\nExamples:");
            LOG("   --filter=*VID_8086*;File;*device* --process=explorer.exe --timeout=10 --verbose");
            LOG("   --filter=*USB* --process=cmd.exe|explorer.exe --timeout=10");
            LOG("   --filter=\\Device\\Mup\\* --timeout=10");
            LOG("   --process=explorer.exe");
            LOG("   --timeout=5");
        }

        std::vector<std::wstring> Process;
        std::vector<std::wstring> Filters;
        std::uint32_t Timeout = 0;
    };

    bool Filter(const hndl::ProcessHandleInfo& handle, const std::vector<std::wstring>& filters)
    {
        for (const auto& mask : filters)
        {
            if (PathMatchSpecW(handle.DeviceName.c_str(), mask.c_str()) ||
                PathMatchSpecW(handle.ObjectName.c_str(), mask.c_str()) ||
                PathMatchSpecW(handle.ObjectType.c_str(), mask.c_str()) ||
                PathMatchSpecW(handle.ProcessName.c_str(), mask.c_str()))
            {
                return true;
            }
        }

        return filters.empty();
    }

    void PrintHandles(const std::vector<hndl::ProcessHandleInfo>& handles, 
        const std::vector<std::wstring>& filters,
        bool showTime)
    {
        std::wstring time = showTime ? utils::GetTime(L"%H:%M:%S") : L"";

        for (auto h : handles)
        {
            if (Filter(h, filters))
            {
                LOG(time << h);
            }
        }
    }

    void ErrorCallback(std::wstring message, uint32_t win32Error)
    {
        LOG_WIN_ERROR(win32Error, message);
    }
}

int wmain(int argc, wchar_t ** argv)
{
    try
    {
        if (CL::PrintHelp(argc, argv))
        {
            return 0;
        }

        CL cl(argc, argv);

        utils::EnablePrivilege(SE_DEBUG_NAME);

        hndl::ProcessHandles processHandles;
        processHandles.SetErrorCallback(ErrorCallback);
        processHandles.SetProcessFilter(cl.Process);
        processHandles.Refresh();

        auto handles = processHandles.GetHandles();
        PrintHandles(handles, cl.Filters, 0 != cl.Timeout);

        while (0 != cl.Timeout)
        {
            Sleep(cl.Timeout * 1000);
            auto changes = processHandles.Update();
            PrintHandles(changes, cl.Filters, true);
        }

        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "\nError: " << ex.what() << "\n\n";
        return -1;
    }
}
