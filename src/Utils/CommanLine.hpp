#pragma once

#include "Exceptions.hpp"

#include <vector>
#include <string>
#include <sstream>

namespace utils
{
    template<typename Class>
    struct CommandLine
    {
        template<typename T>
        static bool TryParseNumber(const std::wstring& value, T& number)
        {
            try
            {
                size_t idx = 0;
                long long val = std::stoll(value, &idx, 0);

                if (value.size() != idx)
                {
                    return false;
                }

                number = static_cast<T>(val);
                THROW_IF(number != val, "Incorrect value " << val);
                return true;
            }
            catch (const std::exception&)
            {
                return false;
            }
        }

        static bool TryParseArg(const std::wstring& argName, const std::wstring& argValue, std::wstring& arg)
        {
            if (0 != argValue.find(argName))
            {
                return false;
            }

            arg.assign(argValue.begin() + argName.size(), argValue.end());
            return true;
        }

        static std::vector<std::wstring> Split(const std::wstring& value, wchar_t splitter, bool includeEmpty)
        {
            std::vector<std::wstring> res;
            std::wstringstream wss(value);
            std::wstring item;
            while (std::getline(wss, item, splitter))
            {
                if (!item.empty() || includeEmpty)
                {
                    res.push_back(item);
                }
            }
            return res;
        }

        static bool HasHelpArg(int argc, wchar_t** argv)
        {
            for (int i = 0; i < argc; ++i)
            {
                if (0 == _wcsicmp(L"h", argv[i])
                    || 0 == _wcsicmp(L"-h", argv[i])
                    || 0 == _wcsicmp(L"/h", argv[i])
                    || 0 == _wcsicmp(L"--help", argv[i])
                    || 0 == _wcsicmp(L"/help", argv[i])
                    || 0 == _wcsicmp(L"help", argv[i])
                    || 0 == _wcsicmp(L"-help", argv[i]))
                {
                    return true;
                }
            }

            return false;
        }

        static bool PrintHelp(int argc, wchar_t** argv)
        {
            if (HasHelpArg(argc, argv))
            {
                Class::Help();
                return true;
            }
            return false;
        }
    };
}