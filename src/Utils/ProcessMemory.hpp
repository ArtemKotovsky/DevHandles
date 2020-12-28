#pragma once

#include <Windows.h>

namespace utils
{
    class ProcessMemory
    {
    public:
        ProcessMemory() = default;
        ~ProcessMemory() noexcept;
        
        ProcessMemory(const ProcessMemory&) = delete;
        ProcessMemory& operator=(const ProcessMemory&) = delete;
        
        ProcessMemory(ProcessMemory&& other) noexcept;
        ProcessMemory& operator=(ProcessMemory&& other) noexcept;

        bool alloc(HANDLE process, SIZE_T size) noexcept;
        bool realloc(HANDLE process, SIZE_T size) noexcept;
        bool protect(DWORD protect) const noexcept;

        SIZE_T read(PVOID memory, SIZE_T size, SIZE_T offset) const noexcept;
        SIZE_T write(PVOID memory, SIZE_T size, SIZE_T offset) const noexcept;

        bool read2(PVOID memory, SIZE_T size, SIZE_T offset) const noexcept;
        bool write2(PVOID memory, SIZE_T size, SIZE_T offset) const noexcept;

        void reset() noexcept;
        void release() noexcept;

        PVOID address() const noexcept;
        PVOID address(SIZE_T offset) const noexcept;
        SIZE_T size() const noexcept;
        
        explicit operator bool() const noexcept;

    private:
        SIZE_T fixSizeByOffset(SIZE_T size, SIZE_T offset) const noexcept;

    private:
        HANDLE m_processHandle = nullptr;
        PVOID m_memory = nullptr;
        SIZE_T m_size = 0;
    };
}
