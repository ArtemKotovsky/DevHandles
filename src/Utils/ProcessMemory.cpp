#include "ProcessMemory.hpp"

namespace utils
{
    ProcessMemory::~ProcessMemory() noexcept
    {
        reset();
    }

    ProcessMemory::ProcessMemory(ProcessMemory&& other) noexcept
    {
        m_processHandle = other.m_processHandle;
        m_memory = other.m_memory;
        m_size = other.m_size;

        other.release();
    }

    ProcessMemory& ProcessMemory::operator=(ProcessMemory&& other) noexcept
    {
        if (this == &other)
        {
            return *this;
        }

        reset();

        m_processHandle = other.m_processHandle;
        m_memory = other.m_memory;
        m_size = other.m_size;

        other.release();
        return *this;
    }

    bool ProcessMemory::alloc(HANDLE process, SIZE_T size) noexcept
    {
        reset();

        if (process && size)
        {
            m_memory = VirtualAllocEx(process, nullptr, size, MEM_COMMIT, PAGE_READWRITE);

            if (m_memory)
            {
                m_processHandle = process;
                m_size = size;
            }
        }

        return !!m_memory;
    }

    bool ProcessMemory::realloc(HANDLE process, SIZE_T size) noexcept
    {
        if (m_processHandle == process && size <= m_size && m_memory)
        {
            return true;
        }
        return alloc(process, size);
    }

    bool ProcessMemory::protect(DWORD protect) const noexcept
    {
        DWORD old = 0;
        return !!VirtualProtectEx(m_processHandle, m_memory, m_size, protect, &old);
    }

    SIZE_T ProcessMemory::read(PVOID memory, SIZE_T size, SIZE_T offset) const noexcept
    {
        size = fixSizeByOffset(size, offset);

        if (0 == size)
        {
            return 0;
        }

        SIZE_T returnedSize = 0;
        PVOID addr = reinterpret_cast<char*>(m_memory) + offset;

        ReadProcessMemory(m_processHandle, addr, memory, size, &returnedSize);
        return returnedSize;
    }

    SIZE_T ProcessMemory::write(PVOID memory, SIZE_T size, SIZE_T offset) const noexcept
    {
        size = fixSizeByOffset(size, offset);

        if (0 == size)
        {
            return 0;
        }

        SIZE_T returnedSize = 0;
        PVOID addr = reinterpret_cast<char*>(m_memory) + offset;

        WriteProcessMemory(m_processHandle, addr, memory, size, &returnedSize);
        return returnedSize;
    }

    bool ProcessMemory::read2(PVOID memory, SIZE_T size, SIZE_T offset) const noexcept
    {
        return read(memory, size, offset) == size;
    }

    bool ProcessMemory::write2(PVOID memory, SIZE_T size, SIZE_T offset) const noexcept
    {
        return write(memory, size, offset) == size;
    }

    void ProcessMemory::reset() noexcept
    {
        if (m_memory)
        {
            VirtualFreeEx(m_processHandle, m_memory, m_size, MEM_RELEASE);
        }

        release();
    }

    void ProcessMemory::release() noexcept
    {
        m_processHandle = nullptr;
        m_memory = nullptr;
        m_size = 0;
    }

    PVOID ProcessMemory::address() const noexcept
    {
        return m_memory;
    }

    SIZE_T ProcessMemory::size() const noexcept
    {
        return m_size;
    }

    ProcessMemory::operator bool() const noexcept
    {
        return (m_memory != nullptr);
    }

    SIZE_T ProcessMemory::fixSizeByOffset(SIZE_T size, SIZE_T offset) const noexcept
    {
        if (size > m_size)
        {
            size = m_size;
        }

        if (offset >= m_size)
        {
            return 0;
        }

        if ((size + offset) > m_size)
        {
            return m_size - offset;
        }

        return size;
    }
}
