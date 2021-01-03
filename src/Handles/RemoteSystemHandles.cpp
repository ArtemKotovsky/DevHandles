#include "RemoteSystemHandles.hpp"
#include "Exceptions.hpp"
#include "ScopedHandle.hpp"
#include "ProcessMemory.hpp"

#define ASMJIT_STATIC
#define ASMJIT_EMBED
#pragma warning(push, 0)
#pragma warning(disable : 6011 6387 26451 26495 26498 26812)
#include <asmjit/asmjit.h>
#pragma warning(pop)

#define JIT(_code_) if (asmjit::kErrorOk != ##_code_) { THROW("Asm jit error at " << __LINE__)}
#define OFFS(_field_) offsetof(RemoteProcMemoory, _field_)

namespace hndl
{
    using Handle = utils::ScopedHandle<HANDLE, decltype(::CloseHandle), ::CloseHandle, nullptr>;

#pragma pack(push, 1)
    struct RemoteProcMemoory
    {
        // Code 3072 bytes
        uint8_t CodeNtQueryObject[1024];
        uint8_t CodeReserved[1024];
        uint8_t CodeExceptionHandler[1024]; // the latest func in this struct

        // Data 1024 bytes
        uint64_t DataReturnLength;
        uint64_t DataStatus;
        uint64_t DataDynamicTable;
        uint64_t DataRsp;
        RUNTIME_FUNCTION DataRuntimeFunc;
        UNWIND_INFO DataUnwindInfo[1];
        uint8_t DataAlignment2[974];
    };
#pragma pack(pop)

    static_assert(sizeof(RemoteProcMemoory) == 4096, "Error");
    static_assert(offsetof(RemoteProcMemoory, DataRuntimeFunc) % sizeof(DWORD32) == 0, "MSDN: error");
    static_assert(offsetof(RemoteProcMemoory, DataUnwindInfo) % sizeof(DWORD32) == 0, "MSDN: error");

    struct RemoteSystemHandles::Impl
    {
        std::vector<char> JitCode;
        utils::ProcessMemory Data;
        utils::ProcessMemory Mem; // RemoteProcMemoory
        Handle Process;
        uint64_t NtQueryObjectAddr = 0;
        uint64_t NtTerminateThreadAddr = 0;
        uint64_t RtlAddGrowableFunctionTableAddr = 0;
        uint64_t RtlDeleteGrowableFunctionTableAddr = 0;
        RUNTIME_FUNCTION RemoteRuntimeFunc{};
    };

    RemoteSystemHandles::RemoteSystemHandles()
        : m_impl(std::make_unique<Impl>())
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll");
        THROW_WIN_IF(!ntdll, "Cannot get ntdll");

        m_impl->NtQueryObjectAddr = reinterpret_cast<uint64_t>(GetProcAddress(ntdll, "NtQueryObject"));
        THROW_WIN_IF(!m_impl->NtQueryObjectAddr, "Cannot get NtQueryObject address");

        m_impl->NtTerminateThreadAddr = reinterpret_cast<uint64_t>(GetProcAddress(ntdll, "NtTerminateThread"));
        THROW_WIN_IF(!m_impl->NtTerminateThreadAddr, "Cannot get NtTerminateThread address");

        m_impl->RtlAddGrowableFunctionTableAddr = reinterpret_cast<uint64_t>(GetProcAddress(ntdll, "RtlAddGrowableFunctionTable"));
        THROW_WIN_IF(!m_impl->RtlAddGrowableFunctionTableAddr, "Cannot get RtlAddGrowableFunctionTable address");

        m_impl->RtlDeleteGrowableFunctionTableAddr = reinterpret_cast<uint64_t>(GetProcAddress(ntdll, "RtlDeleteGrowableFunctionTable"));
        THROW_WIN_IF(!m_impl->RtlDeleteGrowableFunctionTableAddr, "Cannot get RtlDeleteGrowableFunctionTable address");
    }

    RemoteSystemHandles::~RemoteSystemHandles() = default;
    RemoteSystemHandles::RemoteSystemHandles(RemoteSystemHandles&&) noexcept = default;
    RemoteSystemHandles& RemoteSystemHandles::operator=(RemoteSystemHandles&&) noexcept = default;

    bool RemoteSystemHandles::AttachToProcess(uint32_t pid)
    {
        m_impl->Process.reset(OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_READ | 
            PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE, 
            pid));
        return !!m_impl->Process;
    }

    bool RemoteSystemHandles::IsAttached() const
    {
        return !!m_impl->Process;
    }

#pragma warning(suppress : 26812) // The enum type '_OBJECT_INFORMATION_CLASS' is unscoped. Prefer 'enum class' over 'enum' (Enum.3)
    NTSTATUS RemoteSystemHandles::RemoteQueryObject(HANDLE handle,
        OBJECT_INFORMATION_CLASS objectInformationClass,
        PVOID objectInformation,
        ULONG objectInformationLength,
        PULONG returnLength) const
    {
        if (!m_impl->Data.realloc(m_impl->Process, objectInformationLength))
        {
            return STATUS_NO_MEMORY;
        }

        NTSTATUS status = ExecQueryObject(handle, 
            objectInformationClass, 
            objectInformationLength, 
            returnLength);

        if (NT_ERROR(status))
        {
            return status;
        }

        if (!m_impl->Data.read2(objectInformation, *returnLength, 0))
        {
            return STATUS_NO_MEMORY;
        }

        status = RelocateObjectInformation(
            objectInformationClass,
            objectInformation,
            *returnLength,
            m_impl->Data.address());

        if (NT_ERROR(status))
        {
            return status;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS RemoteSystemHandles::ExecQueryObject(HANDLE handle,
        OBJECT_INFORMATION_CLASS objectInformationClass,
        ULONG objectInformationLength,
        PULONG returnLength) const
    {
        if (!m_impl->Mem.realloc(m_impl->Process, sizeof(RemoteProcMemoory)) ||
            !m_impl->Mem.protect(PAGE_EXECUTE_READWRITE))
        {
            return STATUS_NO_MEMORY;
        }

        const uint64_t remoteReturnLengthPtr = reinterpret_cast<uint64_t>(m_impl->Mem.address(OFFS(DataReturnLength)));
        const uint64_t remoteStatusPtr = reinterpret_cast<uint64_t>(m_impl->Mem.address(OFFS(DataStatus)));

        uint64_t remoteStatus = 0xffffffffffffffff;
        uint64_t remoteReturnLength = 0;

        if (!m_impl->Mem.write2(&remoteReturnLength, sizeof(remoteReturnLength), OFFS(DataReturnLength)) ||
            !m_impl->Mem.write2(&remoteStatus, sizeof(remoteStatus), OFFS(DataStatus)))
        {
            return STATUS_NO_MEMORY;
        }

        NTSTATUS status = PrepareJitCode(
            reinterpret_cast<uint64_t>(handle),
            static_cast<uint64_t>(objectInformationClass),
            reinterpret_cast<uint64_t>(m_impl->Data.address()),
            objectInformationLength,
            remoteReturnLengthPtr,
            remoteStatusPtr);

        if (NT_ERROR(status))
        {
            return status;
        }

        if (0 != RunRemoteThread())
        {
            return STATUS_UNSUCCESSFUL;
        }

        if (!m_impl->Mem.read2(&remoteReturnLength, sizeof(remoteReturnLength), OFFS(DataReturnLength)) ||
            !m_impl->Mem.read2(&remoteStatus, sizeof(remoteStatus), OFFS(DataStatus)))
        {
            return STATUS_NO_MEMORY;
        }

        *returnLength = static_cast<ULONG>(remoteReturnLength);
        return static_cast<NTSTATUS>(remoteStatus);
    }

    DWORD RemoteSystemHandles::RunRemoteThread() const
    {
        LPTHREAD_START_ROUTINE func = reinterpret_cast<LPTHREAD_START_ROUTINE>(m_impl->Mem.address(OFFS(CodeNtQueryObject)));
        Handle remoteThread = CreateRemoteThread(m_impl->Process, 0, 0, func, 0, 0, 0);

        if (!remoteThread)
        {
            return GetLastError();
        }

        DWORD status = WaitForSingleObject(remoteThread, 10000);

        if (WAIT_OBJECT_0 != status)
        {
#pragma warning(suppress : 6258) // Using TerminateThread
            if (!TerminateThread(remoteThread, 1))
            {
                return GetLastError();
            }

            return ERROR_USER_APC;
        }

        DWORD exitCode = 0;
        
        if (!GetExitCodeThread(remoteThread, &exitCode))
        {
            return GetLastError();
        }

        return exitCode;
    }

    NTSTATUS RemoteSystemHandles::PrepareJitExceptionHandler() const
    {
        //
        // Jit Exception Handler function
        //
        asmjit::JitRuntime runtime;
        asmjit::CodeHolder code;
        JIT(code.init(runtime.environment()));

        asmjit::x86::Assembler a(&code);
        // JIT(a.int3()); // Breakpoint

        //
        // Remove exception handler
        //
        JIT(a.mov(asmjit::x86::rcx, m_impl->Mem.address(OFFS(DataDynamicTable))));
        JIT(a.mov(asmjit::x86::rcx, asmjit::x86::qword_ptr(asmjit::x86::rcx))); // DynamicTable
        JIT(a.sub(asmjit::x86::rsp, 0x20));
        JIT(a.mov(asmjit::x86::rax, m_impl->RtlDeleteGrowableFunctionTableAddr));
        JIT(a.call(asmjit::x86::rax)); // RtlDeleteGrowableFunctionTable
        JIT(a.add(asmjit::x86::rsp, 0x20));

        //
        // Terminate thread
        //
        JIT(a.mov(asmjit::x86::rcx, -2)); // ThreadHandle, GetCurrentThread()
        JIT(a.mov(asmjit::x86::rdx, -1));  // ExitStatus, non zero
        JIT(a.mov(asmjit::x86::rax, m_impl->NtTerminateThreadAddr)); // func addr
        JIT(a.call(asmjit::x86::rax)); // call the func, it never returns

        //
        // Prepare remote memory for the jit
        //
        m_impl->JitCode.resize(code.codeSize());

        if (sizeof(RemoteProcMemoory::CodeExceptionHandler) < code.codeSize())
        {
            return STATUS_NO_MEMORY;
        }

        JIT(code.relocateToBase(reinterpret_cast<UINT64>(m_impl->Mem.address(OFFS(CodeExceptionHandler)))));

        //
        // Copy the jit code
        //
        THROW_IF(1 != code.sectionCount(), "Jit: more that one section (EH)!");
        JIT(code.copySectionData(m_impl->JitCode.data(), m_impl->JitCode.size(), 0));

        if (!m_impl->Mem.write2(m_impl->JitCode.data(), m_impl->JitCode.size(), OFFS(CodeExceptionHandler)))
        {
            return STATUS_NO_MEMORY;
        }

        //
        // Fill the EH structures
        //
        const ULONG64 base = reinterpret_cast<ULONG64>(m_impl->Mem.address());
        const ULONG64 firstFunc = reinterpret_cast<ULONG64>(m_impl->Mem.address(OFFS(CodeNtQueryObject)));
        const ULONG64 handler = reinterpret_cast<ULONG64>(m_impl->Mem.address(OFFS(CodeExceptionHandler)));
        const ULONG64 dataUnwindInfo = reinterpret_cast<ULONG64>(m_impl->Mem.address(OFFS(DataUnwindInfo)));

        UNWIND_INFO unwindInfo{};
        unwindInfo.Version = 1;
        unwindInfo.Flags = UNW_FLAG_EHANDLER;
        unwindInfo.SizeOfProlog = 0;
        unwindInfo.CountOfCodes = 0;
        unwindInfo.FrameRegister = 0;
        unwindInfo.FrameOffset = 0;
        unwindInfo.UnwindCode[0].FrameOffset = static_cast<USHORT>(handler - base);

        m_impl->RemoteRuntimeFunc.BeginAddress = static_cast<ULONG>(firstFunc - base); // any exception from the beginning of the memory
        m_impl->RemoteRuntimeFunc.EndAddress = static_cast<ULONG>(handler - base); // up to the excextion handler
        m_impl->RemoteRuntimeFunc.UnwindInfoAddress = static_cast<ULONG>(dataUnwindInfo - base); // RVA of unwind info

        //
        // Write the EH structures
        //
        if (!m_impl->Mem.write2(&m_impl->RemoteRuntimeFunc, sizeof(m_impl->RemoteRuntimeFunc), OFFS(DataRuntimeFunc)) ||
            !m_impl->Mem.write2(&unwindInfo, sizeof(unwindInfo), OFFS(DataUnwindInfo)))
        {
            return STATUS_NO_MEMORY;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS RemoteSystemHandles::PrepareJitCode(
        ULONG64 handle,
        ULONG64 objectInformationClass,
        ULONG64 objectInformation,
        ULONG64 objectInformationLength,
        ULONG64 returnLengthPtr,
        ULONG64 statusPtr) const
    {
        BOOL wow64 = FALSE;

        if (!IsWow64Process(m_impl->Process, &wow64))
        {
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status = PrepareJitExceptionHandler();

        if (NT_ERROR(status))
        {
            return status;
        }

        if (wow64)
        {
            return PrepareJitCode86(
                handle,
                objectInformationClass,
                objectInformation,
                objectInformationLength,
                returnLengthPtr,
                statusPtr);
        }

        return PrepareJitCode64(
            handle,
            objectInformationClass,
            objectInformation,
            objectInformationLength,
            returnLengthPtr,
            statusPtr);
    }

    NTSTATUS RemoteSystemHandles::PrepareJitCode64(
        ULONG64 handle,
        ULONG64 objectInformationClass,
        ULONG64 objectInformation,
        ULONG64 objectInformationLength,
        ULONG64 returnLengthPtr,
        ULONG64 statusPtr) const
    {
        asmjit::JitRuntime runtime;
        asmjit::CodeHolder code;
        JIT(code.init(runtime.environment()));

        asmjit::x86::Assembler a(&code);

        // Breakpoint
        // JIT(a.int3());

        //
        // Add exception handler
        //
        JIT(a.mov(asmjit::x86::rcx, m_impl->Mem.address(OFFS(DataDynamicTable))));  // DynamicTable
        JIT(a.mov(asmjit::x86::rdx, m_impl->Mem.address(OFFS(DataRuntimeFunc))));   // FunctionTable
        JIT(a.mov(asmjit::x86::r8, 1));                                             // EntryCount
        JIT(a.mov(asmjit::x86::r9, 1));                                             // MaximumEntryCount
        JIT(a.mov(asmjit::x86::rax, m_impl->Mem.address(m_impl->RemoteRuntimeFunc.EndAddress)));
        JIT(a.push(asmjit::x86::rax));                                              // RangeEnd
        JIT(a.mov(asmjit::x86::rax, m_impl->Mem.address(m_impl->RemoteRuntimeFunc.BeginAddress)));
        JIT(a.push(asmjit::x86::rax));                                              // RangeBase

        JIT(a.sub(asmjit::x86::rsp, 0x20));
        JIT(a.mov(asmjit::x86::rax, m_impl->RtlAddGrowableFunctionTableAddr));
        JIT(a.call(asmjit::x86::rax)); // RtlAddGrowableFunctionTable
        JIT(a.add(asmjit::x86::rsp, 0x30));

        //
        // NtQueryObject args, Windows fastcall64 
        //
        JIT(a.mov(asmjit::x86::rcx, handle));
        JIT(a.mov(asmjit::x86::rdx, objectInformationClass));
        JIT(a.mov(asmjit::x86::r8, objectInformation));
        JIT(a.mov(asmjit::x86::r9, objectInformationLength));
        JIT(a.mov(asmjit::x86::rax, returnLengthPtr));
        JIT(a.push(asmjit::x86::rax)); //qword ptr[rsp + 20h], 5

        //
        // Call NtQueryObject function by dirrect address
        //
        JIT(a.sub(asmjit::x86::rsp, 0x20));
        JIT(a.mov(asmjit::x86::rax, m_impl->NtQueryObjectAddr));
        JIT(a.call(asmjit::x86::rax));
        JIT(a.add(asmjit::x86::rsp, 0x28));

        //
        // Save the ret status to a known memory
        //
        JIT(a.mov(asmjit::x86::rcx, statusPtr));
        JIT(a.mov(asmjit::x86::dword_ptr(asmjit::x86::rcx), asmjit::x86::rax));

        //
        // Remove exception handler
        //
        JIT(a.mov(asmjit::x86::rcx, m_impl->Mem.address(OFFS(DataDynamicTable))));
        JIT(a.mov(asmjit::x86::rcx, asmjit::x86::qword_ptr(asmjit::x86::rcx))); // DynamicTable
        JIT(a.sub(asmjit::x86::rsp, 0x20));
        JIT(a.mov(asmjit::x86::rax, m_impl->RtlDeleteGrowableFunctionTableAddr));
        JIT(a.call(asmjit::x86::rax)); // RtlDeleteGrowableFunctionTable
        JIT(a.add(asmjit::x86::rsp, 0x20));

        //
        // Return from the thread function, 
        // status=0 - everything is ok
        //
        JIT(a.mov(asmjit::x86::rax, 0));
        JIT(a.ret());

        //
        // Prepare remote memory for the jit
        //
        m_impl->JitCode.resize(code.codeSize());

        if (sizeof(RemoteProcMemoory::CodeNtQueryObject) < code.codeSize())
        {
            return STATUS_NO_MEMORY;
        }

        JIT(code.relocateToBase(reinterpret_cast<UINT64>(m_impl->Mem.address(OFFS(CodeNtQueryObject)))));

        //
        // Copy jit code
        //
        THROW_IF(1 != code.sectionCount(), "Jit: more that one section!");
        JIT(code.copySectionData(m_impl->JitCode.data(), m_impl->JitCode.size(), 0));

        if (!m_impl->Mem.write2(m_impl->JitCode.data(), m_impl->JitCode.size(), OFFS(CodeNtQueryObject)))
        {
            return STATUS_NO_MEMORY;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS RemoteSystemHandles::PrepareJitCode86(
        ULONG64 handle,
        ULONG64 objectInformationClass,
        ULONG64 objectInformation,
        ULONG64 objectInformationLength,
        ULONG64 returnLengthPtr,
        ULONG64 statusPtr) const
    {
        //
        // The WOW64 JIT code:
        // 1. switch from x86 to x64
        // 2. call the function
        // 3. switch back to x86
        // 4. return from the thread function
        //

        THROW_IF(handle > ULONG_MAX, "Handle wow64 wrong value");
        THROW_IF(objectInformationClass > ULONG_MAX, "Class wow64 wrong value");
        THROW_IF(objectInformation > ULONG_MAX, "Memory wow64 wrong value");
        THROW_IF(objectInformationLength > ULONG_MAX, "Length wow64 wrong value");
        THROW_IF(returnLengthPtr > ULONG_MAX, "RetLength wow64 wrong value");
        THROW_IF(statusPtr > ULONG_MAX, "Status wow64 wrong value");

        asmjit::JitRuntime runtime;
        asmjit::CodeHolder code;
        JIT(code.init(runtime.environment()));

        asmjit::x86::Assembler a(&code);

        // Breakpoint
        // JIT(a.int3());

        asmjit::Label funcSwitchTo64 = a.newLabel();
        asmjit::Label funcSwitchTo86 = a.newLabel();

        //
        // x86 code: switch to 64bit mode
        //
        // Save regs according to the STDCALL
        //
        JIT(a.push(asmjit::x86::ebx));
        JIT(a.push(asmjit::x86::esi));
        JIT(a.push(asmjit::x86::edi));
        JIT(a.push(asmjit::x86::ebp));

        //
        // Call a function funcSwitchTo64,
        // we need the ret address in the stack to work with it
        //
        JIT(a.call(funcSwitchTo64));

        //
        // Align RSP to 8 bytes
        //
        JIT(a.mov(asmjit::x86::rax, m_impl->Mem.address(OFFS(DataRsp))));
        JIT(a.mov(asmjit::x86::qword_ptr(asmjit::x86::rax), asmjit::x86::rsp));
        
        JIT(a.add(asmjit::x86::rsp, 8));
        JIT(a.and_(asmjit::x86::rsp, ~7));

        //
        // x64 code, run the function and switch it back
        //
        JIT(a.mov(asmjit::x86::rcx, m_impl->Mem.address(OFFS(DataDynamicTable))));  // DynamicTable
        JIT(a.mov(asmjit::x86::rdx, m_impl->Mem.address(OFFS(DataRuntimeFunc))));   // FunctionTable
        JIT(a.mov(asmjit::x86::r8, 1));                                             // EntryCount
        JIT(a.mov(asmjit::x86::r9, 1));                                             // MaximumEntryCount
        JIT(a.mov(asmjit::x86::rax, m_impl->Mem.address(m_impl->RemoteRuntimeFunc.EndAddress)));
        JIT(a.push(asmjit::x86::rax));                                              // RangeEnd
        JIT(a.mov(asmjit::x86::rax, m_impl->Mem.address(m_impl->RemoteRuntimeFunc.BeginAddress)));
        JIT(a.push(asmjit::x86::rax));                                              // RangeBase
        
        JIT(a.sub(asmjit::x86::rsp, 0x20));
        JIT(a.mov(asmjit::x86::rax, m_impl->RtlAddGrowableFunctionTableAddr));
        JIT(a.call(asmjit::x86::rax)); // RtlAddGrowableFunctionTable
        JIT(a.add(asmjit::x86::rsp, 0x30));

        //
        // NtQueryObject args, Windows fastcall64 
        //
        JIT(a.mov(asmjit::x86::rcx, handle));
        JIT(a.mov(asmjit::x86::rdx, objectInformationClass));
        JIT(a.mov(asmjit::x86::r8, objectInformation));
        JIT(a.mov(asmjit::x86::r9, objectInformationLength));
        JIT(a.mov(asmjit::x86::rax, returnLengthPtr));
        JIT(a.push(asmjit::x86::rax)); //qword ptr[rsp + 20h], 5

        //
        // Call NtQueryObject function by dirrect address
        //
        JIT(a.sub(asmjit::x86::rsp, 0x20));
        JIT(a.mov(asmjit::x86::rax, m_impl->NtQueryObjectAddr));
        JIT(a.call(asmjit::x86::rax));
        JIT(a.add(asmjit::x86::rsp, 0x28));

        //
        // Save the ret status to a known memory
        //
        JIT(a.mov(asmjit::x86::rcx, statusPtr));
        JIT(a.mov(asmjit::x86::dword_ptr(asmjit::x86::rcx), asmjit::x86::rax));

        //
        // Remove exception handler
        //
        JIT(a.mov(asmjit::x86::rcx, m_impl->Mem.address(OFFS(DataDynamicTable))));
        JIT(a.mov(asmjit::x86::rcx, asmjit::x86::qword_ptr(asmjit::x86::rcx))); // DynamicTable
        JIT(a.sub(asmjit::x86::rsp, 0x20));
        JIT(a.mov(asmjit::x86::rax, m_impl->RtlDeleteGrowableFunctionTableAddr));
        JIT(a.call(asmjit::x86::rax)); // RtlDeleteGrowableFunctionTable
        JIT(a.add(asmjit::x86::rsp, 0x20));

        //
        // Restore aligned RSP
        //
        JIT(a.mov(asmjit::x86::rax, m_impl->Mem.address(OFFS(DataRsp))));
        JIT(a.mov(asmjit::x86::rsp, asmjit::x86::qword_ptr(asmjit::x86::rax)));

        //
        // x64bit switch back to x86
        //
        JIT(a.call(funcSwitchTo86));

        //
        // x86 code, restore the regs 
        // according to the STDCALL
        //
        JIT(a.pop(asmjit::x86::ebp));
        JIT(a.pop(asmjit::x86::edi));
        JIT(a.pop(asmjit::x86::esi));
        JIT(a.pop(asmjit::x86::ebx));

        //
        // Return 0 from the thread function
        //
        JIT(a.mov(asmjit::x86::eax, 0));
        JIT(a.ret());

        //
        // Function: switching from 32-bit to 64-bit mode
        //
        a.bind(funcSwitchTo64);
        JIT(a.pop(asmjit::x86::eax));   // pop ret address
        JIT(a.push(0x33));              // push x64 selector
        JIT(a.push(asmjit::x86::eax));  // push ret address 
        JIT(a.db(0xCB));                // retf

        //
        // Function switching back from 64-bit to 32-bit mode
        //
        a.bind(funcSwitchTo86);
        JIT(a.pop(asmjit::x86::rax));       // pop ret address
        JIT(a.sub(asmjit::x86::rsp, 8));    // alloc 8 bytes 
        JIT(a.mov(asmjit::x86::dword_ptr(asmjit::x86::rsp), asmjit::x86::eax)); // ret address
        JIT(a.mov(asmjit::x86::dword_ptr(asmjit::x86::rsp, 4), 0x23));          // x86 selector
        JIT(a.db(0xCB));                    // retf

        //
        // Prepare remote memory for the jit
        //
        m_impl->JitCode.resize(code.codeSize());

        if (sizeof(RemoteProcMemoory::CodeNtQueryObject) < code.codeSize())
        {
            return STATUS_NO_MEMORY;
        }

        JIT(code.relocateToBase(reinterpret_cast<UINT64>(m_impl->Mem.address(OFFS(CodeNtQueryObject)))));

        //
        // Copy jit code
        //
        THROW_IF(1 != code.sectionCount(), "Jit: more that one section!");
        JIT(code.copySectionData(m_impl->JitCode.data(), m_impl->JitCode.size(), 0));

        if (!m_impl->Mem.write2(m_impl->JitCode.data(), m_impl->JitCode.size(), OFFS(CodeNtQueryObject)))
        {
            return STATUS_NO_MEMORY;
        }

        return STATUS_SUCCESS;
    }

    void RemoteSystemHandles::RelocateUnicodeString(
        UNICODE_STRING& us,
        LONG_PTR base,
        LONG_PTR remoteBase,
        SIZE_T size) const
    {
        if (!us.Buffer)
        {
            return;
        }

        const LONG_PTR diff = base - remoteBase;
        const LONG_PTR relocatedBuffer = reinterpret_cast<LONG_PTR>(us.Buffer) + diff;
        us.Buffer = reinterpret_cast<PWSTR>(relocatedBuffer);

        const LONG_PTR baseEnd = base + size;
        const LONG_PTR buffer = reinterpret_cast<LONG_PTR>(us.Buffer);

        if (buffer < base || buffer >= baseEnd)
        {
            THROW("Cannot relocate unicode string");
        }
    }

    NTSTATUS RemoteSystemHandles::RelocateObjectInformation(
        OBJECT_INFORMATION_CLASS objectInformationClass,
        PVOID objectInformation,
        ULONG objectInformationLength,
        PVOID remoteBase) const
    {
        const INT_PTR newBase = reinterpret_cast<INT_PTR>(objectInformation);
        const INT_PTR oldBase = reinterpret_cast<INT_PTR>(remoteBase);

        switch (objectInformationClass)
        {
        case ObjectNameInformation:
        {
            auto name = reinterpret_cast<POBJECT_NAME_INFORMATION>(objectInformation);
            RelocateUnicodeString(name->Name, newBase, oldBase, objectInformationLength);
            return STATUS_SUCCESS;
        }

        case ObjectTypeInformation:
        {
            auto type = reinterpret_cast<POBJECT_TYPE_INFORMATION>(objectInformation);
            RelocateUnicodeString(type->TypeName, newBase, oldBase, objectInformationLength);
            return STATUS_SUCCESS;
        }

        case ObjectBasicInformation:
            return STATUS_SUCCESS;

        default:
            return STATUS_NOT_IMPLEMENTED;
        }
    }

    NTSTATUS RemoteSystemHandles::QueryObjectFn(
        _In_ HANDLE Handle,
        _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
        _Out_opt_ PVOID ObjectInformation,
        _In_ ULONG ObjectInformationLength,
        _Out_opt_ PULONG ReturnLength)
    {
        return RemoteQueryObject(Handle,
            ObjectInformationClass,
            ObjectInformation,
            ObjectInformationLength,
            ReturnLength);
    }
}
