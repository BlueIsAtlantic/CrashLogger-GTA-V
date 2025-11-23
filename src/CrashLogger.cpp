#include <windows.h>
#include <DbgHelp.h>
#include <fstream>
#include <string>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <psapi.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <tlhelp32.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

#define LOG_FILE "CrashLogger_Log.txt"
#define MAX_STACK_FRAMES 64
#define FREEZE_CHECK_INTERVAL_MS 2000  // Check every 2 seconds
#define FREEZE_THRESHOLD_MS 10000      // 10 seconds = frozen

static LPTOP_LEVEL_EXCEPTION_FILTER g_previousFilter = nullptr;
static std::atomic<bool> g_watchdogRunning(false);
static std::thread g_watchdogThread;
static DWORD g_mainThreadId = 0;

void WriteLog(const std::string& text)
{
    char buffer[512];
    time_t now = time(0);
    struct tm tstruct;
    localtime_s(&tstruct, &now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %X", &tstruct);

    std::ofstream logfile(LOG_FILE, std::ios::app);
    if (logfile.is_open())
    {
        logfile << "[" << buffer << "] " << text << std::endl;
        logfile.close();
    }
}

void WriteStackTrace(CONTEXT* context)
{
    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();

    SymInitialize(process, NULL, TRUE);
    SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);

    STACKFRAME64 stackFrame = {};
    DWORD machineType;

#if defined(_M_X64)
    machineType = IMAGE_FILE_MACHINE_AMD64;
    stackFrame.AddrPC.Offset = context->Rip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = context->Rbp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = context->Rsp;
    stackFrame.AddrStack.Mode = AddrModeFlat;
#else
    machineType = IMAGE_FILE_MACHINE_I386;
    stackFrame.AddrPC.Offset = context->Eip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = context->Ebp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = context->Esp;
    stackFrame.AddrStack.Mode = AddrModeFlat;
#endif

    WriteLog("=== Stack Trace ===");

    for (int frame = 0; frame < MAX_STACK_FRAMES; frame++)
    {
        if (!StackWalk64(machineType, process, thread, &stackFrame,
            context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL))
        {
            break;
        }

        if (stackFrame.AddrPC.Offset == 0)
            break;

        DWORD64 moduleBase = SymGetModuleBase64(process, stackFrame.AddrPC.Offset);
        char moduleName[MAX_PATH] = { 0 };

        if (moduleBase)
        {
            GetModuleFileNameA((HINSTANCE)moduleBase, moduleName, MAX_PATH);
            char* lastSlash = strrchr(moduleName, '\\');
            if (lastSlash) memmove(moduleName, lastSlash + 1, strlen(lastSlash));
        }

        char symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
        PSYMBOL_INFO symbol = (PSYMBOL_INFO)symbolBuffer;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;
        std::stringstream ss;

        if (SymFromAddr(process, stackFrame.AddrPC.Offset, &displacement, symbol))
        {
            ss << "  [" << frame << "] " << moduleName << " - "
                << symbol->Name << " + 0x" << std::hex << displacement
                << " (0x" << stackFrame.AddrPC.Offset << ")";
        }
        else
        {
            ss << "  [" << frame << "] " << moduleName
                << " - 0x" << std::hex << stackFrame.AddrPC.Offset;
        }

        WriteLog(ss.str());
    }

    SymCleanup(process);
}

void WriteModuleList()
{
    WriteLog("=== Loaded Modules ===");

    HANDLE process = GetCurrentProcess();
    HMODULE modules[1024];
    DWORD needed;

    if (EnumProcessModules(process, modules, sizeof(modules), &needed))
    {
        int moduleCount = needed / sizeof(HMODULE);
        for (int i = 0; i < moduleCount; i++)
        {
            char moduleName[MAX_PATH];
            if (GetModuleFileNameA(modules[i], moduleName, sizeof(moduleName)))
            {
                MODULEINFO modInfo;
                if (GetModuleInformation(process, modules[i], &modInfo, sizeof(modInfo)))
                {
                    std::stringstream ss;
                    ss << "  " << moduleName
                        << " (Base: 0x" << std::hex << modInfo.lpBaseOfDll
                        << ", Size: 0x" << modInfo.SizeOfImage << ")";
                    WriteLog(ss.str());
                }
            }
        }
    }
}

void WriteSystemInfo()
{
    WriteLog("=== System Information ===");

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    std::stringstream ss;
    ss << "  Processor Architecture: " << sysInfo.wProcessorArchitecture;
    WriteLog(ss.str());

    ss.str(""); ss.clear();
    ss << "  Number of Processors: " << sysInfo.dwNumberOfProcessors;
    WriteLog(ss.str());

    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);

    ss.str(""); ss.clear();
    ss << "  Physical Memory: " << (memStatus.ullTotalPhys / (1024 * 1024)) << " MB";
    WriteLog(ss.str());

    ss.str(""); ss.clear();
    ss << "  Available Memory: " << (memStatus.ullAvailPhys / (1024 * 1024)) << " MB";
    WriteLog(ss.str());

    ss.str(""); ss.clear();
    ss << "  Memory Load: " << memStatus.dwMemoryLoad << "%";
    WriteLog(ss.str());
}

const char* GetExceptionString(DWORD code)
{
    switch (code)
    {
    case EXCEPTION_ACCESS_VIOLATION: return "ACCESS_VIOLATION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return "ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_BREAKPOINT: return "BREAKPOINT";
    case EXCEPTION_DATATYPE_MISALIGNMENT: return "DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND: return "FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO: return "FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT: return "FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION: return "FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW: return "FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK: return "FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW: return "FLT_UNDERFLOW";
    case EXCEPTION_ILLEGAL_INSTRUCTION: return "ILLEGAL_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR: return "IN_PAGE_ERROR";
    case EXCEPTION_INT_DIVIDE_BY_ZERO: return "INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW: return "INT_OVERFLOW";
    case EXCEPTION_INVALID_DISPOSITION: return "INVALID_DISPOSITION";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_PRIV_INSTRUCTION: return "PRIV_INSTRUCTION";
    case EXCEPTION_SINGLE_STEP: return "SINGLE_STEP";
    case EXCEPTION_STACK_OVERFLOW: return "STACK_OVERFLOW";
    default: return "UNKNOWN_EXCEPTION";
    }
}

DWORD FindMainThreadId()
{
    DWORD processId = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    DWORD mainThreadId = 0;
    FILETIME minCreateTime = { MAXDWORD, MAXDWORD };

    if (Thread32First(snapshot, &threadEntry))
    {
        do
        {
            if (threadEntry.th32OwnerProcessID == processId)
            {
                HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadEntry.th32ThreadID);
                if (thread)
                {
                    FILETIME createTime, exitTime, kernelTime, userTime;
                    if (GetThreadTimes(thread, &createTime, &exitTime, &kernelTime, &userTime))
                    {
                        if (CompareFileTime(&createTime, &minCreateTime) < 0)
                        {
                            minCreateTime = createTime;
                            mainThreadId = threadEntry.th32ThreadID;
                        }
                    }
                    CloseHandle(thread);
                }
            }
        } while (Thread32Next(snapshot, &threadEntry));
    }

    CloseHandle(snapshot);
    return mainThreadId;
}

void CheckForFreeze(HANDLE mainThread)
{
    DWORD suspendCount = SuspendThread(mainThread);

    if (suspendCount == (DWORD)-1)
    {
        // Thread doesn't exist anymore
        return;
    }

    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;

    if (GetThreadContext(mainThread, &context))
    {
        // Get instruction pointer
        DWORD64 instructionPointer = 0;
#if defined(_M_X64)
        instructionPointer = context.Rip;
#else
        instructionPointer = context.Eip;
#endif

        static DWORD64 lastInstructionPointer = 0;
        static int sameIPCount = 0;

        if (instructionPointer == lastInstructionPointer && instructionPointer != 0)
        {
            sameIPCount++;

            // If instruction pointer hasn't changed for multiple checks = freeze
            if (sameIPCount >= 5)  // 5 checks * 2 seconds = 10 seconds frozen
            {
                WriteLog("========================================");
                WriteLog("=== GAME FREEZE DETECTED ===");
                WriteLog("=== Overload or Infinite Loop ===");
                WriteLog("========================================");
                WriteLog("Game appears to be stuck in infinite loop or deadlock");

                std::stringstream ss;
                ss << "Instruction Pointer stuck at: 0x" << std::hex << instructionPointer;
                WriteLog(ss.str());
                WriteLog("");

                WriteSystemInfo();
                WriteLog("");
                WriteStackTrace(&context);
                WriteLog("");
                WriteLog("========================================");

                sameIPCount = 0;  // Reset to avoid spam
            }
        }
        else
        {
            lastInstructionPointer = instructionPointer;
            sameIPCount = 0;
        }
    }

    ResumeThread(mainThread);
}

void WatchdogThread()
{
    WriteLog("Watchdog thread started - monitoring for freezes");

    // Find main thread
    g_mainThreadId = FindMainThreadId();

    if (g_mainThreadId == 0)
    {
        WriteLog("Warning: Could not find main thread ID");
        return;
    }

    std::stringstream ss;
    ss << "Monitoring thread ID: " << g_mainThreadId;
    WriteLog(ss.str());

    HANDLE mainThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
        FALSE, g_mainThreadId);

    if (!mainThread)
    {
        WriteLog("Warning: Could not open main thread handle");
        return;
    }

    while (g_watchdogRunning)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(FREEZE_CHECK_INTERVAL_MS));
        CheckForFreeze(mainThread);
    }

    CloseHandle(mainThread);
    WriteLog("Watchdog thread stopped");
}

LONG WINAPI CustomExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo)
{
    WriteLog("========================================");
    WriteLog("=== GTA V CRASH DETECTED ===");
    WriteLog("========================================");

    std::stringstream ss;
    ss << "Exception Code: 0x" << std::hex << pExceptionInfo->ExceptionRecord->ExceptionCode
        << " (" << GetExceptionString(pExceptionInfo->ExceptionRecord->ExceptionCode) << ")";
    WriteLog(ss.str());

    ss.str(""); ss.clear();
    ss << "Exception Address: 0x" << std::hex << pExceptionInfo->ExceptionRecord->ExceptionAddress;
    WriteLog(ss.str());

    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
    {
        ss.str(""); ss.clear();
        if (pExceptionInfo->ExceptionRecord->ExceptionInformation[0] == 0)
            ss << "Access Violation: Read from 0x" << std::hex
            << pExceptionInfo->ExceptionRecord->ExceptionInformation[1];
        else if (pExceptionInfo->ExceptionRecord->ExceptionInformation[0] == 1)
            ss << "Access Violation: Write to 0x" << std::hex
            << pExceptionInfo->ExceptionRecord->ExceptionInformation[1];
        else
            ss << "Access Violation: DEP at 0x" << std::hex
            << pExceptionInfo->ExceptionRecord->ExceptionInformation[1];
        WriteLog(ss.str());
    }

    WriteLog("");

#if defined(_M_X64)
    ss.str(""); ss.clear();
    ss << "RAX=0x" << std::hex << std::setw(16) << std::setfill('0') << pExceptionInfo->ContextRecord->Rax;
    WriteLog(ss.str());
    ss.str(""); ss.clear();
    ss << "RBX=0x" << std::hex << std::setw(16) << std::setfill('0') << pExceptionInfo->ContextRecord->Rbx;
    WriteLog(ss.str());
    ss.str(""); ss.clear();
    ss << "RCX=0x" << std::hex << std::setw(16) << std::setfill('0') << pExceptionInfo->ContextRecord->Rcx;
    WriteLog(ss.str());
    ss.str(""); ss.clear();
    ss << "RDX=0x" << std::hex << std::setw(16) << std::setfill('0') << pExceptionInfo->ContextRecord->Rdx;
    WriteLog(ss.str());
    ss.str(""); ss.clear();
    ss << "RSI=0x" << std::hex << std::setw(16) << std::setfill('0') << pExceptionInfo->ContextRecord->Rsi;
    WriteLog(ss.str());
    ss.str(""); ss.clear();
    ss << "RDI=0x" << std::hex << std::setw(16) << std::setfill('0') << pExceptionInfo->ContextRecord->Rdi;
    WriteLog(ss.str());
    ss.str(""); ss.clear();
    ss << "RSP=0x" << std::hex << std::setw(16) << std::setfill('0') << pExceptionInfo->ContextRecord->Rsp;
    WriteLog(ss.str());
    ss.str(""); ss.clear();
    ss << "RBP=0x" << std::hex << std::setw(16) << std::setfill('0') << pExceptionInfo->ContextRecord->Rbp;
    WriteLog(ss.str());
    ss.str(""); ss.clear();
    ss << "RIP=0x" << std::hex << std::setw(16) << std::setfill('0') << pExceptionInfo->ContextRecord->Rip;
    WriteLog(ss.str());
#else
    ss.str(""); ss.clear();
    ss << "EAX=0x" << std::hex << std::setw(8) << std::setfill('0') << pExceptionInfo->ContextRecord->Eax;
    WriteLog(ss.str());
    ss.str(""); ss.clear();
    ss << "EBX=0x" << std::hex << std::setw(8) << std::setfill('0') << pExceptionInfo->ContextRecord->Ebx;
    WriteLog(ss.str());
    ss.str(""); ss.clear();
    ss << "ECX=0x" << std::hex << std::setw(8) << std::setfill('0') << pExceptionInfo->ContextRecord->Ecx;
    WriteLog(ss.str());
    ss.str(""); ss.clear();
    ss << "EDX=0x" << std::hex << std::setw(8) << std::setfill('0') << pExceptionInfo->ContextRecord->Edx;
    WriteLog(ss.str());
    ss.str(""); ss.clear();
    ss << "ESI=0x" << std::hex << std::setw(8) << std::setfill('0') << pExceptionInfo->ContextRecord->Esi;
    WriteLog(ss.str());
    ss.str(""); ss.clear();
    ss << "EDI=0x" << std::hex << std::setw(8) << std::setfill('0') << pExceptionInfo->ContextRecord->Edi;
    WriteLog(ss.str());
    ss.str(""); ss.clear();
    ss << "ESP=0x" << std::hex << std::setw(8) << std::setfill('0') << pExceptionInfo->ContextRecord->Esp;
    WriteLog(ss.str());
    ss.str(""); ss.clear();
    ss << "EBP=0x" << std::hex << std::setw(8) << std::setfill('0') << pExceptionInfo->ContextRecord->Ebp;
    WriteLog(ss.str());
    ss.str(""); ss.clear();
    ss << "EIP=0x" << std::hex << std::setw(8) << std::setfill('0') << pExceptionInfo->ContextRecord->Eip;
    WriteLog(ss.str());
#endif

    WriteLog("");
    WriteSystemInfo();
    WriteLog("");
    WriteStackTrace(pExceptionInfo->ContextRecord);
    WriteLog("");
    WriteLog("========================================");

    if (g_previousFilter != nullptr)
    {
        return g_previousFilter(pExceptionInfo);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// Exported functions
extern "C" __declspec(dllexport) void __stdcall LogMessage(const char* message)
{
    WriteLog(message);
}

extern "C" __declspec(dllexport) void __stdcall LogException(const char* exceptionMsg, const char* context)
{
    std::stringstream ss;
    ss << "Exception in [" << context << "]: " << exceptionMsg;
    WriteLog(ss.str());
}

extern "C" __declspec(dllexport) void __stdcall ClearLog()
{
    std::ofstream logfile(LOG_FILE, std::ios::trunc);
    if (logfile.is_open())
    {
        logfile << "=== GTA V Crash Logger Initialized ===" << std::endl;
        logfile.close();
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        WriteLog("=== Crash Logger DLL Loaded ===");
        g_previousFilter = SetUnhandledExceptionFilter(CustomExceptionHandler);

        // Start watchdog thread
        g_watchdogRunning.store(true);
        g_watchdogThread = std::thread(WatchdogThread);
        break;

    case DLL_PROCESS_DETACH:
        WriteLog("=== Crash Logger DLL Unloaded ===");

        // Stop watchdog thread
        g_watchdogRunning.store(false);
        if (g_watchdogThread.joinable())
        {
            g_watchdogThread.join();
        }

        if (g_previousFilter != nullptr)
        {
            SetUnhandledExceptionFilter(g_previousFilter);
        }
        break;
    }
    return TRUE;
}