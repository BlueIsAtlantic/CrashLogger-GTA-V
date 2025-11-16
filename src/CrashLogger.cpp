#include <windows.h>
#include <fstream>
#include <string>
#include <ctime>
#include <sstream>
#include <iomanip>

#define LOG_FILE "CrashLogger_Log.txt"

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
}

LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo)
{
    std::stringstream ss;
    ss << "Crash Handler caught the crash! Code: 0x"
        << std::hex << pExceptionInfo->ExceptionRecord->ExceptionCode
        << " at address: 0x"
        << pExceptionInfo->ExceptionRecord->ExceptionAddress;

    WriteLog(ss.str());

#if defined(_M_X64)
    ss.str(""); ss.clear();
    ss << "Registers: "
        << "RAX=0x" << std::hex << pExceptionInfo->ContextRecord->Rax
        << ", RBX=0x" << pExceptionInfo->ContextRecord->Rbx
        << ", RCX=0x" << pExceptionInfo->ContextRecord->Rcx
        << ", RDX=0x" << pExceptionInfo->ContextRecord->Rdx
        << ", RSI=0x" << pExceptionInfo->ContextRecord->Rsi
        << ", RDI=0x" << pExceptionInfo->ContextRecord->Rdi
        << ", RSP=0x" << pExceptionInfo->ContextRecord->Rsp
        << ", RIP=0x" << pExceptionInfo->ContextRecord->Rip;
    WriteLog(ss.str());
#else
    ss.str(""); ss.clear();
    ss << "Registers: "
        << "EAX=0x" << std::hex << pExceptionInfo->ContextRecord->Eax
        << ", EBX=0x" << pExceptionInfo->ContextRecord->Ebx
        << ", ECX=0x" << pExceptionInfo->ContextRecord->Ecx
        << ", EDX=0x" << pExceptionInfo->ContextRecord->Edx
        << ", ESI=0x" << pExceptionInfo->ContextRecord->Esi
        << ", EDI=0x" << pExceptionInfo->ContextRecord->Edi
        << ", ESP=0x" << pExceptionInfo->ContextRecord->Esp
        << ", EIP=0x" << pExceptionInfo->ContextRecord->Eip;
    WriteLog(ss.str());
#endif

    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        SetUnhandledExceptionFilter(ExceptionHandler);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
