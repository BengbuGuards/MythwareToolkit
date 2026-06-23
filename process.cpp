#include "globals.h"

static NTSTATUS (NTAPI *MyNtQuerySystemInformation)
    (IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation,
     IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);
static DWORD (NTAPI *RtlNtStatusToDosErrorNoTeb)(NTSTATUS Status);

typedef struct _MYSYSTEM_PROCESS_INFORMATION : SYSTEM_PROCESS_INFORMATION {
    SYSTEM_THREAD_INFORMATION Threads[0];
} MYSYSTEM_PROCESS_INFORMATION, *PMYSYSTEM_PROCESS_INFORMATION;

#define SYSTEM_PROCESS_INFORMATION MYSYSTEM_PROCESS_INFORMATION
#define PSYSTEM_PROCESS_INFORMATION PMYSYSTEM_PROCESS_INFORMATION

void InitNTAPI() {
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    Set(NtSuspendProcess,           GetProcAddress(ntdll, "NtSuspendProcess"));
    Set(NtResumeProcess,            GetProcAddress(ntdll, "NtResumeProcess"));
    Set(MyNtQuerySystemInformation, GetProcAddress(ntdll, "NtQuerySystemInformation"));
    Set(RtlNtStatusToDosErrorNoTeb, GetProcAddress(ntdll, "RtlNtStatusToDosErrorNoTeb"));
}

DWORD GetProcessIDFromName(LPCSTR szName) {
    DWORD id = 0;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (0 == _stricmp(pe.szExeFile, szName)) {
                id = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return id;
}

bool KillProcess(DWORD dwProcessID, int way) {
    if (way == KILL_FORCE) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessID);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            bool rtn = true;
            THREADENTRY32 te = {sizeof(te)};
            BOOL fOk = Thread32First(hSnapshot, &te);
            for (; fOk; fOk = Thread32Next(hSnapshot, &te)) {
                if (te.th32OwnerProcessID == dwProcessID) {
                    HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, te.th32ThreadID);
                    if (!TerminateThread(hThread, 0)) rtn = false;
                    CloseHandle(hThread);
                }
            }
            CloseHandle(hSnapshot);
            return rtn;
        }
        return false;
    } else if (way == KILL_DEFAULT) {
        HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessID);
        WINBOOL sta = TerminateProcess(handle, 0);
        CloseHandle(handle);
        return sta;
    }
    return false;
}

bool KillAllProcessWithName(LPCSTR name, int way) {
    PROCESSENTRY32 pe; bool s = false;
    pe.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (!_stricmp(pe.szExeFile, name))
                s = KillProcess(pe.th32ProcessID, way);
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return s;
}

BOOL SuspendProcess(DWORD dwProcessID, BOOL suspend) {
    HANDLE handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, dwProcessID);
    if (suspend) return NtSuspendProcess(handle) == 0;
    else         return NtResumeProcess(handle) == 0;
}

int GetProcessState(DWORD dwProcessID) {
    int nStatus = -1;
    DWORD dwSize;
    MyNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &dwSize);
    HGLOBAL hBuffer = GlobalAlloc(LPTR, dwSize);
    if (hBuffer == NULL) return nStatus;

    PSYSTEM_PROCESS_INFORMATION pInfo = PSYSTEM_PROCESS_INFORMATION(hBuffer);
    NTSTATUS lStatus = MyNtQuerySystemInformation(SystemProcessInformation, pInfo, dwSize, 0);
    if (!NT_SUCCESS(lStatus)) {
        GlobalFree(hBuffer);
        error = RtlNtStatusToDosErrorNoTeb(lStatus);
        return nStatus;
    }
    while (true) {
        if (((DWORD)(ULONG_PTR)pInfo->UniqueProcessId) == dwProcessID) {
            nStatus = 1;
            for (ULONG i = 0; i < pInfo->NumberOfThreads; i++) {
                if (pInfo->Threads[i].WaitReason != Suspended) {
                    nStatus = 0;
                    break;
                }
            }
            break;
        }
        if (pInfo->NextEntryOffset == 0) break;
        pInfo = PSYSTEM_PROCESS_INFORMATION(PBYTE(pInfo) + pInfo->NextEntryOffset);
    }
    GlobalFree(hBuffer);
    return nStatus;
}
