#include "globals.h"
#include <aclapi.h>

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

// ── 防杀进程：通过 ACL 拒绝 PROCESS_TERMINATE ──
static bool g_bProcessProtected = false;

bool ToggleProcessProtection() {
    HANDLE hProcess = GetCurrentProcess();
    PACL pOldDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

    if (!g_bProcessProtected) {
        // ── 启用保护 ──
        // 获取当前进程的安全描述符
        DWORD err1 = GetSecurityInfo(hProcess, SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION, NULL, NULL,
            &pOldDACL, NULL, &pSD);
        if (err1 != ERROR_SUCCESS) {
            LOG_ERROR("GetSecurityInfo failed: %lu", err1);
            return false;
        }

        // 添加 DENY ACE：禁止 Everyone 终止本进程
        EXPLICIT_ACCESSA ea = {};
        ea.grfAccessPermissions = PROCESS_TERMINATE;
        ea.grfAccessMode = DENY_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;

        SID_IDENTIFIER_AUTHORITY sia = SECURITY_WORLD_SID_AUTHORITY;
        PSID pEveryone = NULL;
        AllocateAndInitializeSid(&sia, 1, SECURITY_WORLD_RID, 0,0,0,0,0,0,0, &pEveryone);
        ea.Trustee.ptstrName = (LPSTR)pEveryone;

        PACL pNewDACL = NULL;
        DWORD err2 = SetEntriesInAclA(1, &ea, pOldDACL, &pNewDACL);
        FreeSid(pEveryone);
        LocalFree(pSD);
        if (err2 != ERROR_SUCCESS) {
            LOG_ERROR("SetEntriesInAcl failed: %lu", err2);
            return false;
        }

        DWORD err3 = SetSecurityInfo(hProcess, SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL);
        LocalFree(pNewDACL);
        if (err3 != ERROR_SUCCESS) {
            LOG_ERROR("SetSecurityInfo(DENY) failed: %lu", err3);
            return false;
        }

        g_bProcessProtected = true;
        LOG_INFO("Process protection ON: PROCESS_TERMINATE denied");
        return true;

    } else {
        // ── 关闭保护 ──
        PSID pEveryone = NULL;
        SID_IDENTIFIER_AUTHORITY sia = SECURITY_WORLD_SID_AUTHORITY;
        AllocateAndInitializeSid(&sia, 1, SECURITY_WORLD_RID, 0,0,0,0,0,0,0, &pEveryone);

        EXPLICIT_ACCESSA ea2 = {};
        ea2.grfAccessPermissions = PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION |
                                   SYNCHRONIZE | READ_CONTROL;
        ea2.grfAccessMode = SET_ACCESS;
        ea2.grfInheritance = NO_INHERITANCE;
        ea2.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea2.Trustee.ptstrName = (LPSTR)pEveryone;

        PACL pNewDACL = NULL;
        DWORD err2 = SetEntriesInAclA(1, &ea2, NULL, &pNewDACL);
        FreeSid(pEveryone);
        if (err2 != ERROR_SUCCESS) {
            LOG_ERROR("SetEntriesInAcl(restore) failed: %lu", err2);
            return false;
        }

        err2 = SetSecurityInfo(hProcess, SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL);
        LocalFree(pNewDACL);
        if (err2 != ERROR_SUCCESS) {
            LOG_ERROR("SetSecurityInfo(ALLOW) failed: %lu", err2);
            return false;
        }

        g_bProcessProtected = false;
        LOG_INFO("Process protection OFF");
        return true;
    }
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
