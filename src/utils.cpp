#include "globals.h"

static HANDLE g_hLogFile = INVALID_HANDLE_VALUE;

void InitLogFile() {
    char path[MAX_PATH];
    GetTempPath(MAX_PATH, path);
    strcat(path, "MythwareToolkit.log");
    g_hLogFile = CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

void CloseLogFile() {
    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(g_hLogFile);
        CloseHandle(g_hLogFile);
        g_hLogFile = INVALID_HANDLE_VALUE;
    }
}

void LogWrite(const char* text) {
    if (g_hLogFile != INVALID_HANDLE_VALUE && text) {
        DWORD written;
        WriteFile(g_hLogFile, text, strlen(text), &written, NULL);
    }
}

// ── 运行时日志（追加模式，写入 %TEMP%\MythwareToolkit_run.log）──
void WriteRuntimeLog(const char* level, const char* where, const char* fmt, ...) {
    char path[MAX_PATH];
    GetTempPath(MAX_PATH, path);
    strcat(path, "MythwareToolkit_run.log");
    HANDLE hFile = CreateFile(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    // 时间戳 + 级别 + 位置
    SYSTEMTIME st; GetLocalTime(&st);
    char header[128];
    sprintf(header, "[%02d:%02d:%02d.%03d] %-5s %s: ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            level, where);
    DWORD written;
    WriteFile(hFile, header, strlen(header), &written, NULL);

    // 格式化消息
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    WriteFile(hFile, msg, strlen(msg), &written, NULL);
    WriteFile(hFile, "\r\n", 2, &written, NULL);

    FlushFileBuffers(hFile);
    CloseHandle(hFile);
}

const char* FormatLogTime() {
    static char szBuffer[64];
    SYSTEMTIME  time;
    GetLocalTime(&time);
    sprintf(szBuffer, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
        time.wYear, time.wMonth, time.wDay,
        time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
    return szBuffer;
}

void PrtError(LPCSTR szDes, LRESULT lResult) {
    DWORD  dwError = lResult == 0 ? GetLastError() : lResult & 0xFFFF;
    LPSTR  szError = NULL;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
                  NULL, dwError, 0, (PTSTR)&szError, 0, NULL);
    char s[BUFSIZ] = {};
    sprintf(s, "%s：%u-%s", szDes, dwError, szError);
    LocalFree(HLOCAL(szError));
    size_t uSize = strlen(s);
    if (*(s + uSize - 1) == '\n') *(WORD*)(s + uSize - 2) = 0;
    Println(s);
}

const char* RandomWindowTitle() {
    static char title[11];
    std::srand((unsigned)time(NULL));
    memset(title, 0, 11);
    for (int i = 0; i < 10; i++) {
        int u = std::rand(), c = u % 31;
        if (c < 5)       title[i] = u % 10 + '0';
        else if (c < 18) title[i] = u % 26 + 'a';
        else             title[i] = u % 26 + 'A';
    }
    return title;
}

BOOL EnableDebugPrivilege() {
    HANDLE           hToken;
    LUID             Luid;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = Luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

// 获取异常代码的可读名称
static const char* ExceptionCodeName(DWORD code) {
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:         return "ACCESS_VIOLATION";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "ARRAY_BOUNDS_EXCEEDED";
        case EXCEPTION_BREAKPOINT:               return "BREAKPOINT";
        case EXCEPTION_DATATYPE_MISALIGNMENT:    return "DATATYPE_MISALIGNMENT";
        case EXCEPTION_FLT_DENORMAL_OPERAND:     return "FLT_DENORMAL_OPERAND";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "FLT_DIVIDE_BY_ZERO";
        case EXCEPTION_FLT_INEXACT_RESULT:       return "FLT_INEXACT_RESULT";
        case EXCEPTION_FLT_INVALID_OPERATION:    return "FLT_INVALID_OPERATION";
        case EXCEPTION_FLT_OVERFLOW:             return "FLT_OVERFLOW";
        case EXCEPTION_FLT_STACK_CHECK:          return "FLT_STACK_CHECK";
        case EXCEPTION_FLT_UNDERFLOW:            return "FLT_UNDERFLOW";
        case EXCEPTION_ILLEGAL_INSTRUCTION:      return "ILLEGAL_INSTRUCTION";
        case EXCEPTION_IN_PAGE_ERROR:            return "IN_PAGE_ERROR";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "INT_DIVIDE_BY_ZERO";
        case EXCEPTION_INT_OVERFLOW:             return "INT_OVERFLOW";
        case EXCEPTION_INVALID_DISPOSITION:      return "INVALID_DISPOSITION";
        case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "NONCONTINUABLE_EXCEPTION";
        case EXCEPTION_PRIV_INSTRUCTION:         return "PRIV_INSTRUCTION";
        case EXCEPTION_SINGLE_STEP:              return "SINGLE_STEP";
        case EXCEPTION_STACK_OVERFLOW:           return "STACK_OVERFLOW";
        default:                                 return "UNKNOWN";
    }
}

// 写崩溃日志到 %TEMP%\MythwareToolkit_crash.log
static void WriteCrashLog(const char* text) {
    char path[MAX_PATH];
    GetTempPath(MAX_PATH, path);
    strcat(path, "MythwareToolkit_crash.log");
    HANDLE hFile = CreateFile(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        SetFilePointer(hFile, 0, NULL, FILE_END);
        WriteFile(hFile, text, strlen(text), &written, NULL);
        CloseHandle(hFile);
    }
}

// 获取地址所在模块名
static const char* GetModuleName(DWORD64 addr, DWORD64* base) {
    static char buf[MAX_PATH];
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)(DWORD_PTR)addr, &mbi, sizeof(mbi))) {
        if (GetModuleFileName((HMODULE)mbi.AllocationBase, buf, MAX_PATH)) {
            if (base) *base = (DWORD64)(DWORD_PTR)mbi.AllocationBase;
            char* p = strrchr(buf, '\\');
            return p ? p + 1 : buf;
        }
    }
    if (base) *base = 0;
    return "???";
}

LONG WINAPI GlobalExceptionHandler(EXCEPTION_POINTERS* exceptionInfo) {
    // 同时在运行日志中记录
    EXCEPTION_RECORD* er = exceptionInfo->ExceptionRecord;
    WriteRuntimeLog("CRASH", "ExceptionHandler", "code=0x%08X addr=0x%p",
                    er->ExceptionCode, er->ExceptionAddress);

    char log[8192];
    char line[512];
    SYSTEMTIME st;
    GetLocalTime(&st);

    // ── 时间戳 ──
    sprintf(log, "\r\n========== CRASH [%04d-%02d-%02d %02d:%02d:%02d.%03d] ==========\r\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    DWORD code = er->ExceptionCode;
    DWORD64 addr = (DWORD64)er->ExceptionAddress;
    DWORD64 modBase;
    const char* modName = GetModuleName(addr, &modBase);

    sprintf(line, "Exception: 0x%08X (%s)\r\n", code, ExceptionCodeName(code));
    strcat(log, line);
    sprintf(line, "Address:   0x%016llX\r\n", addr);
    strcat(log, line);
    if (modBase != 0) {
        sprintf(line, "Module:    %s+0x%llX (base=0x%llX)\r\n", modName, addr - modBase, modBase);
    } else {
        sprintf(line, "Module:    <not in any loaded module>\r\n");
    }
    strcat(log, line);
    sprintf(line, "Flags:     0x%08X (%s)\r\n", er->ExceptionFlags,
            (er->ExceptionFlags & EXCEPTION_NONCONTINUABLE) ? "NONCONTINUABLE" : "CONTINUABLE");
    strcat(log, line);

    // ── 访问违例详情 ──
    if (code == EXCEPTION_ACCESS_VIOLATION) {
        sprintf(line, "Access:    %s at 0x%016llX\r\n",
                er->ExceptionInformation[0] == 0 ? "READ" :
                er->ExceptionInformation[0] == 1 ? "WRITE" : "EXECUTE",
                (DWORD64)er->ExceptionInformation[1]);
        strcat(log, line);
    }

    // ── 寄存器 ──
    CONTEXT* ctx = exceptionInfo->ContextRecord;
    sprintf(line, "\r\nRegisters:\r\n");
    strcat(log, line);
    sprintf(line, "  RIP=0x%016llX RSP=0x%016llX RBP=0x%016llX\r\n", ctx->Rip, ctx->Rsp, ctx->Rbp);
    strcat(log, line);
    sprintf(line, "  RAX=0x%016llX RBX=0x%016llX RCX=0x%016llX RDX=0x%016llX\r\n", ctx->Rax, ctx->Rbx, ctx->Rcx, ctx->Rdx);
    strcat(log, line);
    sprintf(line, "  RSI=0x%016llX RDI=0x%016llX R8=0x%016llX R9=0x%016llX\r\n", ctx->Rsi, ctx->Rdi, ctx->R8, ctx->R9);
    strcat(log, line);

    // ── 栈回溯（RBP 链）──
    sprintf(line, "\r\nStack trace (RBP chain):\r\n");
    strcat(log, line);
    DWORD64 rbp = ctx->Rbp;
    for (int i = 0; i < 20 && rbp; i++) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((LPCVOID)(DWORD_PTR)rbp, &mbi, sizeof(mbi))) break;
        if (mbi.State != MEM_COMMIT) break;
        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) break;
        DWORD64 retAddr = *(DWORD64*)(rbp + 8);
        DWORD64 nextRbp = *(DWORD64*)(rbp);
        if (retAddr == 0) break;
        DWORD64 fbase;
        const char* fname = GetModuleName(retAddr, &fbase);
        sprintf(line, "  [%2d] RBP=0x%016llX → 0x%016llX [%s+0x%llX]\r\n", i, rbp, retAddr, fname, retAddr - fbase);
        strcat(log, line);
        if (nextRbp == 0 || nextRbp <= rbp) break;
        rbp = nextRbp;
    }

    strcat(log, "=========================================\r\n");
    WriteCrashLog(log);

    // ── 弹窗 ──
    char message[BUFSIZ * 2] = {};
    sprintf(message, "异常代码：0x%08X (%s)，位于内存地址：0x%X [%s+0x%X]\n%s\n\n崩溃日志已写入 %%TEMP%%\\MythwareToolkit_crash.log",
        code, ExceptionCodeName(code),
        addr, modName, addr - modBase,
        (er->ExceptionFlags & EXCEPTION_NONCONTINUABLE) ? "该错误不可继续执行" : "该错误可尝试继续执行");
    HHOOK hCBTHook = SetWindowsHookEx(WH_CBT, CBTProc, NULL, GetCurrentThreadId());
    int id = MessageBox(NULL, message, "程序运行异常", MB_ICONERROR | MB_YESNO | MB_DEFBUTTON2);
    UnhookWindowsHookEx(hCBTHook);
    if (id == IDYES) {
        return EXCEPTION_CONTINUE_SEARCH;
    } else if (id == IDNO) {
        return (er->ExceptionFlags & EXCEPTION_NONCONTINUABLE) ?
               EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

BOOL CALLBACK SetWindowFont(HWND hwndChild, LPARAM lParam) {
    SendMessage(hwndChild, WM_SETFONT, WPARAM(lParam), 0);
    return TRUE;
}

static HHOOK g_hPermCBT = NULL;

// 永久 CBT 钩子：保护所有对话框不被教师端截屏看到
LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HCBT_ACTIVATE) {
        HWND msgHwnd = HWND(wParam);
        char  szClass[8];
        GetClassName(msgHwnd, szClass, 8);
        if (_stricmp("#32770", szClass) == 0) {
            // 所有对话框对教师端监控不可见
            SetWindowDisplayAffinity(msgHwnd, WDA_EXCLUDEFROMCAPTURE);

            int  nLength = GetWindowTextLength(msgHwnd);
            char szName[nLength + 2];
            GetWindowText(msgHwnd, szName, nLength + 1);
            if (_stricmp(szName, "实时提醒") == 0) {
                SetDlgItemText(msgHwnd, IDYES, "关闭");
                SetDlgItemText(msgHwnd, IDNO, "强制关闭");
                SetDlgItemText(msgHwnd, IDCANCEL, "取消");
                HMENU msgMenu = GetSystemMenu(msgHwnd, FALSE);
                EnableMenuItem(msgMenu, SC_CLOSE, MF_GRAYED);
            } else if (_stricmp(szName, "USB Setting") == 0) {
                SetDlgItemText(msgHwnd, IDYES, "软解禁");
                SetDlgItemText(msgHwnd, IDNO, "硬解禁");
            } else if (_stricmp(szName, "程序运行异常") == 0) {
                SetDlgItemText(msgHwnd, IDYES, "终止程序");
                SetDlgItemText(msgHwnd, IDNO, "继续");
            }
        }
    }
    return CallNextHookEx(g_hPermCBT, nCode, wParam, lParam);
}

void InstallDialogProtection() {
    if (!g_hPermCBT)
        g_hPermCBT = SetWindowsHookEx(WH_CBT, CBTProc, NULL, GetCurrentThreadId());
}

void UninstallDialogProtection() {
    if (g_hPermCBT) {
        UnhookWindowsHookEx(g_hPermCBT);
        g_hPermCBT = NULL;
    }
}
