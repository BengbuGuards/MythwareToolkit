// utils.cpp — 日志、异常处理、CBT钩子、随机标题
#include "globals.h"
#include "version.h"

// ── 源码字面量编码适配（Win7 兼容）──────────────────────────
// 详见 globals.h 中的说明。这里把 UTF-8 字面量转成进程 ANSI 代码页。
static UINT AnsiConvACP() {
    static const UINT acp = GetACP();
    return acp;
}

// 仅在"含非 ASCII 且 ACP 不是 UTF-8"时才需要转换
static bool NeedAnsiConv(const char* u8) {
    if (AnsiConvACP() == CP_UTF8) return false;
    for (const char* p = u8; *p; ++p)
        if ((unsigned char)*p >= 0x80) return true;
    return false;
}

static std::string Utf8ToAnsi(const char* u8) {
    UINT acp = AnsiConvACP();
    int wlen = MultiByteToWideChar(CP_UTF8, 0, u8, -1, NULL, 0);
    if (wlen <= 0) return std::string(u8);
    std::wstring w((size_t)wlen, L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, u8, -1, &w[0], wlen) <= 0) return std::string(u8);

    int alen = WideCharToMultiByte(acp, 0, w.c_str(), -1, NULL, 0, NULL, NULL);
    if (alen <= 0) return std::string(u8);
    std::string a((size_t)alen, '\0');
    if (WideCharToMultiByte(acp, 0, w.c_str(), -1, &a[0], alen, NULL, NULL) <= 0)
        return std::string(u8);
    a.resize((size_t)alen - 1);   // 去掉结尾 '\0'，交给 std::string 自己维护
    return a;
}

LPCSTR UA(const char* u8) {
    if (!u8 || !NeedAnsiConv(u8)) return u8;
    // 环形缓冲：保证同一表达式内多次调用（如 sprintf(fmt, UA(a), UA(b))）互不覆盖。
    // 返回的指针仅在本表达式内有效，需跨语句保存请改用 AS()。
    static thread_local std::string slot[16];
    static thread_local int idx = 0;
    idx = (idx + 1) & 15;
    slot[idx] = Utf8ToAnsi(u8);
    return slot[idx].c_str();
}

std::string AS(const char* u8) {
    if (!u8) return std::string();
    return NeedAnsiConv(u8) ? Utf8ToAnsi(u8) : std::string(u8);
}

// ── 日志基础：线程安全 + 大小轮转 ──────────────────────────
static const DWORD LOG_MAX_BYTES = 2u * 1024u * 1024u;   // 单文件上限 2 MB

static HANDLE           g_hLogFile = INVALID_HANDLE_VALUE;   // UI 日志（每次运行覆盖）
static HANDLE           g_hRunLog  = INVALID_HANDLE_VALUE;   // 运行日志（追加）
static char             g_runLogPath[MAX_PATH] = {};
static CRITICAL_SECTION g_logCS;
static INIT_ONCE        g_logOnce = INIT_ONCE_STATIC_INIT;

// 超过上限时把 xxx.log 改名为 xxx.log.old（只保留一份历史）
static void RotateIfLarge(const char* path) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesEx(path, GetFileExInfoStandard, &fad)) return;
    ULARGE_INTEGER sz;
    sz.LowPart  = fad.nFileSizeLow;
    sz.HighPart = fad.nFileSizeHigh;
    if (sz.QuadPart <= LOG_MAX_BYTES) return;

    char oldPath[MAX_PATH + 8];
    sprintf(oldPath, "%s.old", path);
    DeleteFile(oldPath);
    MoveFile(path, oldPath);
}

static BOOL CALLBACK InitLogOnce(PINIT_ONCE, PVOID, PVOID*) {
    InitializeCriticalSection(&g_logCS);

    char tmp[MAX_PATH];
    GetTempPath(MAX_PATH, tmp);
    sprintf(g_runLogPath, "%sMythwareToolkit_run.log", tmp);
    RotateIfLarge(g_runLogPath);

    g_hRunLog = CreateFile(g_runLogPath, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_hRunLog != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz = {};
        if (GetFileSizeEx(g_hRunLog, &sz) && sz.QuadPart == 0) {
            DWORD written;
            WriteFile(g_hRunLog, "\xEF\xBB\xBF", 3, &written, NULL);   // UTF-8 BOM
        }
    }
    return TRUE;
}

static void EnsureLogInit() {
    InitOnceExecuteOnce(&g_logOnce, InitLogOnce, NULL, NULL);
}

void InitLogFile() {
    EnsureLogInit();

    char path[MAX_PATH];
    GetTempPath(MAX_PATH, path);
    strcat(path, "MythwareToolkit.log");
    RotateIfLarge(path);
    g_hLogFile = CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    // 崩溃日志也在启动时轮转，避免长期累积
    GetTempPath(MAX_PATH, path);
    strcat(path, "MythwareToolkit_crash.log");
    RotateIfLarge(path);

    // 会话头：版本 / 架构 / PID / 系统 / ACP / 权限 / 程序路径
    OSVERSIONINFO vi = { sizeof(OSVERSIONINFO) };
    GetVersionEx(&vi);
    char exePath[MAX_PATH] = {};
    GetModuleFileName(NULL, exePath, MAX_PATH);
    const char* lvl = eLevel == RL_SYSTEM ? "SYSTEM" :
                      eLevel == RL_ADMIN  ? "ADMIN"  :
                      eLevel == RL_USER   ? "USER"   : "UNKNOWN";
    WriteRuntimeLog("START", "Session",
        "===== v%s (%d-bit) PID=%lu ACP=%u OS=%lu.%lu.%lu elevation=%s exe=%s =====",
        TOOLKIT_VERSION_STR, (int)(sizeof(PVOID) * 8), GetCurrentProcessId(),
        GetACP(), vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber,
        lvl, exePath);

    char hdr[256];
    sprintf(hdr, "===== MythwareToolkit v%s %d-bit PID=%lu =====\r\n",
            TOOLKIT_VERSION_STR, (int)(sizeof(PVOID) * 8), GetCurrentProcessId());
    LogWrite(hdr);
}

void CloseLogFile() {
    EnsureLogInit();
    EnterCriticalSection(&g_logCS);
    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(g_hLogFile);
        CloseHandle(g_hLogFile);
        g_hLogFile = INVALID_HANDLE_VALUE;
    }
    if (g_hRunLog != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(g_hRunLog);
        CloseHandle(g_hRunLog);
        g_hRunLog = INVALID_HANDLE_VALUE;
    }
    LeaveCriticalSection(&g_logCS);
}

void LogWrite(const char* text) {
    if (!text) return;
    EnsureLogInit();
    EnterCriticalSection(&g_logCS);
    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(g_hLogFile, text, (DWORD)strlen(text), &written, NULL);
    }
    LeaveCriticalSection(&g_logCS);
}

// Print / Println 的底层实现：内存缓冲与文件写入在同一次加锁内完成
void LogAppend(const char* text, bool newline) {
    if (!text) text = "";
    std::string line(FormatLogTime());
    line += text;
    if (newline) line += "\r\n";

    EnsureLogInit();
    EnterCriticalSection(&g_logCS);
    sOutPut += line;
    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(g_hLogFile, line.data(), (DWORD)line.size(), &written, NULL);
    }
    LeaveCriticalSection(&g_logCS);
}

// ── 运行时日志（追加写入 %TEMP%\MythwareToolkit_run.log）──
void WriteRuntimeLog(const char* level, const char* where, const char* fmt, ...) {
    EnsureLogInit();

    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    msg[sizeof(msg) - 1] = '\0';

    SYSTEMTIME st; GetLocalTime(&st);
    char header[192];
    sprintf(header, "[%04d-%02d-%02d %02d:%02d:%02d.%03d][%-5s][TID:%05lu] %s: ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            level, (unsigned long)GetCurrentThreadId(), where);

    std::string line(header);
    line += msg;
    line += "\r\n";

    // 单次加锁 + 单次 WriteFile，避免多线程日志互相穿插
    EnterCriticalSection(&g_logCS);
    if (g_hRunLog != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(g_hRunLog, line.data(), (DWORD)line.size(), &written, NULL);
        FlushFileBuffers(g_hRunLog);
    }
    LeaveCriticalSection(&g_logCS);
}

const char* FormatLogTime() {
    static thread_local char szBuffer[64];
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
    sprintf(s, UA("%s：%u-%s"), szDes, dwError, szError ? szError : "");
    LocalFree(HLOCAL(szError));
    size_t uSize = strlen(s);
    // uSize < 2 时（FormatMessage 失败会给出 NULL 描述）不能回退两个字节，否则越界读
    if (uSize >= 2 && *(s + uSize - 1) == '\n') *(WORD*)(s + uSize - 2) = 0;
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
    if (!text) return;
    EnsureLogInit();
    char path[MAX_PATH];
    GetTempPath(MAX_PATH, path);
    strcat(path, "MythwareToolkit_crash.log");
    EnterCriticalSection(&g_logCS);
    HANDLE hFile = CreateFile(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, text, (DWORD)strlen(text), &written, NULL);
        FlushFileBuffers(hFile);
        CloseHandle(hFile);
    }
    LeaveCriticalSection(&g_logCS);
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
#ifdef _WIN64
    sprintf(line, "Address:   0x%016llX\r\n", addr);
#else
    sprintf(line, "Address:   0x%08lX\r\n", (DWORD)addr);
#endif
    strcat(log, line);
    if (modBase != 0) {
#ifdef _WIN64
        sprintf(line, "Module:    %s+0x%llX (base=0x%llX)\r\n", modName, addr - modBase, modBase);
#else
        sprintf(line, "Module:    %s+0x%lX (base=0x%lX)\r\n",
                modName, (DWORD)(addr - modBase), (DWORD)modBase);
#endif
    } else {
        sprintf(line, "Module:    <not in any loaded module>\r\n");
    }
    strcat(log, line);
    sprintf(line, "Flags:     0x%08X (%s)\r\n", er->ExceptionFlags,
            (er->ExceptionFlags & EXCEPTION_NONCONTINUABLE) ? "NONCONTINUABLE" : "CONTINUABLE");
    strcat(log, line);

    // ── 访问违例详情 ──
    if (code == EXCEPTION_ACCESS_VIOLATION) {
#ifdef _WIN64
        sprintf(line, "Access:    %s at 0x%016llX\r\n",
                er->ExceptionInformation[0] == 0 ? "READ" :
                er->ExceptionInformation[0] == 1 ? "WRITE" : "EXECUTE",
                (DWORD64)er->ExceptionInformation[1]);
#else
        sprintf(line, "Access:    %s at 0x%08lX\r\n",
                er->ExceptionInformation[0] == 0 ? "READ" :
                er->ExceptionInformation[0] == 1 ? "WRITE" : "EXECUTE",
                (DWORD)er->ExceptionInformation[1]);
#endif
        strcat(log, line);
    }

    // ── 寄存器 ──
    CONTEXT* ctx = exceptionInfo->ContextRecord;
    sprintf(line, "\r\nRegisters:\r\n");
    strcat(log, line);
#ifdef _WIN64
    sprintf(line, "  RIP=0x%016llX RSP=0x%016llX RBP=0x%016llX\r\n", ctx->Rip, ctx->Rsp, ctx->Rbp);
    strcat(log, line);
    sprintf(line, "  RAX=0x%016llX RBX=0x%016llX RCX=0x%016llX RDX=0x%016llX\r\n", ctx->Rax, ctx->Rbx, ctx->Rcx, ctx->Rdx);
    strcat(log, line);
    sprintf(line, "  RSI=0x%016llX RDI=0x%016llX R8=0x%016llX R9=0x%016llX\r\n", ctx->Rsi, ctx->Rdi, ctx->R8, ctx->R9);
    strcat(log, line);
#else
    sprintf(line, "  EIP=0x%08lX ESP=0x%08lX EBP=0x%08lX\r\n",
            (DWORD)ctx->Eip, (DWORD)ctx->Esp, (DWORD)ctx->Ebp);
    strcat(log, line);
    sprintf(line, "  EAX=0x%08lX EBX=0x%08lX ECX=0x%08lX EDX=0x%08lX\r\n",
            (DWORD)ctx->Eax, (DWORD)ctx->Ebx, (DWORD)ctx->Ecx, (DWORD)ctx->Edx);
    strcat(log, line);
    sprintf(line, "  ESI=0x%08lX EDI=0x%08lX\r\n",
            (DWORD)ctx->Esi, (DWORD)ctx->Edi);
    strcat(log, line);
#endif

    // ── 栈回溯（帧指针链）──
#ifdef _WIN64
    sprintf(line, "\r\nStack trace (RBP chain):\r\n");
#else
    sprintf(line, "\r\nStack trace (EBP chain):\r\n");
#endif
    strcat(log, line);
#ifdef _WIN64
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
        sprintf(line, UA("  [%2d] RBP=0x%016llX → 0x%016llX [%s+0x%llX]\r\n"), i, rbp, retAddr, fname, retAddr - fbase);
        strcat(log, line);
        if (nextRbp == 0 || nextRbp <= rbp) break;
        rbp = nextRbp;
    }
#else
    DWORD ebp = (DWORD)ctx->Ebp;
    for (int i = 0; i < 20 && ebp; i++) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((LPCVOID)(DWORD_PTR)ebp, &mbi, sizeof(mbi))) break;
        if (mbi.State != MEM_COMMIT) break;
        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) break;
        DWORD retAddr  = *(DWORD*)(DWORD_PTR)(ebp + 4);
        DWORD nextEbp  = *(DWORD*)(DWORD_PTR)ebp;
        if (retAddr == 0) break;
        DWORD64 fbase;
        const char* fname = GetModuleName((DWORD64)retAddr, &fbase);
        sprintf(line, UA("  [%2d] EBP=0x%08lX → 0x%08lX [%s+0x%lX]\r\n"),
                i, ebp, retAddr, fname, (DWORD)((DWORD64)retAddr - fbase));
        strcat(log, line);
        if (nextEbp == 0 || nextEbp <= ebp) break;
        ebp = nextEbp;
    }
#endif

    strcat(log, "=========================================\r\n");
    WriteCrashLog(log);

    // ── 弹窗 ──
    char message[BUFSIZ * 2] = {};
#ifdef _WIN64
    sprintf(message, UA("异常代码：0x%08X (%s)，位于内存地址：0x%llX [%s+0x%llX]\n%s\n\n崩溃日志已写入 %%TEMP%%\\MythwareToolkit_crash.log"),
        code, ExceptionCodeName(code),
        addr, modName, addr - modBase,
        UA((er->ExceptionFlags & EXCEPTION_NONCONTINUABLE) ? "该错误不可继续执行" : "该错误可尝试继续执行"));
#else
    sprintf(message, UA("异常代码：0x%08X (%s)，位于内存地址：0x%X [%s+0x%X]\n%s\n\n崩溃日志已写入 %%TEMP%%\\MythwareToolkit_crash.log"),
        code, ExceptionCodeName(code),
        (DWORD)addr, modName, (DWORD)(addr - modBase),
        UA((er->ExceptionFlags & EXCEPTION_NONCONTINUABLE) ? "该错误不可继续执行" : "该错误可尝试继续执行"));
#endif
    HHOOK hCBTHook = SetWindowsHookEx(WH_CBT, CBTProc, NULL, GetCurrentThreadId());
    int id = MessageBox(NULL, message, UA("程序运行异常"), MB_ICONERROR | MB_YESNO | MB_DEFBUTTON2);
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

// ── 防教师端截屏 ──
// WDA_EXCLUDEFROMCAPTURE 需要 Win10 2004+，在 Win7/旧版上调用会失败；
// 此时回退到 WDA_MONITOR（Win7 起可用，效果是截图里窗口区域全黑）。
void ApplyAntiCapture(HWND hWnd) {
    if (!hWnd || !IsWindow(hWnd)) return;
    if (!SetWindowDisplayAffinity(hWnd, WDA_EXCLUDEFROMCAPTURE))
        SetWindowDisplayAffinity(hWnd, WDA_MONITOR);
}

static HHOOK g_hPermCBT = NULL;

// 把弹窗贴到屏幕左上角或右上角（MessageBox 默认居中）
static void PlaceDialogAtCorner(HWND hDlg, bool bRight) {
    RECT rc;
    if (!GetWindowRect(hDlg, &rc)) return;
    int x = bRight ? GetSystemMetrics(SM_CXSCREEN) - (rc.right - rc.left) : 0;
    SetWindowPos(hDlg, HWND_TOPMOST, x, 0, 0, 0, SWP_NOSIZE | SWP_NOACTIVATE);
}

// 按 ids 给定的顺序，把按钮从左到右重排到现有按钮槽位上。
// 固定“取排序后的 x 槽位再分配”，因此重复调用结果不变——
// 多个 CBT 钩子同时存在时，本函数会被调用多次，必须幂等。
static void ArrangeButtons(HWND hDlg, const int* ids, int count) {
    HWND  hBtn[3];
    POINT pos[3];
    int   n = 0;
    for (int i = 0; i < count && n < 3; ++i) {
        HWND h = GetDlgItem(hDlg, ids[i]);
        if (!h) continue;
        RECT r; GetWindowRect(h, &r);
        POINT p = { r.left, r.top };
        ScreenToClient(hDlg, &p);
        hBtn[n] = h; pos[n] = p; ++n;
    }
    if (n == 0) return;

    int xs[3], y = pos[0].y;
    for (int i = 0; i < n; ++i) xs[i] = pos[i].x;
    for (int i = 0; i < n; ++i)
        for (int j = i + 1; j < n; ++j)
            if (xs[j] < xs[i]) { int t = xs[i]; xs[i] = xs[j]; xs[j] = t; }

    for (int i = 0; i < n; ++i)
        SetWindowPos(hBtn[i], NULL, xs[i], y, 0, 0,
                     SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

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
            // 鼠标检测弹窗：
            if (_stricmp(szName, UA("实时提醒（最小化）")) == 0) {
                // 用 MB_OKCANCEL 而不是 MB_YESNO：有 Cancel 按钮时右上角 × 才真正生效
                //（MB_YESNO 的 MessageBox 内部会忽略 WM_CLOSE）。× 与「取消」等价。
                SetDlgItemText(msgHwnd, IDOK,     UA("最小化"));
                SetDlgItemText(msgHwnd, IDCANCEL, UA("取消"));
                // 左上角触发 → 弹窗贴左上角，按钮顺序：最小化、取消
                PlaceDialogAtCorner(msgHwnd, false);
            } else if (_stricmp(szName, UA("实时提醒（关闭）")) == 0) {
                SetDlgItemText(msgHwnd, IDYES, UA("关闭"));
                SetDlgItemText(msgHwnd, IDNO,  UA("强制关闭"));
                SetDlgItemText(msgHwnd, IDCANCEL, UA("取消"));
                // 右上角触发 → 弹窗贴右上角；
                // 按钮左→右：关闭、取消、强制关闭（最右侧为“强制关闭”）
                static const int orderClose[] = { IDYES, IDCANCEL, IDNO };
                ArrangeButtons(msgHwnd, orderClose, 3);
                PlaceDialogAtCorner(msgHwnd, true);
                HMENU msgMenu = GetSystemMenu(msgHwnd, FALSE);
                EnableMenuItem(msgMenu, SC_CLOSE, MF_ENABLED);
            } else if (_stricmp(szName, "USB Setting") == 0) {
                SetDlgItemText(msgHwnd, IDYES, UA("软解禁"));
                SetDlgItemText(msgHwnd, IDNO, UA("硬解禁"));
            } else if (_stricmp(szName, UA("程序运行异常")) == 0) {
                SetDlgItemText(msgHwnd, IDYES, UA("终止程序"));
                SetDlgItemText(msgHwnd, IDNO, UA("继续"));
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
