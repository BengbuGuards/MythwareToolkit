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

LONG WINAPI GlobalExceptionHandler(EXCEPTION_POINTERS* exceptionInfo) {
    char message[BUFSIZ * 2] = {};
    sprintf(message, "异常代码：0x%08X，位于内存地址：0x%X\n该%s，程序将可能失去窗口，请联系开发者",
        exceptionInfo->ExceptionRecord->ExceptionCode,
        exceptionInfo->ExceptionRecord->ExceptionAddress,
        ((exceptionInfo->ExceptionRecord->ExceptionFlags) & EXCEPTION_NONCONTINUABLE) ? "错误不可继续执行" : "错误可尝试继续执行");
    HHOOK hCBTHook = SetWindowsHookEx(WH_CBT, CBTProc, NULL, GetCurrentThreadId());
    int id = MessageBox(NULL, message, "程序运行异常", MB_ICONERROR | MB_YESNO | MB_DEFBUTTON2);
    UnhookWindowsHookEx(hCBTHook);
    if (id == IDYES) {
        return EXCEPTION_CONTINUE_SEARCH;
    } else if (id == IDNO) {
        return ((exceptionInfo->ExceptionRecord->ExceptionFlags) & EXCEPTION_NONCONTINUABLE) ?
               EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

BOOL CALLBACK SetWindowFont(HWND hwndChild, LPARAM lParam) {
    SendMessage(hwndChild, WM_SETFONT, WPARAM(lParam), 0);
    return TRUE;
}

LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HCBT_ACTIVATE) {
        HWND msgHwnd = HWND(wParam);
        char  szClass[7];
        GetClassName(msgHwnd, szClass, 7);
        if (_stricmp("#32770", szClass) == 0) {
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
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}
