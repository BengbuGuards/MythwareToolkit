// globals.h — 全局宏定义、变量声明、函数原型
#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <fltuser.h>
#include <userenv.h>
#include <commctrl.h>
#include <versionhelpers.h>
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <cmath>

// ── 宏 ──────────────────────────────────────────────────────
#define KILL_FORCE   1
#define KILL_DEFAULT 2
#define Set(dest, source) *(PVOID*)&(dest) = (PVOID)(source)

// 日志宏（同时写入内存和文件；LogAppend 内部保证线程安全与单次写入）
#define Print(text)   LogAppend((text), false)
#define Println(text) LogAppend((text), true)
#define ge            error = GetLastError()

// ── 运行权限级别 ────────────────────────────────────────────
enum RunLevel { RL_UNKNOWN, RL_USER, RL_ADMIN, RL_SYSTEM };

// ── 极域窗口信息 ────────────────────────────────────────────
struct MW_INFO {
    HWND  hwndOfBoardcast;
    DWORD pid;
    bool  bNotResponding;
};

// ── VB 随机数模拟 ───────────────────────────────────────────
struct VBRandomEngine {
    int m_rndSeed = 327680;

    void Randomize(double Number) {
        int num = m_rndSeed, num2;
        unsigned char bytes[sizeof(double)];
        memcpy(bytes, &Number, sizeof(double));
        memcpy(&num2, bytes + 4, sizeof(int));
        num2 = ((num2 & 65535) ^ (num2 >> 16)) << 8;
        num = (num & -16776961) | num2;
        m_rndSeed = num;
    }

    float Rnd() { return Rnd(1.f); }

    float Rnd(float Number) {
        int num = m_rndSeed;
        if ((double)Number != 0.0) {
            if ((double)Number < 0.0) {
                num = *(int*)(&Number);
                long long num2 = (long long)num & (long long)((unsigned long long)(-1));
                num = (int)((num2 + (num2 >> 24)) & 16777215L);
            }
            num = (int)(((long long)num * 1140671485L + 12820163L) & 16777215L);
        }
        m_rndSeed = num;
        return (float)num / 16777216.f;
    }
};

// ── 全局变量 extern 声明 ────────────────────────────────────
extern std::string sOutPut;
extern HHOOK        kbdHook, mseHook;
extern HWND         hwnd, focus, hBdCst;
extern HWND         BtAbt, BtKmw, TxOut, TxLnk, BtTop, BtCur, BtKbh, BtSnp, BtWnd;
extern NOTIFYICONDATA icon;
extern HMENU        hMenu;
extern HFONT        hFont;
extern int          width, height, w, h, mwSts;
extern bool         asking, ask, closingProcess;
extern DWORD        error;
extern POINT        p, pt;
extern HANDLE       thread, mouHook, keyHook;
extern UINT         WM_TASKBAR;
extern RunLevel     eLevel;
extern LPCSTR       MythwareFilename;
extern VBRandomEngine VBMath;

// ── ntdll 动态加载的函数指针 ─────────────────────────────────
extern NTSTATUS (NTAPI *NtSuspendProcess)(IN HANDLE Process);
extern NTSTATUS (NTAPI *NtResumeProcess)(IN HANDLE Process);

// ── 公共函数声明 ────────────────────────────────────────────
// utils
const char* RandomWindowTitle();
const char* FormatLogTime();
void        PrtError(LPCSTR szDes, LRESULT lResult);
BOOL        EnableDebugPrivilege();
LONG WINAPI GlobalExceptionHandler(EXCEPTION_POINTERS* exceptionInfo);
BOOL CALLBACK SetWindowFont(HWND hwndChild, LPARAM lParam);
void        ApplyAntiCapture(HWND hWnd);   // 防教师端截屏（Win7 自动回退 WDA_MONITOR）
LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam);
void        InstallDialogProtection();
void        UninstallDialogProtection();
void        InitLogFile();
void        CloseLogFile();
void        LogWrite(const char* text);
void        LogAppend(const char* text, bool newline);   // Print/Println 的底层实现
void        WriteRuntimeLog(const char* level, const char* where, const char* fmt, ...);

// ── 源码字面量编码适配（Win7 兼容）──────────────────────────
// 源码以 -fexec-charset=UTF-8 编译，中文字面量是 UTF-8 字节；本程序调用 ANSI (A)
// 系列 Win32 API，这些 API 用进程 ANSI 代码页(ACP)解码。
// 
// 别因为"现在跑在 Win10/11 上"就把 UA()/AS() 拆掉。
//
//   UA() — 瞬时生效，返回值仅在本调用表达式内有效（环形缓冲），用于直接传参
//   AS() — 返回持有的 std::string，用于跨语句保存或字符串拼接
//
// 漏包一处编译器不会报错、只会静默乱码；改动后用 scripts/check_literals.py 兜底。
LPCSTR      UA(const char* u8);
std::string AS(const char* u8);

// 运行时日志宏（写入 %TEMP%\MythwareToolkit_run.log）
#define LOG_INFO(fmt, ...)  WriteRuntimeLog("INFO",  __FUNCTION__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  WriteRuntimeLog("WARN",  __FUNCTION__, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) WriteRuntimeLog("ERROR", __FUNCTION__, fmt, ##__VA_ARGS__)

// process
void  InitNTAPI();
DWORD GetProcessIDFromName(LPCSTR szName);
bool  KillProcess(DWORD dwProcessID, int way);
bool  KillAllProcessWithName(LPCSTR name, int way);
BOOL  SuspendProcess(DWORD dwProcessID, BOOL suspend);
int   GetProcessState(DWORD dwProcessID);
bool  ToggleProcessProtection();

// mythware
BOOL        GetMythwarePasswordFromRegedit(char* str);
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
std::string GetRunLevelString();
void        UpdateMythwareStatus();
void        ToggleBroadcastWindow();
void        ControlMythware(BOOL kill);
void        ExitBlackScreen();

// hooks
DWORD WINAPI KeyHookThreadProc(LPVOID lpParameter);
DWORD WINAPI MouseHookThreadProc(LPVOID lpParameter);
DWORD WINAPI ThreadProc(LPVOID lpParameter);
LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam);

// bypass
void UnlockSystemPrograms(HWND hwnd);
void RemoveNetworkRestrictions();
void RemoveUSBRestrictions(HWND hwnd);

// assistant
void KillStudentAssistant();

// floating — 受保护的弹出菜单（对教师端监控不可见）
BOOL TrackPopupMenuProtected(HMENU hMenu, UINT uFlags, int x, int y, HWND hWnd);
