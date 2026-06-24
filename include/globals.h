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

// 日志宏（同时写入内存和文件）
#define Print(text)   do { const char* _t = FormatLogTime(); sOutPut = sOutPut + _t + text; LogWrite(_t); LogWrite(text); } while(0)
#define Println(text) Print(text); sOutPut += "\r\n"; LogWrite("\r\n")
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
LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam);
void        InitLogFile();
void        CloseLogFile();
void        LogWrite(const char* text);

// process
void  InitNTAPI();
DWORD GetProcessIDFromName(LPCSTR szName);
bool  KillProcess(DWORD dwProcessID, int way);
bool  KillAllProcessWithName(LPCSTR name, int way);
BOOL  SuspendProcess(DWORD dwProcessID, BOOL suspend);
int   GetProcessState(DWORD dwProcessID);

// mythware
BOOL        GetMythwarePasswordFromRegedit(char* str);
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
const char* GetRunLevelString();
void        UpdateMythwareStatus();
void        ToggleBroadcastWindow();
void        ControlMythware(BOOL kill);

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
