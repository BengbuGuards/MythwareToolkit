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

BOOL GetMythwarePasswordFromRegedit(char *str);
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
DWORD WINAPI KeyHookThreadProc(LPVOID lpParameter);
DWORD WINAPI MouseHookThreadProc(LPVOID lpParameter);

DWORD WINAPI ThreadProc(LPVOID lpParameter);
BOOL CALLBACK SetWindowFont(HWND hwndChild, LPARAM lParam);
bool SetupTrayIcon(HWND m_hWnd, HINSTANCE hInstance);
LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam);

void InitNTAPI();
LPCSTR RandomWindowTitle();
BOOL EnableDebugPrivilege();
DWORD GetProcessIDFromName(LPCSTR szName);
bool KillProcess(DWORD dwProcessID, int way);
bool KillAllProcessWithName(LPCSTR name, int way);
BOOL SuspendProcess(DWORD dwProcessID, BOOL suspend);
int GetProcessState(DWORD dwProcessID);
#define KILL_FORCE 1
#define KILL_DEFAULT 2
#define Set(dest, source) *(PVOID*)&(dest) = (PVOID)(source) //强行修改不同指针型数据的值

LONG WINAPI GlobalExceptionHandler(EXCEPTION_POINTERS* exceptionInfo);
inline void PrtError(LPCSTR szDes, LRESULT lResult);
inline LPSTR FormatLogTime();