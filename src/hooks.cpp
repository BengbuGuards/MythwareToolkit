#include "globals.h"

LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

DWORD WINAPI KeyHookThreadProc(LPVOID lpParameter) {
    HMODULE hModule = GetModuleHandle(NULL);
    while (true) {
        kbdHook = (HHOOK)SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)HookProc, hModule, 0);
        Sleep(25);
        UnhookWindowsHookEx(kbdHook);
    }
    return 0;
}

DWORD WINAPI MouseHookThreadProc(LPVOID lpParameter) {
    HMODULE hModule = GetModuleHandle(NULL);
    while (true) {
        mseHook = (HHOOK)SetWindowsHookEx(WH_MOUSE_LL, (HOOKPROC)HookProc, hModule, 0);
        ClipCursor(NULL);
        Sleep(25);
        UnhookWindowsHookEx(mseHook);
    }
    return 0;
}

DWORD WINAPI ThreadProc(LPVOID lpParameter) {
    while (true) {
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        Sleep(250);
    }
    return 0L;
}
