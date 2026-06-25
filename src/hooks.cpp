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
        // 窗口隐藏时不抢置顶，避免和极域黑屏窗口 Z 序打架导致闪烁
        if (hwnd && IsWindow(hwnd) && IsWindowVisible(hwnd)) {
            SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            Sleep(250);
        } else {
            Sleep(1000);  // 隐藏时降低检查频率
        }
    }
    return 0L;
}
