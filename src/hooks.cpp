// hooks.cpp — 键盘/鼠标钩子线程、窗口置顶线程
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

// 轮询维持置顶：UIAccess 版间隔放长，便携版保持短间隔
DWORD WINAPI ThreadProc(LPVOID lpParameter) {
    while (true) {
        if (hwnd && IsWindow(hwnd) && IsWindowVisible(hwnd)) {
            SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
#ifdef UIACCESS_BUILD
            Sleep(3000);   // UIAccess：长间隔，减少干扰
#else
            Sleep(250);    // 便携版：短间隔，维持置顶
#endif
        } else {
            Sleep(1000);
        }
    }
    return 0L;
}
