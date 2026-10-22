// main.cpp — 程序入口 WinMain + 主窗口消息处理 + 托盘图标 + 内嵌工具启动
#pragma GCC optimize(3)

#include "globals.h"
#include "version.h"
#include "psd.h"
#include "floating.h"
#include "ui.h"
#undef UNICODE
#undef _UNICODE

// 全局变量定义
std::string     sOutPut;
HHOOK           kbdHook, mseHook;
HWND            hwnd, focus, hBdCst;
HWND            BtAbt, BtKmw, TxOut, TxLnk, BtTop, BtCur, BtKbh, BtSnp, BtWnd;
NOTIFYICONDATA  icon;
HMENU           hMenu;
HFONT           hFont;
int             width = 660, height = 335, w, h, mwSts;
bool            asking = false, ask = false, closingProcess = false;
DWORD           error = -1;
POINT           p, pt;
HANDLE          thread, mouHook, keyHook;
UINT            WM_TASKBAR;
RunLevel        eLevel;
LPCSTR          MythwareFilename = "StudentMain.exe";
VBRandomEngine  VBMath;

NTSTATUS (NTAPI *NtSuspendProcess)(IN HANDLE Process);
NTSTATUS (NTAPI *NtResumeProcess)(IN HANDLE Process);

static std::string helpText = AS("极域工具包 v") + TOOLKIT_VERSION_STR + AS(" | 小流汗黄豆 & Jsenn123\n\
额外功能：1. 快捷键Alt+C双击杀掉当前进程，Alt+W最小化顶层窗口，Alt+B唤起主窗口\n\
2. 悬浮窗左键打开主面板，中键直接切换广播窗口化/全屏化，右键打开快捷菜单，可拖拽移动\n\
3. 最小化时隐藏到任务栏托盘，左键双击打开主界面，右键单击调出菜单\n\
4. 解禁工具可解禁Chrome和Edge的小游戏；若提示设置失败，可能是无权限或指定注册表键值不存在\n\
5. 解键盘锁功能如果对Alt+Ctrl+Delete无效时，重新勾选即可\n\
6. 启动时附加-s或/s命令行可以System权限启动\n\
7. MeltdownDFC为冰点还原密码破解工具，crdisk为其他保护系统删除工具（慎用！）\n\
8. 退出黑屏功能请慎用，目前仍有未知bug，会导致退出后操作不顺。（慎用！）");

static bool SetupTrayIcon(HWND m_hWnd, HINSTANCE hInstance) {
    icon.cbSize = sizeof(NOTIFYICONDATA); icon.hWnd = m_hWnd; icon.uID = 0;
    icon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    icon.uCallbackMessage = WM_USER + 3;
    icon.hIcon = LoadIcon(hInstance, "MAINICON");
    strcpy(icon.szTip, UA("明天会更好"));  //托盘图标显示文字
    return 0 != Shell_NotifyIcon(NIM_ADD, &icon);
}

static void RunEmbeddedExe(int resId, LPCSTR exeName) {
    LOG_INFO("RunEmbeddedExe resId=%d name=%s", resId, exeName);
    DWORD dwPID = GetProcessIDFromName(exeName);
    if (dwPID) { LOG_INFO("%s already running (pid=%lu)", exeName, dwPID); return; }
    char szTempPath[MAX_PATH]; GetTempPath(MAX_PATH, szTempPath);
    strcat(szTempPath, exeName);
    HANDLE hFile = CreateFile(szTempPath, GENERIC_ALL, FILE_SHARE_READ, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_ERROR("CreateFile(%s) failed: err=%lu", szTempPath, GetLastError());
        SetWindowText(TxOut, UA("创建失败")); return;
    }
    HRSRC hResInfo = FindResource(NULL, MAKEINTRESOURCE(resId), RT_RCDATA);
    if (!hResInfo) {
        LOG_ERROR("FindResource(%d) failed: err=%lu", resId, GetLastError());
        CloseHandle(hFile); SetWindowText(TxOut, UA("资源未找到")); return;
    }
    HGLOBAL hResData = LoadResource(NULL, hResInfo);
    DWORD dwSize = SizeofResource(NULL, hResInfo);
    LPVOID pData = LockResource(hResData);
    if (pData && dwSize > 0) {
        DWORD written;
        if (!WriteFile(hFile, pData, dwSize, &written, NULL)) {
            LOG_ERROR("WriteFile failed: err=%lu", GetLastError());
            SetWindowText(TxOut, UA("写入失败")); CloseHandle(hFile); return;
        }
        LOG_INFO("Extracted %lu bytes to %s", dwSize, szTempPath);
        FlushFileBuffers(hFile); CloseHandle(hFile);
        // ShellExecuteEx + runas 提权（MeltdownDFC/crdisk 需要管理员权限）
        SHELLEXECUTEINFO sei = {};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = "runas";
        sei.lpFile = szTempPath;
        sei.nShow = SW_SHOW;
        if (ShellExecuteEx(&sei)) {
            LOG_INFO("Launched %s (pid=%lu)", exeName, GetProcessId(sei.hProcess));
            CloseHandle(sei.hProcess);
            SetWindowText(TxOut, UA("执行完成"));
        } else {
            DWORD err = GetLastError();
            if (err == ERROR_CANCELLED) {
                LOG_INFO("User cancelled UAC prompt for %s", exeName);
                SetWindowText(TxOut, UA("用户取消"));
            } else {
                LOG_ERROR("ShellExecuteEx(%s) failed: err=%lu", exeName, err);
                SetWindowText(TxOut, UA("启动失败"));
            }
        }
    } else {
        LOG_ERROR("LockResource failed or size=0");
        SetWindowText(TxOut, UA("写入失败")); CloseHandle(hFile);
    }
}

// ── 鼠标角落检测：停留 > 800ms 触发，离开 > 500ms 才允许再次触发 ──
static DWORD g_cornerEnterTime = 0;
static DWORD g_cornerLeaveTime = 0;
static bool  g_wasInCorner    = false;

static void CheckCornerTrigger(HWND hwnd) {
    if (!ask || asking) return;
    GetCursorPos(&p);

    bool inCorner = (p.x == 0 || p.x == w) && p.y == 0;
    DWORD now = GetTickCount();

    if (!inCorner) {
        if (g_wasInCorner) { g_cornerLeaveTime = now; g_wasInCorner = false; }
        g_cornerEnterTime = 0;
        return;
    }
    // 在角落里
    if (!g_wasInCorner) {
        // 刚进入角落：检查去抖间隔
        if (now - g_cornerLeaveTime < 500) return;
        g_cornerEnterTime = now;
        g_wasInCorner = true;
    }
    // 停留不够 800ms
    if (now - g_cornerEnterTime < 800) return;

    // ── 触发 ──
    asking = true;
    SetWindowPos(hwnd, NULL, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    ResetFloatingWindowPos();

    HWND hFg = GetForegroundWindow();
    if (hFg == GetFloatingWindow()) {
        asking = false;
        g_cornerEnterTime = 0;
        g_wasInCorner = false;
        return;
    }
    if (p.x == 0) { // 左上角：最小化
        if (MessageBox(hwnd, UA("检测到鼠标位置变化！是否最小化焦点窗口？"),
            UA("实时提醒（最小化）"), MB_OKCANCEL | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST) == IDOK)
            if (!IsHungAppWindow(hFg)) ShowWindow(hFg, SW_MINIMIZE);
    } else { // 右上角：关闭
        HHOOK hook = SetWindowsHookEx(WH_CBT, CBTProc, NULL, GetCurrentThreadId());
        int id = MessageBox(hwnd, UA("检测到鼠标位置变化！是否关闭焦点窗口？"),
            UA("实时提醒（关闭）"), MB_YESNOCANCEL | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST);
        UnhookWindowsHookEx(hook);
        if (id == IDYES) PostMessage(hFg, WM_CLOSE, 0, 0);
        else if (id == IDNO) {
            HWND hP = CreateWindowEx(0, WC_STATIC, "", 0,0,0,0,0,NULL,NULL,NULL,NULL);
            SetParent(hFg, hP); ge; PostMessage(hP, WM_CLOSE, 0, 0);
        }
    }
    asking = false;
    g_cornerEnterTime = 0;
    g_wasInCorner = false;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
    switch (Message) {
        case WM_CREATE: {
            OSVERSIONINFO vi = {sizeof(OSVERSIONINFO)}; GetVersionEx(&vi);
            SYSTEM_INFO si = {}; GetNativeSystemInfo(&si);
            char szVersion[BUFSIZ] = {};
            sprintf(szVersion, UA("系统版本：%u.%u.%u %d-bit\n程序版本：%s %d-bit\n"),
                vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber,
                (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) ? 64 : 32, TOOLKIT_VERSION_STR, sizeof(PVOID)*8);
            sOutPut += szVersion;
            EnableDebugPrivilege();
            w = GetSystemMetrics(SM_CXSCREEN) - 1; h = GetSystemMetrics(SM_CYSCREEN) - 1;
            WM_TASKBAR = RegisterWindowMessage("TaskbarCreated");
            thread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
            keyHook = CreateThread(NULL, 0, KeyHookThreadProc, NULL, CREATE_SUSPENDED, NULL);
            mouHook = CreateThread(NULL, 0, MouseHookThreadProc, NULL, CREATE_SUSPENDED, NULL);
            // 安装永久 CBT 钩子：所有主线程弹窗自动防教师端截屏
            SetWindowsHookEx(WH_CBT, CBTProc, GetModuleHandle(NULL), GetCurrentThreadId());
            SetTimer(hwnd, 1, 1000, NULL); SetTimer(hwnd, 2, 2000, NULL);
            RegisterHotKey(hwnd, 0, MOD_ALT, 'C'); RegisterHotKey(hwnd, 1, MOD_ALT, 'W');
            if (!RegisterHotKey(hwnd, 2, MOD_ALT, 'B'))
                if (MessageBox(hwnd, UA("注册系统级热键 Alt+B 失败，有可能该应用的另一实例还在运行，请先关闭它再重新启动本程序！否则唤出窗口功能将失效！若点击「取消」则阻止程序继续启动"),
                    UA("明 天 会 更 好"), MB_OKCANCEL | MB_ICONWARNING) == IDCANCEL) { PostQuitMessage(0); return FALSE; }

            HINSTANCE hi = ((LPCREATESTRUCT)lParam)->hInstance;
            CreateAllControls(hwnd, hi);

            HWND hToolTip = CreateWindowEx(WS_EX_TOPMOST, TOOLTIPS_CLASS, NULL, WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
                CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hwnd, NULL, hi, NULL);
            TOOLINFO ti = {sizeof(ti)}; ti.uFlags = TTF_IDISHWND | TTF_SUBCLASS; ti.hwnd = hwnd; ti.uId = (UINT_PTR)TxOut;
            static std::string runLevelText = GetRunLevelString();   // 需活到 tooltip 生命周期结束
            ti.lpszText = const_cast<char*>(runLevelText.c_str());
            SendMessage(hToolTip, TTM_ADDTOOL, 0, (LPARAM)&ti);

            NONCLIENTMETRICS info; info.cbSize = sizeof(NONCLIENTMETRICS);
            if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, 0, &info, 0)) hFont = CreateFontIndirect((LOGFONT*)&info.lfMessageFont);
            EnumChildWindows(hwnd, SetWindowFont, LPARAM(hFont));
            SetupTrayIcon(hwnd, hi);

            HMENU sys = GetSystemMenu(hwnd, FALSE);
            AppendMenu(sys, MF_STRING, 2, UA("显示上一次错误(&E)")); AppendMenu(sys, MF_STRING, 4, UA("显示程序日志(&L)"));
            AppendMenu(sys, MF_STRING, 3, UA("启动任务管理器(&T)")); DrawMenuBar(hwnd);
            focus = GetDlgItem(hwnd, 1013); SetFocus(focus);
            SendMessage(hwnd, WM_TIMER, WPARAM(2), 0);

            // 极域注入的 hook DLL 不能直接 FreeModule，因为系统钩子还指着 DLL 内地址
            // 暴力卸载会导致钩子回调跳转到无效内存 → 0xC0000005 DEP 崩溃
            // 正确做法：保留 DLL 加载，通过我们自己的钩子覆盖其行为即可
            break;
        }

        case WM_INITMENU: { HMENU sys = GetSystemMenu(hwnd, FALSE); SetMenuDefaultItem(sys, SC_MINIMIZE, 0); break; }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case 1002: {
                    static bool bAboutOpen = false;
                    if (!bAboutOpen) {
                        bAboutOpen = true;
                        MessageBox(NULL, helpText.c_str(), UA("关于/帮助"), MB_OK | MB_ICONINFORMATION);
                        bAboutOpen = false;
                    }
                    break;
                }
                case 1006: KillStudentAssistant(); break;
                case 1004: ControlMythware(FALSE); UpdateMythwareStatus(); break;
                case 1007: {
                    static bool bUnlockOpen = false;
                    if (!bUnlockOpen) {
                        bUnlockOpen = true;
                        UnlockSystemPrograms(hwnd);
                        bUnlockOpen = false;
                    }
                    break;
                }
                case 1008: {
    // 提权后重新运行本程序执行解除网络限制
    char exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);
    SHELLEXECUTEINFO sei = {};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "runas";
    sei.lpFile = exePath;
    sei.lpParameters = "-net";
    sei.nShow = SW_HIDE;
    if (ShellExecuteEx(&sei)) {
        LOG_INFO("Elevated RemoveNetworkRestrictions launched (pid=%lu)", GetProcessId(sei.hProcess));
        CloseHandle(sei.hProcess);
        SetWindowText(TxOut, UA("正在解除网络限制..."));
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_CANCELLED)
            SetWindowText(TxOut, UA("用户取消"));
        else {
            LOG_ERROR("ShellExecuteEx runas failed: err=%lu", err);
            RemoveNetworkRestrictions();  // 回退：直接尝试
        }
    }
    break;
}
                case 1009: RemoveUSBRestrictions(hwnd); break;
                case 1010: {
                    HWND hShell = FindWindow("Shell_TrayWnd", NULL); DWORD pid;
                    GetWindowThreadProcessId(hShell, &pid);
                    if (pid == 0 || hShell == NULL) { WinExec("explorer.exe", SW_SHOW); break; }
                    HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                    if (TerminateProcess(handle, 2)) SetWindowText(TxOut, UA("执行成功"));
                    else { ge; SetWindowText(TxOut, UA("执行失败")); }
                    CloseHandle(handle); break;
                }
                case 1013: KillStudentAssistant(); break;
                case 1011: { LRESULT check = SendMessage(BtSnp, BM_GETCHECK, 0, 0); if (check == BST_CHECKED) ApplyAntiCapture(hwnd); else SetWindowDisplayAffinity(hwnd, WDA_NONE); break; }
                case 1012: { LRESULT check = SendMessage(BtWnd, BM_GETCHECK, 0, 0); ask = check == BST_CHECKED; break; }
                case 1014: ToggleBroadcastWindow(); UpdateMythwareStatus(); break;
                case 1015: ShowPsdWnd(); break;
                case 1016: {
    LRESULT check = SendMessage(BtTop, BM_GETCHECK, 0, 0);
    if (check == BST_CHECKED) {
        ResumeThread(thread);
    } else {
        SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        SuspendThread(thread);
    }
    break;
}
                case 1017: { LRESULT check = SendMessage(BtCur, BM_GETCHECK, 0, 0); if (check == BST_CHECKED) ResumeThread(mouHook); else { SuspendThread(mouHook); UnhookWindowsHookEx(mseHook); } break; }
                case 1018: {
                    LRESULT check = SendMessage(BtKbh, BM_GETCHECK, 0, 0);
                    if (check == BST_CHECKED) {
                        ResumeThread(keyHook);
                        HANDLE hDevice = CreateFile("\\\\.\\TDKeybd", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                        if (hDevice == INVALID_HANDLE_VALUE) { DWORD dwErr = GetLastError(); PrtError(dwErr == ERROR_FILE_NOT_FOUND ? UA("解键盘锁失败：极域未安装") : UA("解键盘锁：打开设备失败"), dwErr); break; }
                        BOOL bEnable = TRUE; DWORD bytesReturned = 0;
                        if (DeviceIoControl(hDevice, 0x220000, &bEnable, 4, NULL, 0, &bytesReturned, NULL)) Print(UA("解键盘锁：发送控制码成功"));
                        else PrtError(UA("解键盘锁：发送控制码失败"), GetLastError());
                        CloseHandle(hDevice);
                    } else { SuspendThread(keyHook); UnhookWindowsHookEx(kbdHook); }
                    break;
                }
                case 1019: RunEmbeddedExe(2, "\\MeltdownDFC.exe"); break;
                case 1020: RunEmbeddedExe(3, "\\crdisk.exe"); break;
                case 1021: ExitBlackScreen(); break;
                case 1022: ToggleFloatingWindow(); break;
            }
            return 0;
        }

        case WM_HOTKEY:
            switch (wParam) {
                case 0: if (closingProcess) { closingProcess = false; KillTimer(hwnd, 3); HWND topHwnd = GetForegroundWindow(); DWORD pid; GetWindowThreadProcessId(topHwnd, &pid); if (pid != GetCurrentProcessId()) KillProcess(pid, KILL_FORCE); } else { closingProcess = true; SetTimer(hwnd, 3, GetDoubleClickTime(), NULL); } break;
                case 1: MinimizeFocusWindow(); break;
                case 2: ShowWindow(hwnd, SW_SHOWNORMAL); SetForegroundWindow(hwnd); break;
            }
            return 0;

        case WM_TIMER:
            // 定时重设防截屏保护，防止被外部清除
            if (SendMessage(BtSnp, BM_GETCHECK, 0, 0) == BST_CHECKED)
                SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
            switch (wParam) {
                case 1: CheckCornerTrigger(hwnd); break;
                case 2: SetWindowText(hwnd, RandomWindowTitle()); UpdateMythwareStatus(); break;
                case 3: closingProcess = false; KillTimer(hwnd, 3); break;
            }
            break;

        case WM_CLOSE: ShowWindow(hwnd, SW_HIDE); return TRUE;

        case WM_DESTROY:
            CloseLogFile();
            UnregisterHotKey(hwnd, 0); UnregisterHotKey(hwnd, 1); UnregisterHotKey(hwnd, 2);
            UninstallDialogProtection();
            CloseHandle(thread);
            CloseHandle(keyHook); CloseHandle(mouHook);
            Shell_NotifyIcon(NIM_DELETE, &icon); UnhookWindowsHookEx(mseHook); UnhookWindowsHookEx(kbdHook);
            break;

        case WM_ACTIVATE: {
            char c[64];
            if (LOWORD(wParam) == WA_INACTIVE) {
                if (GetWindowLong(hwnd, GWL_STYLE) & WS_VISIBLE) {
                    focus = GetFocus();
                    if (focus && GetClassName(focus, c, sizeof(c)) && _stricmp(c, "Button") == 0) {
                        LONG style = GetWindowLong(focus, GWL_STYLE);
                        if ((style & BS_AUTOCHECKBOX) != BS_AUTOCHECKBOX) SendMessage(focus, BM_SETSTYLE, 0, TRUE);
                    }
                }
            } else {
                if (focus && IsWindow(focus)) { SetFocus(focus);
                    if (GetClassName(focus, c, sizeof(c)) && _stricmp(c, "Button") == 0) {
                        LONG style = GetWindowLong(focus, GWL_STYLE);
                        if ((style & BS_AUTOCHECKBOX) != BS_AUTOCHECKBOX) SendMessage(focus, BM_SETSTYLE, BS_DEFPUSHBUTTON, TRUE);
                    }
                }
            }
            return FALSE;
        }

        case WM_USER + 3:
            if (lParam == WM_LBUTTONDBLCLK) { ShowWindow(hwnd, SW_SHOWNORMAL); SetForegroundWindow(hwnd); }
            else if (lParam == WM_RBUTTONUP) { GetCursorPos(&pt); SetForegroundWindow(hwnd); HMENU hPopup = CreatePopupMenu(); AppendMenu(hPopup, MF_STRING, 1, UA("关闭程序")); AppendMenu(hPopup, MF_STRING, 2, UA("打开窗口")); int i = TrackPopupMenuProtected(hPopup, TPM_RETURNCMD, pt.x, pt.y, hwnd); if (i == 1) { DestroyFloatingWindow(); PostQuitMessage(0); } else if (i == 2) { ShowWindow(hwnd, SW_SHOWNORMAL); SetForegroundWindow(hwnd); } }
            return FALSE;

        case WM_NOTIFY:
            switch (((LPNMHDR)lParam)->code) {
                case BCN_DROPDOWN: {
                    NMBCDROPDOWN* pDropDown = (NMBCDROPDOWN*)lParam;
                    if (pDropDown->hdr.hwndFrom == BtKmw) {
                        POINT ptBtn; ptBtn.x = pDropDown->rcButton.left; ptBtn.y = pDropDown->rcButton.bottom;
                        ClientToScreen(pDropDown->hdr.hwndFrom, &ptBtn);
                        HMENU hSplitMenu = CreatePopupMenu();
                        AppendMenu(hSplitMenu, MF_BYPOSITION, 1, (mwSts != 1) ? UA("挂起极域") : UA("恢复极域"));
                        EnableMenuItem(hSplitMenu, 1, mwSts != 2 ? MF_ENABLED : MF_GRAYED);
        SuspendThread(thread);
                        int i = TrackPopupMenuProtected(hSplitMenu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD, ptBtn.x, ptBtn.y, hwnd);
        ResumeThread(thread);
                        if (i == 1) { BOOL sts = SuspendProcess(GetProcessIDFromName(MythwareFilename), !mwSts); SetWindowText(TxOut, sts ? UA("挂起/恢复成功") : UA("挂起/恢复失败")); UpdateMythwareStatus(); }
                        return TRUE;
                    }
                    break;
                }
                case NM_CLICK:
                    if (((LPNMHDR)lParam)->hwndFrom == TxOut) {
                        focus = GetFocus(); char c[64];
                        if (focus && GetClassName(focus, c, sizeof(c)) && _stricmp(c, "Button") == 0) {
                            LONG style = GetWindowLong(focus, GWL_STYLE);
                            if ((style & BS_AUTOCHECKBOX) != BS_AUTOCHECKBOX) SendMessage(focus, BM_SETSTYLE, BS_DEFPUSHBUTTON, TRUE);
                        }
                        break;
                    }
                case NM_RETURN: { PNMLINK pNMLink = (PNMLINK)lParam; LITEM item = pNMLink->item; if ((((LPNMHDR)lParam)->hwndFrom == TxLnk) && (item.iLink == 0)) ShellExecuteW(NULL, L"open", item.szUrl, NULL, NULL, SW_SHOW); break; }
            }
            break;

        case WM_NCHITTEST: { UINT nHitTest = DefWindowProc(hwnd, WM_NCHITTEST, wParam, lParam); if (nHitTest == HTCLIENT && GetAsyncKeyState(MK_LBUTTON) < 0) nHitTest = HTCAPTION; return nHitTest; }

        case WM_SYSCOMMAND:
            switch (wParam) {
                case 2: { if (error == -1) error = GetLastError(); LPSTR szError = NULL; FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, (PTSTR)&szError, 0, NULL); char s[BUFSIZ] = {}; sprintf(s, UA("GetLastError上一次记录\n%u：%s"), error, szError); LocalFree(HLOCAL(szError)); MessageBox(hwnd, s, UA("上一次错误"), MB_OK | MB_ICONINFORMATION); error = -1; break; }
                case 3: { HWND h = FindWindow("TaskManagerWindow", NULL); BYTE nCount = 0; if (!h) { DWORD value = 0; HKEY retKey; RegOpenKeyEx(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey); RegSetValueEx(retKey, "DisableTaskMgr", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD)); RegFlushKey(retKey); RegCloseKey(retKey); WinExec("taskmgr", SW_SHOW); ge; do { if (++nCount == 60) { SetWindowText(TxOut, UA("启动失败")); return FALSE; } Sleep(50); h = FindWindow("TaskManagerWindow", NULL); } while (!h); } HMENU hm = GetMenu(h); MENUITEMINFO mii = {sizeof(MENUITEMINFO), MIIM_STATE}; GetMenuItemInfo(hm, 0x7704, FALSE, &mii); if (!(mii.fState & MFS_CHECKED)) PostMessage(h, WM_COMMAND, 0x7704, 0); SetWindowText(TxOut, UA("设置完成")); break; }
                case 4: { char szTempPath[MAX_PATH]; GetTempPath(MAX_PATH, szTempPath); HANDLE hFile = CreateFile(strcat(szTempPath, "\\ToolkitLog.txt"), GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL); WriteFile(hFile, sOutPut.c_str(), sOutPut.size() + 1, NULL, NULL); FlushFileBuffers(hFile); ShellExecute(hwnd, "open", szTempPath, NULL, NULL, SW_SHOW); CloseHandle(hFile); break; }
                case SC_MINIMIZE: SetActiveWindow(hwnd); focus = GetFocus(); break;
            }
            return DefWindowProc(hwnd, Message, wParam, lParam);

        case WM_SIZE: if (wParam == SIZE_MINIMIZED) { ShowWindow(hwnd, SW_HIDE); return TRUE; } break;

        case WM_SHOWWINDOW:
            if (wParam) SetWindowPos(hwnd, NULL, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
            break;

        case WM_WINDOWPOSCHANGED: {
            // 事件驱动置顶：仅当其他窗口把本窗口挤下去时才重新置顶，避免无意义轮询
            WINDOWPOS* wp = (WINDOWPOS*)lParam;
            if (!(wp->flags & SWP_NOZORDER) && IsWindowVisible(hwnd)) {
                SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                             SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            }
            return DefWindowProc(hwnd, Message, wParam, lParam);
        }

        default: if (Message == WM_TASKBAR) Shell_NotifyIcon(NIM_ADD, &icon); return DefWindowProc(hwnd, Message, wParam, lParam);
    }
    return TRUE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    SetUnhandledExceptionFilter(GlobalExceptionHandler);
    InitNTAPI();
    LOG_INFO("WinMain start, cmdLine=%s", lpCmdLine ? lpCmdLine : "(null)");

    HANDLE hToken; OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    DWORD dwLength = 0; GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength);
    PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLength);
    if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLength, &dwLength)) {
        DWORD dwLevel = *GetSidSubAuthority(pTIL->Label.Sid, *GetSidSubAuthorityCount(pTIL->Label.Sid) - 1);
        if (dwLevel >= SECURITY_MANDATORY_SYSTEM_RID) eLevel = RL_SYSTEM;
        else if (dwLevel >= SECURITY_MANDATORY_HIGH_RID) eLevel = RL_ADMIN;
        else eLevel = RL_USER;
    } else eLevel = RL_UNKNOWN;

    int argc; bool bStartAsSystem = false; bool bDoNetUnlock = false;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        bStartAsSystem = (!_wcsicmp(argv[1], L"-s") || !_wcsicmp(argv[1], L"/s"));
        bDoNetUnlock   = (!_wcsicmp(argv[1], L"-net") || !_wcsicmp(argv[1], L"/net"));
        LocalFree(argv);
    }
    // -net 参数：提权后自动执行解除网络限制
    if (bDoNetUnlock) {
        LOG_INFO("Auto-run RemoveNetworkRestrictions (elevated)");
        RemoveNetworkRestrictions();
        return 0;
    }
    if (eLevel != RL_SYSTEM && bStartAsSystem) {
        EnableDebugPrivilege();
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetProcessIDFromName("lsass.exe"));
        if (!hProcess) hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetProcessIDFromName("winlogon.exe"));
        HANDLE hTokenx, hTokenDup; OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hTokenx);
        DuplicateTokenEx(hTokenx, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hTokenDup);
        CloseHandle(hProcess); CloseHandle(hTokenx);
        STARTUPINFOW si; PROCESS_INFORMATION pi; ZeroMemory(&si, sizeof(STARTUPINFOW)); si.cb = sizeof(STARTUPINFOW);
        GetStartupInfoW(&si);
        BOOL bResult = CreateProcessWithTokenW(hTokenDup, LOGON_NETCREDENTIALS_ONLY, NULL, GetCommandLineW(), NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi);
        error = GetLastError(); CloseHandle(hTokenDup);
        if (bResult) return 0;
        else MessageBox(NULL, UA("无法以系统权限运行，将以普通方式运行。欲知详细信息请查看上一次错误"), UA("极域工具包"), MB_ICONERROR | MB_OK);
    }

    WNDCLASSEX wc; MSG msg; memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(WNDCLASSEX); wc.lpfnWndProc = WndProc; wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = (HBRUSH)COLOR_WINDOW;
    wc.lpszClassName = "WindowClass"; wc.hIcon = LoadIcon(hInstance, "MAINICON"); wc.hIconSm = LoadIcon(hInstance, "MAINICON");
    if (!RegisterClassEx(&wc)) { MessageBox(NULL, UA("窗口类注册失败！请重试"), UA("极 域 工 具 包"), MB_ICONEXCLAMATION | MB_OK); return 0; }

    hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, "WindowClass", RandomWindowTitle(), (WS_OVERLAPPEDWINDOW | WS_VISIBLE) ^ WS_MAXIMIZEBOX ^ WS_SIZEBOX, 0, 0, width, height, NULL, NULL, hInstance, NULL);
    if (hwnd == NULL) { MessageBox(NULL, UA("窗口创建失败！请重试"), UA("极 域 工 具 包"), MB_ICONEXCLAMATION | MB_OK); return 0; }

    ShowWindow(hwnd, nCmdShow); UpdateWindow(hwnd);
    InitLogFile();

    // 所有对话框自动防截屏
    InstallDialogProtection();

    // 启动即开启防杀保护
    ToggleProcessProtection();
    LOG_INFO("Process protection: enabled by default");

    LOG_INFO("Creating floating window...");
    if (!CreateFloatingWindow(hInstance)) {
        LOG_ERROR("CreateFloatingWindow returned NULL");
        Println(UA("悬浮窗创建失败（可能窗口类已注册或资源加载异常）"));
    }
    LOG_INFO("Entering message loop");

    while (GetMessage(&msg, NULL, 0, 0) > 0) { if (!IsDialogMessage(hwnd, &msg)) { TranslateMessage(&msg); DispatchMessage(&msg); } }
    return msg.wParam;
}
