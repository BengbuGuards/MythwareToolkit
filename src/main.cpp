#pragma GCC optimize(3)

#include "globals.h"
#include "psd.h"
#include "floating.h"
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
int             width = 640, height = 380, w, h, mwSts;
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

static LPCSTR helpText = "极域工具包 v2.0 | 小流汗黄豆 | 交流群828869154（进群请注明极域工具包）\n\
额外功能：1. 快捷键Alt+C双击杀掉当前进程，Alt+W最小化顶层窗口，Alt+B唤起主窗口\n\
2. 悬浮窗左键打开主面板，右键直接切换广播窗口化/全屏化，可拖拽移动\n\
3. 最小化时隐藏到任务栏托盘，左键双击打开主界面，右键单击调出菜单\n\
4. 解禁工具可解禁Chrome和Edge的小游戏；若提示设置失败，可能是无权限或指定注册表键值不存在\n\
5. 解键盘锁功能如果对Alt+Ctrl+Delete无效时，重新勾选即可\n\
6. 启动时附加-s或/s命令行可以System权限启动\n\
7. MeltdownDFC为冰点还原密码破解工具，crdisk为其他保护系统删除工具（慎用！）";

static bool SetupTrayIcon(HWND m_hWnd, HINSTANCE hInstance) {
    icon.cbSize = sizeof(NOTIFYICONDATA); icon.hWnd = m_hWnd; icon.uID = 0;
    icon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    icon.uCallbackMessage = WM_USER + 3;
    icon.hIcon = LoadIcon(hInstance, "MAINICON");
    strcpy(icon.szTip, "极域工具包");
    return 0 != Shell_NotifyIcon(NIM_ADD, &icon);
}

static void RunEmbeddedExe(int resId, LPCSTR exeName) {
    DWORD dwPID = GetProcessIDFromName(exeName);
    if (dwPID) return;
    char szTempPath[MAX_PATH]; GetTempPath(MAX_PATH, szTempPath);
    HANDLE hFile = CreateFile(strcat(szTempPath, exeName), GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { SetWindowText(TxOut, "创建失败"); return; }
    HRSRC hResInfo = FindResource(NULL, MAKEINTRESOURCE(resId), RT_RCDATA);
    HGLOBAL hResData = LoadResource(NULL, hResInfo);
    DWORD dwSize = SizeofResource(NULL, hResInfo);
    LPVOID pData = LockResource(hResData);
    if (pData) {
        if (!WriteFile(hFile, pData, dwSize + 1, NULL, NULL)) { SetWindowText(TxOut, "写入失败"); CloseHandle(hFile); return; }
        FlushFileBuffers(hFile); CloseHandle(hFile);
        if (WinExec(szTempPath, SW_SHOW) < 32) SetWindowText(TxOut, "启动失败");
        else SetWindowText(TxOut, "执行完成");
    } else { SetWindowText(TxOut, "写入失败"); CloseHandle(hFile); }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
    switch (Message) {
        case WM_CREATE: {
            OSVERSIONINFO vi = {sizeof(OSVERSIONINFO)}; GetVersionEx(&vi);
            SYSTEM_INFO si = {}; GetNativeSystemInfo(&si);
            char szVersion[BUFSIZ] = {};
            sprintf(szVersion, "系统版本：%u.%u.%u %d-bit\n程序版本：%s %d-bit\n",
                vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber,
                (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) ? 64 : 32, "2.0.0", sizeof(PVOID)*8);
            sOutPut += szVersion;
            EnableDebugPrivilege();
            w = GetSystemMetrics(SM_CXSCREEN) - 1; h = GetSystemMetrics(SM_CYSCREEN) - 1;
            WM_TASKBAR = RegisterWindowMessage("TaskbarCreated");
            thread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
            keyHook = CreateThread(NULL, 0, KeyHookThreadProc, NULL, CREATE_SUSPENDED, NULL);
            mouHook = CreateThread(NULL, 0, MouseHookThreadProc, NULL, CREATE_SUSPENDED, NULL);
            SetTimer(hwnd, 1, 1000, NULL); SetTimer(hwnd, 2, 2000, NULL);
            RegisterHotKey(hwnd, 0, MOD_ALT, 'C'); RegisterHotKey(hwnd, 1, MOD_ALT, 'W');
            if (!RegisterHotKey(hwnd, 2, MOD_ALT, 'B'))
                if (MessageBox(hwnd, "注册系统级热键 Alt+B 失败，有可能该应用的另一实例还在运行，请先关闭它再重新启动本程序！否则唤出窗口功能将失效！若点击「取消」则阻止程序继续启动",
                    "极 域 工 具 包", MB_OKCANCEL | MB_ICONWARNING) == IDCANCEL) { PostQuitMessage(0); return FALSE; }

            HINSTANCE hi = ((LPCREATESTRUCT)lParam)->hInstance;
            int L = 12, R = 330, LW = 310, RW = 290, y;

            TxLnk = CreateWindow("SysLink", "极域工具包 <a href=\"https://github.com/BengbuGuards/MythwareToolkit\">GitHub</a>",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP, L + 2, 6, 220, 22, hwnd, HMENU(1001), hi, NULL);
            BtAbt = CreateWindow(WC_BUTTON, "关于/帮助", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                R + RW - 100, 2, 100, 28, hwnd, HMENU(1002), hi, NULL);

            char str[BUFSIZ] = {}; LPCSTR psd;
            if (!GetMythwarePasswordFromRegedit(str)) psd = "获取密码失败"; else psd = str;
            CreateWindow(WC_STATIC, "极域密码:", WS_CHILD | WS_VISIBLE, L + 2, 32, 56, 22, hwnd, NULL, hi, NULL);
            CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, psd, WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_READONLY,
                L + 62, 30, LW - 68, 22, hwnd, HMENU(1003), hi, NULL);

            y = 58;
            CreateWindow(WC_BUTTON, "极域控制", WS_CHILD | WS_VISIBLE | BS_GROUPBOX, L, y, LW, 138, hwnd, NULL, hi, NULL);
            BtKmw = CreateWindow(WC_BUTTON, "杀掉极域", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_SPLITBUTTON,
                L + 8, y + 16, LW - 16, 40, hwnd, HMENU(1004), hi, NULL);
            CreateWindow(WC_BUTTON, "广播窗口化", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | WS_DISABLED,
                L + 8, y + 64, 144, 30, hwnd, HMENU(1014), hi, NULL);
            CreateWindow(WC_BUTTON, "动态密码计算器", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                L + 158, y + 64, 144, 30, hwnd, HMENU(1015), hi, NULL);

            y = 58; int gap = RW - 16 - 134*2;
            CreateWindow(WC_BUTTON, "高级工具", WS_CHILD | WS_VISIBLE | BS_GROUPBOX, R, y, RW, 138, hwnd, NULL, hi, NULL);
            CreateWindow(WC_BUTTON, "一键解禁系统程序", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, R + 8, y + 16, 134, 30, hwnd, HMENU(1007), hi, NULL);
            CreateWindow(WC_BUTTON, "重启资源管理器", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, R + 8 + 134 + gap, y + 16, 134, 30, hwnd, HMENU(1010), hi, NULL);
            CreateWindow(WC_BUTTON, "解除极域网络限制", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, R + 8, y + 54, 134, 30, hwnd, HMENU(1008), hi, NULL);
            CreateWindow(WC_BUTTON, "解除极域U盘限制", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, R + 8 + 134 + gap, y + 54, 134, 30, hwnd, HMENU(1009), hi, NULL);
            CreateWindow(WC_BUTTON, "MeltdownDFC", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, R + 8, y + 92, 134, 24, hwnd, HMENU(1019), hi, NULL);
            CreateWindow(WC_BUTTON, "crdisk", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, R + 8 + 134 + gap, y + 92, 134, 24, hwnd, HMENU(1020), hi, NULL);

            y = 246; int totalW = LW + RW + 8;
            CreateWindow(WC_BUTTON, "功能开关", WS_CHILD | WS_VISIBLE | BS_GROUPBOX, L, y, totalW, 52, hwnd, NULL, hi, NULL);
            BtTop = CreateWindow(WC_BUTTON, "置顶此窗口", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, L + 14, y + 16, 94, 22, hwnd, HMENU(1016), hi, NULL);
            SendMessage(BtTop, BM_SETCHECK, BST_CHECKED, 0);
            BtCur = CreateWindow(WC_BUTTON, "解鼠标锁(&M)", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, L + 120, y + 16, 92, 22, hwnd, HMENU(1017), hi, NULL);
            BtKbh = CreateWindow(WC_BUTTON, "解键盘锁(&C)", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, L + 224, y + 16, 92, 22, hwnd, HMENU(1018), hi, NULL);
            BtSnp = CreateWindow(WC_BUTTON, "防止截屏", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX | (IsWindows7OrGreater() ? 0 : WS_DISABLED), R + 10, y + 16, 80, 22, hwnd, HMENU(1011), hi, NULL);
            SendMessage(BtSnp, BM_SETCHECK, BST_CHECKED, 0); SendMessage(hwnd, WM_COMMAND, 1011, 0);
            BtWnd = CreateWindow(WC_BUTTON, "启用鼠标检测弹窗", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, R + 100, y + 16, 170, 22, hwnd, HMENU(1012), hi, NULL);

            CreateWindow(WC_BUTTON, "杀掉学生机房管理助手", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, L, 196, totalW, 44, hwnd, HMENU(1013), hi, NULL);

            TxOut = CreateWindow(STATUSCLASSNAME, "等待操作", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, HMENU(1005), hi, NULL);
            int pts[2] = {420, -1}; SendMessage(TxOut, SB_SETPARTS, WPARAM(2), LPARAM(pts));

            HWND hToolTip = CreateWindowEx(WS_EX_TOPMOST, TOOLTIPS_CLASS, NULL, WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
                CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hwnd, NULL, hi, NULL);
            TOOLINFO ti = {sizeof(ti)}; ti.uFlags = TTF_IDISHWND | TTF_SUBCLASS; ti.hwnd = hwnd; ti.uId = (UINT_PTR)TxOut;
            ti.lpszText = const_cast<char*>(GetRunLevelString());
            SendMessage(hToolTip, TTM_ADDTOOL, 0, (LPARAM)&ti);

            NONCLIENTMETRICS info; info.cbSize = sizeof(NONCLIENTMETRICS);
            if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, 0, &info, 0)) hFont = CreateFontIndirect((LOGFONT*)&info.lfMessageFont);
            EnumChildWindows(hwnd, SetWindowFont, LPARAM(hFont));
            SetupTrayIcon(hwnd, hi);

            HMENU sys = GetSystemMenu(hwnd, FALSE);
            AppendMenu(sys, MF_STRING, 2, "显示上一次错误(&E)"); AppendMenu(sys, MF_STRING, 4, "显示程序日志(&L)");
            AppendMenu(sys, MF_STRING, 3, "启动任务管理器(&T)"); DrawMenuBar(hwnd);
            focus = GetDlgItem(hwnd, 1013); SetFocus(focus);
            SendMessage(hwnd, WM_TIMER, WPARAM(2), 0);

            HMODULE hook = NULL;
            if (sizeof(PVOID) == 8) {
                hook = GetModuleHandle("LibTDProcHook64.dll"); if (hook) FreeModule(hook);
                hook = GetModuleHandle("LibTDMaster64.dll"); if (hook) FreeModule(hook);
            } else {
                hook = GetModuleHandle("LibTDProcHook32.dll"); if (hook) FreeModule(hook);
                hook = GetModuleHandle("LibTDMaster32.dll"); if (hook) FreeModule(hook);
            }
            break;
        }

        case WM_INITMENU: { HMENU sys = GetSystemMenu(hwnd, FALSE); SetMenuDefaultItem(sys, SC_MINIMIZE, 0); break; }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case 1002: MessageBox(NULL, helpText, "关于/帮助", MB_OK | MB_ICONINFORMATION); break;
                case 1004: ControlMythware(FALSE); UpdateMythwareStatus(); break;
                case 1007: UnlockSystemPrograms(hwnd); break;
                case 1008: RemoveNetworkRestrictions(); break;
                case 1009: RemoveUSBRestrictions(hwnd); break;
                case 1010: {
                    HWND hShell = FindWindow("Shell_TrayWnd", NULL); DWORD pid;
                    GetWindowThreadProcessId(hShell, &pid);
                    if (pid == 0 || hShell == NULL) { WinExec("explorer.exe", SW_SHOW); break; }
                    HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                    if (TerminateProcess(handle, 2)) SetWindowText(TxOut, "执行成功");
                    else { ge; SetWindowText(TxOut, "执行失败"); }
                    CloseHandle(handle); break;
                }
                case 1013: KillStudentAssistant(); break;
                case 1011: { LRESULT check = SendMessage(BtSnp, BM_GETCHECK, 0, 0); SetWindowDisplayAffinity(hwnd, check == BST_CHECKED ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE); break; }
                case 1012: { LRESULT check = SendMessage(BtWnd, BM_GETCHECK, 0, 0); ask = check == BST_CHECKED; break; }
                case 1014: ToggleBroadcastWindow(); UpdateMythwareStatus(); break;
                case 1015: ShowPsdWnd(); break;
                case 1016: { LRESULT check = SendMessage(BtTop, BM_GETCHECK, 0, 0); if (check == BST_CHECKED) ResumeThread(thread); else { SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE); SuspendThread(thread); } break; }
                case 1017: { LRESULT check = SendMessage(BtCur, BM_GETCHECK, 0, 0); if (check == BST_CHECKED) ResumeThread(mouHook); else { SuspendThread(mouHook); UnhookWindowsHookEx(mseHook); } break; }
                case 1018: {
                    LRESULT check = SendMessage(BtKbh, BM_GETCHECK, 0, 0);
                    if (check == BST_CHECKED) {
                        ResumeThread(keyHook);
                        HANDLE hDevice = CreateFile("\\\\.\\TDKeybd", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                        if (GetLastError()) { PrtError(GetLastError() == ERROR_FILE_NOT_FOUND ? "解键盘锁失败：极域未安装" : "解键盘锁：打开设备失败", GetLastError()); break; }
                        BOOL bEnable = TRUE;
                        if (DeviceIoControl(hDevice, 0x220000, &bEnable, 4, NULL, 0, NULL, NULL)) Print("解键盘锁：发送控制码成功");
                        else PrtError("解键盘锁：发送控制码失败", GetLastError());
                        CloseHandle(hDevice);
                    } else { SuspendThread(keyHook); UnhookWindowsHookEx(kbdHook); }
                    break;
                }
                case 1019: RunEmbeddedExe(2, "\\MeltdownDFC.exe"); break;
                case 1020: RunEmbeddedExe(3, "\\crdisk.exe"); break;
            }
            return 0;
        }

        case WM_HOTKEY:
            switch (wParam) {
                case 0: if (closingProcess) { closingProcess = false; KillTimer(hwnd, 3); HWND topHwnd = GetForegroundWindow(); DWORD pid; GetWindowThreadProcessId(topHwnd, &pid); if (pid != GetCurrentProcessId()) KillProcess(pid, KILL_FORCE); } else { closingProcess = true; SetTimer(hwnd, 3, GetDoubleClickTime(), NULL); } break;
                case 1: { HWND topHwnd = GetForegroundWindow(); if (!IsHungAppWindow(topHwnd)) ShowWindow(topHwnd, SW_MINIMIZE); break; }
                case 2: ShowWindow(hwnd, SW_SHOWNORMAL); SetForegroundWindow(hwnd); break;
            }
            return 0;

        case WM_TIMER:
            switch (wParam) {
                case 1: if (!asking && ask) {
                    GetCursorPos(&p);
                    if (p.x == 0 && p.y == 0) { asking = true; HWND topHwnd = GetForegroundWindow(); if (MessageBox(hwnd, "检测到鼠标位置变化！是否最小化焦点窗口？", "实时提醒", MB_YESNO | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST) == IDYES) { if (!IsHungAppWindow(topHwnd)) ShowWindow(topHwnd, SW_MINIMIZE); } asking = false; }
                    else if (p.x == w && p.y == 0) { asking = true; HWND topHwnd = GetForegroundWindow(); HHOOK hCBTHook = SetWindowsHookEx(WH_CBT, CBTProc, NULL, GetCurrentThreadId()); int id = MessageBox(hwnd, "检测到鼠标位置变化！是否关闭焦点窗口？", "实时提醒", MB_YESNOCANCEL | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST); UnhookWindowsHookEx(hCBTHook); if (id == IDYES) PostMessage(topHwnd, WM_CLOSE, 0, 0); else if (id == IDNO) { HWND hParent = CreateWindowEx(0, WC_STATIC, "", 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL); SetParent(topHwnd, hParent); ge; PostMessage(hParent, WM_CLOSE, 0, 0); } asking = false; }
                } break;
                case 2: SetWindowText(hwnd, RandomWindowTitle()); UpdateMythwareStatus(); break;
                case 3: closingProcess = false; KillTimer(hwnd, 3); break;
            }
            break;

        case WM_CLOSE: ShowWindow(hwnd, SW_HIDE); return TRUE;

        case WM_DESTROY:
            CloseLogFile();
            UnregisterHotKey(hwnd, 0); UnregisterHotKey(hwnd, 1); UnregisterHotKey(hwnd, 2);
            CloseHandle(thread); CloseHandle(keyHook); CloseHandle(mouHook);
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
            else if (lParam == WM_RBUTTONUP) { GetCursorPos(&pt); SetForegroundWindow(hwnd); HMENU hPopup = CreatePopupMenu(); AppendMenu(hPopup, MF_STRING, 1, "关闭程序"); AppendMenu(hPopup, MF_STRING, 2, "打开窗口"); int i = TrackPopupMenu(hPopup, TPM_RETURNCMD, pt.x, pt.y, 0, hwnd, NULL); if (i == 1) { DestroyFloatingWindow(); PostQuitMessage(0); } else if (i == 2) { ShowWindow(hwnd, SW_SHOWNORMAL); SetForegroundWindow(hwnd); } }
            return FALSE;

        case WM_NOTIFY:
            switch (((LPNMHDR)lParam)->code) {
                case BCN_DROPDOWN: {
                    NMBCDROPDOWN* pDropDown = (NMBCDROPDOWN*)lParam;
                    if (pDropDown->hdr.hwndFrom == BtKmw) {
                        POINT ptBtn; ptBtn.x = pDropDown->rcButton.left; ptBtn.y = pDropDown->rcButton.bottom;
                        ClientToScreen(pDropDown->hdr.hwndFrom, &ptBtn);
                        HMENU hSplitMenu = CreatePopupMenu();
                        AppendMenu(hSplitMenu, MF_BYPOSITION, 1, (mwSts != 1) ? "挂起极域" : "恢复极域");
                        EnableMenuItem(hSplitMenu, 1, mwSts != 2 ? MF_ENABLED : MF_GRAYED);
                        SuspendThread(thread);
                        int i = TrackPopupMenu(hSplitMenu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD, ptBtn.x, ptBtn.y, 0, hwnd, NULL);
                        ResumeThread(thread);
                        if (i == 1) { BOOL sts = SuspendProcess(GetProcessIDFromName(MythwareFilename), !mwSts); SetWindowText(TxOut, sts ? "挂起/恢复成功" : "挂起/恢复失败"); UpdateMythwareStatus(); }
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
                case 2: { if (error == -1) error = GetLastError(); LPSTR szError = NULL; FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, (PTSTR)&szError, 0, NULL); char s[BUFSIZ] = {}; sprintf(s, "GetLastError上一次记录\n%u：%s", error, szError); LocalFree(HLOCAL(szError)); MessageBox(hwnd, s, "上一次错误", MB_OK | MB_ICONINFORMATION); error = -1; break; }
                case 3: { HWND h = FindWindow("TaskManagerWindow", NULL); BYTE nCount = 0; if (!h) { DWORD value = 0; HKEY retKey; RegOpenKeyEx(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey); RegSetValueEx(retKey, "DisableTaskMgr", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD)); RegFlushKey(retKey); RegCloseKey(retKey); WinExec("taskmgr", SW_SHOW); ge; do { if (++nCount == 60) { SetWindowText(TxOut, "启动失败"); return FALSE; } Sleep(50); h = FindWindow("TaskManagerWindow", NULL); } while (!h); } HMENU hm = GetMenu(h); MENUITEMINFO mii = {sizeof(MENUITEMINFO), MIIM_STATE}; GetMenuItemInfo(hm, 0x7704, FALSE, &mii); if (!(mii.fState & MFS_CHECKED)) PostMessage(h, WM_COMMAND, 0x7704, 0); SetWindowText(TxOut, "设置完成"); break; }
                case 4: { char szTempPath[MAX_PATH]; GetTempPath(MAX_PATH, szTempPath); HANDLE hFile = CreateFile(strcat(szTempPath, "\\ToolkitLog.txt"), GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL); WriteFile(hFile, sOutPut.c_str(), sOutPut.size() + 1, NULL, NULL); FlushFileBuffers(hFile); ShellExecute(hwnd, "open", szTempPath, NULL, NULL, SW_SHOW); CloseHandle(hFile); break; }
                case SC_MINIMIZE: SetActiveWindow(hwnd); focus = GetFocus(); break;
            }
            return DefWindowProc(hwnd, Message, wParam, lParam);

        case WM_SIZE: if (wParam == SIZE_MINIMIZED) { ShowWindow(hwnd, SW_HIDE); return TRUE; } break;

        default: if (Message == WM_TASKBAR) Shell_NotifyIcon(NIM_ADD, &icon); return DefWindowProc(hwnd, Message, wParam, lParam);
    }
    return TRUE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    SetUnhandledExceptionFilter(GlobalExceptionHandler);
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    InitNTAPI();

    HANDLE hToken; OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    DWORD dwLength = 0; GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength);
    PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLength);
    if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLength, &dwLength)) {
        DWORD dwLevel = *GetSidSubAuthority(pTIL->Label.Sid, *GetSidSubAuthorityCount(pTIL->Label.Sid) - 1);
        if (dwLevel >= SECURITY_MANDATORY_SYSTEM_RID) eLevel = RL_SYSTEM;
        else if (dwLevel >= SECURITY_MANDATORY_HIGH_RID) eLevel = RL_ADMIN;
        else eLevel = RL_USER;
    } else eLevel = RL_UNKNOWN;

    int argc; bool bStartAsSystem = false;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) { bStartAsSystem = (!_wcsicmp(argv[1], L"-s") || !_wcsicmp(argv[1], L"/s")); LocalFree(argv); }
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
        else MessageBox(NULL, "无法以系统权限运行，将以普通方式运行。欲知详细信息请查看上一次错误", "极域工具包", MB_ICONERROR | MB_OK);
    }

    WNDCLASSEX wc; MSG msg; memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(WNDCLASSEX); wc.lpfnWndProc = WndProc; wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = (HBRUSH)COLOR_WINDOW;
    wc.lpszClassName = "WindowClass"; wc.hIcon = LoadIcon(hInstance, "MAINICON"); wc.hIconSm = LoadIcon(hInstance, "MAINICON");
    if (!RegisterClassEx(&wc)) { MessageBox(NULL, "窗口类注册失败！请重试", "极 域 工 具 包", MB_ICONEXCLAMATION | MB_OK); return 0; }

    hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, "WindowClass", RandomWindowTitle(), (WS_OVERLAPPEDWINDOW | WS_VISIBLE) ^ WS_MAXIMIZEBOX ^ WS_SIZEBOX, 0, 0, width, height, NULL, NULL, hInstance, NULL);
    if (hwnd == NULL) { MessageBox(NULL, "窗口创建失败！请重试", "极 域 工 具 包", MB_ICONEXCLAMATION | MB_OK); return 0; }

    ShowWindow(hwnd, nCmdShow); UpdateWindow(hwnd);
    InitLogFile();
    CreateFloatingWindow(hInstance);

    while (GetMessage(&msg, NULL, 0, 0) > 0) { if (!IsDialogMessage(hwnd, &msg)) { TranslateMessage(&msg); DispatchMessage(&msg); } }
    CoUninitialize();
    return msg.wParam;
}
