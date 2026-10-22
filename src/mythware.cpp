// mythware.cpp — 极域进程控制、广播窗口化、黑屏退出
#include "globals.h"

static constexpr LPCSTR sBdCst[2] = {"屏幕广播", " 窗口化屏幕"};

static DWORD FindMythwarePid() {
    DWORD id = GetProcessIDFromName(MythwareFilename);
    if (id) return id;
    static const char* altNames[] = {"StudentM.exe", "StudentMain64.exe", "Student.exe", "MasterHelper.exe", NULL};
    for (int i = 0; altNames[i]; i++) {
        id = GetProcessIDFromName(altNames[i]);
        if (id) return id;
    }
    return 0;
}

BOOL GetMythwarePasswordFromRegedit(char *str) {
    HKEY  retKey;
    BYTE  retKeyVal[MAX_PATH * 2] = {0};
    DWORD nSize = MAX_PATH * 2;
    LONG  ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\TopDomain\\e-Learning Class\\Student",
                    0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &retKey);
    if (ret != ERROR_SUCCESS) return FALSE;
    ret = RegQueryValueExA(retKey, "knock1", NULL, NULL, (LPBYTE)retKeyVal, &nSize);
    RegCloseKey(retKey);
    if (ret != ERROR_SUCCESS) return FALSE;
    for (int i = 0; i < int(nSize); i += 4) {
        retKeyVal[i + 0] = (retKeyVal[i + 0] ^ 0x50 ^ 0x45);
        retKeyVal[i + 1] = (retKeyVal[i + 1] ^ 0x43 ^ 0x4c);
        retKeyVal[i + 2] = (retKeyVal[i + 2] ^ 0x4c ^ 0x43);
        retKeyVal[i + 3] = (retKeyVal[i + 3] ^ 0x45 ^ 0x50);
    }
    int sum = 0;
    for (int i = 0; i < int(nSize); i += 1) {
        if (retKeyVal[i + 1] == 0) {
            *(str + sum) = retKeyVal[i];
            sum++;
            if (retKeyVal[i] == 0) break;
        }
    }
    return TRUE;
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    MW_INFO* info = (MW_INFO*)lParam; DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != info->pid) return TRUE;
    HWND hOwner = GetWindow(hwnd, GW_OWNER);
    LONG l = GetWindowLong(hwnd, GWL_EXSTYLE);
    if ((!hOwner || !IsWindowVisible(hOwner) || (l & WS_EX_APPWINDOW))
        && (l & WS_EX_TOOLWINDOW) == 0 && IsHungAppWindow(hwnd))
        info->bNotResponding = true;
    char szClass[5];
    if (GetClassName(hwnd, szClass, 5) && _stricmp(szClass, "Afx:") == 0) {
        int nLength = GetWindowTextLength(hwnd);
        char szName[nLength + 2];
        GetWindowText(hwnd, szName, nLength + 1);
        // 窗口标题来自 GetWindowTextA（ACP 字节），字面量必须同样转成 ACP 才能比较
        std::string sFull = AS(sBdCst[0]), sTail = AS(sBdCst[1]);
        // nLength 不足 sTail 长度时回退会算出负偏移越界读，必须先判长度
        if (_stricmp(szName, sFull.c_str()) == 0 ||
            (nLength >= (int)sTail.size() &&
             _stricmp(szName + nLength - sTail.size(), sTail.c_str()) == 0)) {
            info->hwndOfBoardcast = hwnd;
            return FALSE;
        }
    }
    return TRUE;
}

std::string GetRunLevelString() {
    switch (eLevel) {
        case RL_USER:   return AS("用户权限");
        case RL_ADMIN:  return AS("管理员权限");
        case RL_SYSTEM: return AS("系统权限");
        default:        return AS("权限未知");
    }
}

void UpdateMythwareStatus() {
    static DWORD s_lastPid   = (DWORD)-1;
    static int   s_lastState = -999;
    static bool  s_lastHung  = false;

    DWORD id = FindMythwarePid();
    bool  bHung = false;
    if (id == 0) {
        SendMessage(TxOut, SB_SETTEXT, 1, LPARAM(UA("极域未运行")));
        mwSts = 2;
        SetWindowText(BtKmw, UA("恢复极域"));
    } else {
        MW_INFO info = {}; info.pid = id;
        BOOL bWindowing = FALSE;
        EnumWindows(EnumWindowsProc, LPARAM(&info));
        hBdCst = info.hwndOfBoardcast;
        if (hBdCst) {
            LONG lStyle = GetWindowLong(hBdCst, GWL_STYLE);
            if (lStyle & WS_SYSMENU) bWindowing = TRUE;
        }
        EnableWindow(GetDlgItem(hwnd, 1014), hBdCst ? TRUE : FALSE);
        SetDlgItemText(hwnd, 1014, bWindowing ? UA("广播全屏化") : UA("广播窗口化"));
        mwSts = GetProcessState(id);
        bHung = info.bNotResponding;
        std::string show;
        if (mwSts == -1)                   show = AS("极域状态未知");
        else if (mwSts == 0 && !info.bNotResponding) show = AS("极域运行中");
        else if (mwSts == 0 && info.bNotResponding)  show = AS("极域无响应");
        else if (mwSts == 1)               show = AS("极域已挂起");
        // 读取极域版本号
        char mwVer[32] = "";
        HKEY hkVer;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\TopDomain\\e-Learning Class Standard\\1.00",
                0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &hkVer) == ERROR_SUCCESS) {
            DWORD sz = sizeof(mwVer);
            RegQueryValueEx(hkVer, "Version", NULL, NULL, (LPBYTE)mwVer, &sz);
            RegCloseKey(hkVer);
        }
        char buf[160];
        sprintf(buf, "%s[PID:%d] v%s", show.c_str(), int(id), mwVer);
        SendMessage(TxOut, SB_SETTEXT, 1, LPARAM(buf));
        SetWindowText(BtKmw, UA("杀掉极域"));
    }

    if (id != s_lastPid || mwSts != s_lastState || bHung != s_lastHung) {
        LOG_INFO("Mythware status changed: pid=%lu state=%d hung=%d",
                 id, mwSts, (int)bHung);
        s_lastPid   = id;
        s_lastState = mwSts;
        s_lastHung  = bHung;
    }
}

void ToggleBroadcastWindow() {
    LOG_INFO("ToggleBroadcastWindow: hBdCst=%p", hBdCst);
    if (!hBdCst) { SetWindowText(TxOut, UA("未找到广播窗口")); return; }
    LONG lStyle = GetWindowLong(hBdCst, GWL_STYLE);
    BOOL bWindowing = lStyle & (WS_CAPTION | WS_SIZEBOX);
    PostMessage(hBdCst, WM_COMMAND, MAKEWPARAM(1004, BM_CLICK), 0);
    SetWindowText(TxOut, bWindowing ? UA("全屏化完成") : UA("窗口化完成"));
}

void ControlMythware(BOOL kill) {
    LOG_INFO("ControlMythware kill=%d mwSts=%d MythwareFilename=%s", kill, mwSts, MythwareFilename);
    if (mwSts != 2) {
        DWORD pid = FindMythwarePid();
        LOG_INFO("ControlMythware: pid=%lu", pid);
        // 同时杀掉守护进程防止自启
        KillProcess(GetProcessIDFromName("MasterHelper.exe"), KILL_FORCE);
        KillProcess(GetProcessIDFromName("GATESRV.exe"), KILL_FORCE);
        Sleep(50);
        if (pid && KillProcess(pid, KILL_FORCE)) {
            SetWindowText(TxOut, UA("执行成功"));
            Sleep(100);
            UpdateMythwareStatus();
        } else { ge; SetWindowText(TxOut, UA("执行失败")); }
    } else {
        HKEY retKey; char szPath[MAX_PATH * 2];
        LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\TopDomain\\e-Learning Class Standard\\1.00",
                      0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &retKey);
        if (ret != ERROR_SUCCESS) { ge; SetWindowText(TxOut, UA("获取路径失败")); RegCloseKey(retKey); return; }
        DWORD dataLong = MAX_PATH * 2, type = REG_SZ;
        ret = RegQueryValueEx(retKey, "TargetDirectory", 0, &type, LPBYTE(szPath), &dataLong);
        RegCloseKey(retKey);
        if (ret != ERROR_SUCCESS) { ge; SetWindowText(TxOut, UA("获取路径失败")); return; }
        HWND hwndShell = FindWindow("Shell_TrayWnd", NULL); DWORD pid;
        GetWindowThreadProcessId(hwndShell, &pid);
        HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!handle) { SetWindowText(TxOut, UA("无法获取桌面进程")); return; }
        HANDLE token;
        OpenProcessToken(handle, TOKEN_DUPLICATE, &token);
        DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &token);
        STARTUPINFO si = {}; PROCESS_INFORMATION pi = {};
        si.cb = sizeof(STARTUPINFO);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOW;
        BOOL bResult = CreateProcessAsUser(token, strcat(szPath, MythwareFilename),
                            NULL, NULL, NULL, FALSE,
                            CREATE_NEW_PROCESS_GROUP | NORMAL_PRIORITY_CLASS,
                            NULL, NULL, &si, &pi);
        if (bResult) {
            SetWindowText(TxOut, UA("启动成功"));
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            Sleep(100); UpdateMythwareStatus();
        }
        else { ge; SetWindowText(TxOut, UA("启动失败")); }
        CloseHandle(handle); CloseHandle(token);
    }
}

// ── 退出黑屏安静：多级递进，尽可能不杀进程 ──
static BOOL CALLBACK FindBlackScreenProc(HWND hWnd, LPARAM lParam) {
    if (!IsWindowVisible(hWnd)) return TRUE;
    LONG ex = GetWindowLong(hWnd, GWL_EXSTYLE);
    if (!(ex & WS_EX_TOPMOST)) return TRUE;
    RECT r; GetWindowRect(hWnd, &r);
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    if (r.right - r.left < sw || r.bottom - r.top < sh) return TRUE;
    *(HWND*)lParam = hWnd;
    return FALSE;
}

void ExitBlackScreen() {
    LOG_INFO("ExitBlackScreen start");
    HWND hBlack = NULL;
    EnumWindows(FindBlackScreenProc, (LPARAM)&hBlack);

    if (!hBlack) {
        LOG_INFO("No black screen window found");
        SetWindowText(TxOut, UA("未检测到黑屏窗口"));
        return;
    }

    // ── 第1级：悄悄隐藏黑窗 ──
    ShowWindow(hBlack, SW_HIDE);
    Sleep(200);
    if (!IsWindowVisible(hBlack)) {
        LOG_INFO("Level 1: black screen hidden (hwnd=%p)", hBlack);
        SetWindowText(TxOut, UA("已隐藏黑屏（第1级）"));
        return;
    }

    // ── 第2级：取消置顶 + 最小化 ──
    LOG_INFO("Level 1 failed, trying level 2");
    SetWindowPos(hBlack, HWND_BOTTOM, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    ShowWindow(hBlack, SW_MINIMIZE);
    Sleep(200);
    if (!IsWindowVisible(hBlack) || IsIconic(hBlack)) {
        LOG_INFO("Level 2: black screen minimized");
        SetWindowText(TxOut, UA("已退出黑屏（第2级）"));
        return;
    }

    // ── 第3级：模拟 ESC 键 ──
    LOG_INFO("Level 2 failed, trying level 3 (ESC)");
    SetForegroundWindow(hBlack);
    Sleep(50);
    keybd_event(VK_ESCAPE, 0, 0, 0);
    keybd_event(VK_ESCAPE, 0, KEYEVENTF_KEYUP, 0);
    Sleep(300);
    if (!IsWindowVisible(hBlack)) {
        LOG_INFO("Level 3: ESC closed black screen");
        SetWindowText(TxOut, UA("已退出黑屏（第3级）"));
        return;
    }

    // ── 第4级：请求用户确认后杀进程 ──
    LOG_INFO("Level 3 failed, asking user for kill permission");
    int id = MessageBox(NULL,
        UA("无法通过常规方式退出黑屏安静。\n\n"
           "是否杀掉极域进程？\n"
           "点是：强制结束极域（教师端会显示学生离线）\n"
           "点否：保持现状"),
        UA("退出黑屏"), MB_YESNO | MB_ICONWARNING | MB_SETFOREGROUND);
    if (id == IDYES) {
        if (KillProcess(GetProcessIDFromName(MythwareFilename), KILL_FORCE)) {
            LOG_INFO("Level 4: killed StudentMain.exe");
            SetWindowText(TxOut, UA("已杀掉极域进程"));
        } else {
            SetWindowText(TxOut, UA("杀进程失败"));
        }
    } else {
        LOG_INFO("User declined kill");
        SetWindowText(TxOut, UA("无法退出黑屏"));
    }
    UpdateMythwareStatus();
}
