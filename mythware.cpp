#include "globals.h"

static constexpr LPCSTR sBdCst[2] = {"屏幕广播", " 窗口化屏幕"};

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
        if (_stricmp(szName, sBdCst[0]) == 0 ||
            _stricmp(szName + nLength - strlen(sBdCst[1]), sBdCst[1]) == 0) {
            info->hwndOfBoardcast = hwnd;
            return FALSE;
        }
    }
    return TRUE;
}

const char* GetRunLevelString() {
    switch (eLevel) {
        case RL_USER:   return "用户权限";
        case RL_ADMIN:  return "管理员权限";
        case RL_SYSTEM: return "系统权限";
        default:        return "权限未知";
    }
}

void UpdateMythwareStatus() {
    DWORD id = GetProcessIDFromName(MythwareFilename);
    if (id == 0) {
        SendMessage(TxOut, SB_SETTEXT, 1, LPARAM("极域未运行"));
        mwSts = 2;
        SetWindowText(BtKmw, "启动极域");
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
        SetDlgItemText(hwnd, 1014, bWindowing ? "广播全屏化" : "广播窗口化");
        mwSts = GetProcessState(id);
        std::string show;
        if (mwSts == -1)                   show = "极域状态未知";
        else if (mwSts == 0 && !info.bNotResponding) show = "极域运行中";
        else if (mwSts == 0 && info.bNotResponding)  show = "极域无响应";
        else if (mwSts == 1)               show = "极域已挂起";
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
        SetWindowText(BtKmw, "杀掉极域");
    }
}

void ToggleBroadcastWindow() {
    LONG lStyle = GetWindowLong(hBdCst, GWL_STYLE);
    BOOL bWindowing = lStyle & (WS_CAPTION | WS_SIZEBOX);
    PostMessage(hBdCst, WM_COMMAND, MAKEWPARAM(1004, BM_CLICK), 0);
    SetWindowText(TxOut, bWindowing ? "全屏化完成" : "窗口化完成");
}

void ControlMythware(BOOL kill) {
    if (mwSts != 2) {
        if (KillProcess(GetProcessIDFromName(MythwareFilename), KILL_FORCE)) {
            SetWindowText(TxOut, "执行成功");
            Sleep(30);
        } else { ge; SetWindowText(TxOut, "执行失败"); }
    } else {
        HKEY retKey; char szPath[MAX_PATH * 2];
        LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\TopDomain\\e-Learning Class Standard\\1.00",
                      0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &retKey);
        if (ret != ERROR_SUCCESS) { ge; SetWindowText(TxOut, "获取路径失败"); RegCloseKey(retKey); return; }
        DWORD dataLong = MAX_PATH * 2, type = REG_SZ;
        ret = RegQueryValueEx(retKey, "TargetDirectory", 0, &type, LPBYTE(szPath), &dataLong);
        RegCloseKey(retKey);
        if (ret != ERROR_SUCCESS) { ge; SetWindowText(TxOut, "获取路径失败"); return; }
        HWND hwndShell = FindWindow("Shell_TrayWnd", NULL); DWORD pid;
        GetWindowThreadProcessId(hwndShell, &pid);
        HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!handle) { SetWindowText(TxOut, "无法获取桌面进程"); return; }
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
        if (bResult) { SetWindowText(TxOut, "启动成功"); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
        else { ge; SetWindowText(TxOut, "启动失败"); }
        CloseHandle(handle); CloseHandle(token);
    }
}
