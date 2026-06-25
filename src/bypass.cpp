#include "globals.h"

// ── FltLib 动态加载（避免启动时依赖 FltLib.dll）────────────
typedef HRESULT (WINAPI *PFN_FilterConnectCommunicationPort)(
    LPCWSTR, DWORD, LPCVOID, DWORD, LPVOID, HANDLE*);
typedef HRESULT (WINAPI *PFN_FilterSendMessage)(
    HANDLE, LPVOID, DWORD, LPVOID, DWORD, LPDWORD);

static PFN_FilterConnectCommunicationPort pFilterConnect = NULL;
static PFN_FilterSendMessage          pFilterSend    = NULL;
static HMODULE                         hFltLib        = NULL;

static void LoadFltLib() {
    if (hFltLib) return;
    hFltLib = LoadLibrary("FltLib.dll");
    if (hFltLib) {
        pFilterConnect = (PFN_FilterConnectCommunicationPort)
            GetProcAddress(hFltLib, "FilterConnectCommunicationPort");
        pFilterSend = (PFN_FilterSendMessage)
            GetProcAddress(hFltLib, "FilterSendMessage");
    }
}

void UnlockSystemPrograms(HWND hwnd) {
    BYTE cStatus = 0; HKEY retKey; LONG ret;
    DWORD value = 0, out = 0, cb;
    char szPath[BUFSIZ], outputBuf[BUFSIZ];
    std::string sMsg = "操作完成！已解禁以下项目：";

    static const std::pair<LPCSTR, std::vector<std::pair<LPCSTR, LPCSTR>>> paths[] = {
        {"SOFTWARE\\Policies\\Microsoft\\Windows\\System", {{"DisableCMD","命令提示符"}}},
        {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", {
            {"DisableRegistryTools","注册表编辑器"}, {"DisableTaskMgr","任务管理器"},
            {"DisableLockWorkstation","锁定账户"}, {"DisableChangePassword","修改密码"},
            {"DisableSwitchUserOption","切换用户"}}},
        {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", {
            {"NoRun","Win+R运行"}, {"RestrictRun","限制程序运行"}, {"NoLogOff","注销"},
            {"StartMenuLogOff","开始菜单注销按钮"}, {"NoTrayContextMenu","托盘右键菜单"},
            {"Hidden","强制显示隐藏文件"}, {"NoFolderOptions","文件夹选项"}}},
        {"SOFTWARE\\Policies\\Microsoft\\MMC", {{"RestrictToPermittedSnapins","微软管理控制台"}}},
        {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3", {
            {"1803","IE下载限制"}, {"2200","IE ActiveX控件"}}}
    };
    for (auto p : paths) {
        RegOpenKeyEx(HKEY_CURRENT_USER, p.first, 0, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
        for (auto v : p.second) {
            ret = RegQueryValueEx(retKey, v.first, 0, NULL, (BYTE*)&out, &cb);
            if (out) {
                ret &= RegSetValueEx(retKey, v.first, 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
                if (ret == ERROR_SUCCESS) { cStatus = 1; sprintf(outputBuf, "解除%s成功", v.second); Println(outputBuf); sMsg += v.second; sMsg += "、"; }
            }
        }
        RegCloseKey(retKey);
    }

    static const std::pair<LPCSTR, std::vector<std::pair<LPCSTR, LPCSTR>>> paths2[] = {
        {"SYSTEM\\CurrentControlSet\\Services\\usbstor", {{"Start","USB限制（当前控制集）"}}},
        {"SYSTEM\\ControlSet001\\Services\\usbstor", {{"Start","USB限制（控制集1）"}}},
        {"SYSTEM\\ControlSet002\\Services\\usbstor", {{"Start","USB限制（控制集2）"}}},
        {"SYSTEM\\ControlSet003\\Services\\usbstor", {{"Start","USB限制（控制集3）"}}},
    };
    value = 3;
    for (auto p : paths2) {
        RegOpenKeyEx(HKEY_LOCAL_MACHINE, p.first, 0, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
        for (auto v : p.second) {
            ret = RegQueryValueEx(retKey, v.first, 0, NULL, (BYTE*)&out, &cb);
            if (out == 4) {
                ret &= RegSetValueEx(retKey, v.first, 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
                if (ret == ERROR_SUCCESS) { cStatus = 1; sprintf(outputBuf, "解除%s成功", v.second); Println(outputBuf); sMsg += v.second; sMsg += "、"; }
            }
        }
        RegCloseKey(retKey);
    }

    static const std::pair<LPCSTR, LPCSTR> images[] = {
        {"taskkill.exe","taskkill"}, {"ntsd.exe","ntsd"}, {"tasklist.exe","tasklist"},
        {"sethc.exe","粘滞键快捷键（sethc.exe）"}, {"sidebar.exe","Win7边栏"},
        {"Chess.exe","Win7象棋"}, {"FreeCell.exe","Win7空当接龙"}, {"Hearts.exe","Win7红心大战"},
        {"Minesweeper.exe","扫雷"}, {"PurblePlace.exe","Win7 Purble Place"},
        {"Mahjong.exe","Win7麻将"}, {"SpiderSolitaire.exe","Win7蜘蛛纸牌"},
        {"bckgzm.exe","Internet双陆棋"}, {"chkrzm.exe","Internet跳棋"}, {"shvlzm.exe","Internet黑白棋"},
        {"Solitaire.exe","Win7纸牌"}, {"winmine.exe","扫雷（winmine.exe）"},
        {"Magnify.exe","放大镜"}, {"QQPCTray.exe","QQPCTray"}
    };
    for (auto p : images) {
        strcpy(szPath, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\");
        strcat(szPath, p.first);
        RegOpenKeyEx(HKEY_LOCAL_MACHINE, szPath, 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
        if (RegDeleteValue(retKey, "debugger") == ERROR_SUCCESS) {
            cStatus = 1; sprintf(outputBuf, "解除%s成功", p.second); Println(outputBuf); sMsg += p.second; sMsg += "、";
        }
        RegCloseKey(retKey);
    }

    static const std::pair<LPCSTR, std::vector<std::pair<LPCSTR, LPCSTR>>> deletePaths[] = {
        {"SOFTWARE\\Policies\\Google\\Chrome", {{"AllowDinosaurEasterEgg","Chrome恐龙游戏"}, {"DownloadRestrictions","Chrome下载限制"}, {"SaveAs","Chrome另存为"}, {"DeveloperToolsAvailability","Chrome开发者工具"}}},
        {"SOFTWARE\\Policies\\Microsoft\\Edge", {{"AllowSurfGame","Edge冲浪游戏"}, {"WebWidgetAllowed","Edge边栏"}, {"DownloadRestrictions","Edge下载限制"}, {"SaveAs","Edge另存为"}, {"DeveloperToolsAvailability","Edge开发者工具"}}},
        {"SOFTWARE\\Policies\\Mozilla\\Firefox", {{"DisableDownloads","Firefox下载限制1"}, {"BlockAboutDownloads","Firefox下载限制2"}, {"DeveloperToolsAvailability","Firefox开发者工具"}}},
        {"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", {{"AllowMultipleTSSessions","多终端服务会话"}}},
        {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", {{"HideFastUserSwitching","快速用户切换"}}},
        {"SOFTWARE\\Policies\\Microsoft\\WindowsStore", {{"RemoveWindowsStore","Windows应用商店"}}},
    };
    for (auto p : deletePaths) {
        RegOpenKeyEx(HKEY_LOCAL_MACHINE, p.first, 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
        for (auto v : p.second) {
            if (RegDeleteValue(retKey, v.first) == ERROR_SUCCESS) { cStatus = 1; sprintf(outputBuf, "解除%s成功", v.second); Println(outputBuf); sMsg += v.second; sMsg += "、"; }
        }
        RegCloseKey(retKey);
    }

    RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Internet Explorer\\Restrictions", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
    if (RegDeleteValue(retKey, "NoBrowserSaveAs") == ERROR_SUCCESS) { Println("解除IE另存为成功"); sMsg += "IE另存为、"; cStatus = 1; }
    RegCloseKey(retKey);

    RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
    if (RegDeleteValue(retKey, "ShowTaskViewButton") == ERROR_SUCCESS) { Println("解除任务视图按钮成功"); sMsg += "任务视图按钮、"; cStatus = 1; }
    RegCloseKey(retKey);

    RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
    if (RegDeleteValue(retKey, "Scancode Map") == ERROR_SUCCESS) { Println("解除键盘映射成功"); sMsg += "Tab键（键盘映射）、"; cStatus = 1; }
    RegCloseKey(retKey);

    LPCSTR path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    bool bHandled = false;
    HANDLE hFile = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    std::string tempPath = std::string(path) + ".tmp";
    HANDLE hTemp = CreateFile(tempPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE && hTemp != INVALID_HANDLE_VALUE) {
        char buf[4096]; DWORD read; std::string line;
        while (ReadFile(hFile, buf, sizeof(buf), &read, NULL) && read > 0) {
            for (DWORD i = 0; i < read; ++i) {
                if (buf[i] == '\n') {
                    if (line.find("127.0.0.1") != 0 || line.find_first_not_of(" \t") < line.find("127.0.0.1"))
                    { line += '\n'; WriteFile(hTemp, line.c_str(), line.size(), NULL, NULL); }
                    else bHandled = true;
                    line.clear();
                } else line += buf[i];
            }
        }
        if (!line.empty()) {
            if (line.find("127.0.0.1") != 0 || line.find_first_not_of(" \t") < line.find("127.0.0.1"))
                WriteFile(hTemp, line.c_str(), line.size(), NULL, NULL);
            else bHandled = true;
        }
        CloseHandle(hFile); CloseHandle(hTemp);
        SetFileAttributes(path, FILE_ATTRIBUTE_NORMAL); DeleteFile(path);
        if (bHandled && MoveFile(tempPath.c_str(), path)) { cStatus = 1; sMsg += "网站限制、"; }
    }

    SetWindowText(TxOut, "设置成功");
    if (cStatus) {
        sMsg.pop_back(); sMsg.pop_back(); sMsg += "。";
        sMsg += "请重启资源管理器以应用一些功能，如需恢复Tab键请注销后重新登录。";
        MessageBox(hwnd, sMsg.c_str(), "说明", MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
    }
}

void RemoveNetworkRestrictions() {
    LOG_INFO("RemoveNetworkRestrictions start");
    // 步骤1：通过设备驱动解除网络限制
    HANDLE hNetFilter = CreateFile("\\\\.\\TDNetFilter", GENERIC_READ | GENERIC_WRITE,
                                    FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hNetFilter != INVALID_HANDLE_VALUE) {
        LOG_INFO("TDNetFilter device opened OK");
        DeviceIoControl(hNetFilter, 0x120014, NULL, 0, NULL, 0, NULL, 0);
        PrtError("解除网络限制：发送停止指令", GetLastError());
        CloseHandle(hNetFilter);
    } else {
        LOG_WARN("TDNetFilter device open failed: err=%lu", GetLastError());
        PrtError("解除网络限制：打开设备", GetLastError());
    }
    // 步骤2：杀掉相关进程
    bool bStateM = KillProcess(GetProcessIDFromName("MasterHelper.exe"), KILL_DEFAULT);
    bool bStateG = KillProcess(GetProcessIDFromName("GATESRV.exe"), KILL_DEFAULT);
    LOG_INFO("Kill MasterHelper=%d GATESRV=%d", bStateM, bStateG);
    std::string text = "解除网络限制：停止相关进程";
    Println((text + (bStateM && bStateG ? "成功" : "失败")).c_str());
    // 步骤3：停止并删除限网驱动服务
    SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (sc) {
        SC_HANDLE hFilt = OpenService(sc, "TDNetFilter", SERVICE_STOP | DELETE);
        if (hFilt) {
            SERVICE_STATUS ss = {};
            bStateM = ControlService(hFilt, SERVICE_CONTROL_STOP, &ss);
            LOG_INFO("TDNetFilter service stop: %d", bStateM);
            DeleteService(hFilt);
            CloseServiceHandle(hFilt);
        } else {
            LOG_WARN("TDNetFilter service not found: err=%lu", GetLastError());
        }
        CloseServiceHandle(sc);
    } else {
        LOG_WARN("OpenSCManager failed: err=%lu", GetLastError());
    }
    text = "解除网络限制：停止限网驱动";
    Println((text + (bStateM ? "成功" : "失败")).c_str());
    SetWindowText(TxOut, "设置完成");
}

void RemoveUSBRestrictions(HWND hwnd) {
    HHOOK hCBTHook = SetWindowsHookEx(WH_CBT, CBTProc, NULL, GetCurrentThreadId());
    int id = MessageBox(hwnd, "请选择关闭USB锁的模式！\n软解禁：向过滤端口发送停止请求\n硬解禁：直接删除过滤驱动，软解禁方案无效时使用！",
                        "USB Setting", MB_YESNOCANCEL | MB_ICONQUESTION | MB_SETFOREGROUND);
    UnhookWindowsHookEx(hCBTHook);
    if (id == IDYES) {
        LoadFltLib();
        if (!pFilterConnect || !pFilterSend) { SetWindowText(TxOut, "设置失败：系统不支持"); return; }
        HANDLE hPort = NULL;
        HRESULT hResult = pFilterConnect(L"\\TDFileFilterPort", 0, NULL, 0, NULL, &hPort);
        if (hResult || hPort <= (HANDLE)0 || GetLastError()) { error = hResult & 0x0000FFFF; SetWindowText(TxOut, "设置失败"); return; }
        int lpInBuffer[4] = {8, 0, 0, 0};
        hResult = pFilterSend(hPort, lpInBuffer, 16, NULL, 0, NULL);
        ge; CloseHandle(hPort);
        SetWindowText(TxOut, !hResult ? "设置完成" : "设置失败");
    } else if (id == IDNO) {
        SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        SC_HANDLE hFilt = OpenService(sc, "TDFileFilter", SERVICE_STOP | DELETE);
        SERVICE_STATUS ss = {};
        if (ControlService(hFilt, SERVICE_CONTROL_STOP, &ss)) SetWindowText(TxOut, "设置成功");
        else { ge; SetWindowText(TxOut, "设置失败"); }
        DeleteService(hFilt); CloseServiceHandle(sc); CloseServiceHandle(hFilt);
    }
}
