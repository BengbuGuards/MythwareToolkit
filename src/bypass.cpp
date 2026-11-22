// bypass.cpp — 注册表解禁、网络/USB限制解除
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

// 读取一个 REG_DWORD；键值不存在、类型不符都当作“没有设置”
// 注意 RegQueryValueEx 的 lpcbData 是【入/出】参数：入参必须是缓冲区真实大小。
// v1.3.1 这里传的是未初始化的栈变量，一旦系统返回的字符串比 DWORD 长就会写穿栈，
// 是 Win7 上 0xC0000005 崩溃的根源之一。
static bool QueryDwordValue(HKEY key, LPCSTR name, DWORD* out) {
    DWORD type = 0, cb = sizeof(DWORD), value = 0;
    LONG ret = RegQueryValueEx(key, name, NULL, &type, (LPBYTE)&value, &cb);
    if (ret != ERROR_SUCCESS || type != REG_DWORD) return false;
    if (cb > sizeof(DWORD)) return false;
    *out = value;
    return true;
}

void UnlockSystemPrograms(HWND hwnd) {
    LOG_INFO("UnlockSystemPrograms start");
    BYTE cStatus = 0; LONG ret;
    DWORD out = 0;
    char szPath[BUFSIZ], outputBuf[BUFSIZ];
    std::string sMsg = AS("操作完成！已解禁以下项目：");
    const std::string sep = AS("、");

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
    for (const auto& p : paths) {
        // RegOpenKeyEx 失败时 retKey 是未初始化的垃圾值，绝不能拿去查询/关闭
        HKEY retKey = NULL;
        if (RegOpenKeyEx(HKEY_CURRENT_USER, p.first, 0,
                         KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey) != ERROR_SUCCESS) {
            LOG_INFO("Unlock: open HKCU\\%s failed", p.first);
            continue;
        }
        for (const auto& v : p.second) {
            DWORD value = 0;
            if (!QueryDwordValue(retKey, v.first, &out)) continue;
            if (out) {
                ret = RegSetValueEx(retKey, v.first, 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
                if (ret == ERROR_SUCCESS) { cStatus = 1; sprintf(outputBuf, UA("解除%s成功"), UA(v.second)); Println(outputBuf); sMsg += AS(v.second); sMsg += sep; }
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
    for (const auto& p : paths2) {
        HKEY retKey = NULL;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, p.first, 0,
                         KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey) != ERROR_SUCCESS) {
            LOG_INFO("Unlock: open HKLM\\%s failed", p.first);
            continue;
        }
        for (const auto& v : p.second) {
            DWORD value = 3;
            if (!QueryDwordValue(retKey, v.first, &out)) continue;
            if (out == 4) {
                ret = RegSetValueEx(retKey, v.first, 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
                if (ret == ERROR_SUCCESS) { cStatus = 1; sprintf(outputBuf, UA("解除%s成功"), UA(v.second)); Println(outputBuf); sMsg += AS(v.second); sMsg += sep; }
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
    for (const auto& p : images) {
        sprintf(szPath, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s", p.first);
        HKEY retKey = NULL;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szPath, 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey) != ERROR_SUCCESS)
            continue;
        if (RegDeleteValue(retKey, "debugger") == ERROR_SUCCESS) {
            cStatus = 1; sprintf(outputBuf, UA("解除%s成功"), UA(p.second)); Println(outputBuf); sMsg += AS(p.second); sMsg += sep;
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
    for (const auto& p : deletePaths) {
        HKEY retKey = NULL;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, p.first, 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey) != ERROR_SUCCESS)
            continue;
        for (const auto& v : p.second) {
            if (RegDeleteValue(retKey, v.first) == ERROR_SUCCESS) { cStatus = 1; sprintf(outputBuf, UA("解除%s成功"), UA(v.second)); Println(outputBuf); sMsg += AS(v.second); sMsg += sep; }
        }
        RegCloseKey(retKey);
    }

    HKEY retKey = NULL;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Internet Explorer\\Restrictions", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey) == ERROR_SUCCESS) {
        if (RegDeleteValue(retKey, "NoBrowserSaveAs") == ERROR_SUCCESS) { Println(UA("解除IE另存为成功")); sMsg += AS("IE另存为"); sMsg += sep; cStatus = 1; }
        RegCloseKey(retKey);
    }

    retKey = NULL;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey) == ERROR_SUCCESS) {
        if (RegDeleteValue(retKey, "ShowTaskViewButton") == ERROR_SUCCESS) { Println(UA("解除任务视图按钮成功")); sMsg += AS("任务视图按钮"); sMsg += sep; cStatus = 1; }
        RegCloseKey(retKey);
    }

    retKey = NULL;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey) == ERROR_SUCCESS) {
        if (RegDeleteValue(retKey, "Scancode Map") == ERROR_SUCCESS) { Println(UA("解除键盘映射成功")); sMsg += AS("Tab键（键盘映射）"); sMsg += sep; cStatus = 1; }
        RegCloseKey(retKey);
    }

    // ── hosts：去掉 127.0.0.1 重定向 ──
    // 先整体读入内存、过滤完再写临时文件、最后用 MoveFileEx 原子替换。
    // 旧实现边读边写、WriteFile 不传“已写字节数”、失败也照样删原文件，容易把 hosts 弄坏。
    const char* path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    HANDLE hFile = CreateFile(path, GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_WARN("Unlock: open hosts failed: err=%lu", GetLastError());
    } else {
        std::string hosts;
        char buf[4096];
        DWORD read = 0;
        while (ReadFile(hFile, buf, sizeof(buf), &read, NULL) && read > 0)
            hosts.append(buf, read);
        CloseHandle(hFile);

        std::string filtered;
        bool bHandled = false;
        size_t pos = 0;
        while (pos < hosts.size()) {
            size_t nl   = hosts.find('\n', pos);
            size_t next = (nl == std::string::npos) ? hosts.size() : nl + 1;
            const char* begin = hosts.data() + pos;
            size_t len = next - pos;
            size_t first = 0;
            while (first < len && (begin[first] == ' ' || begin[first] == '\t')) ++first;
            if (len - first >= 9 && memcmp(begin + first, "127.0.0.1", 9) == 0) {
                bHandled = true;                    // 极域加的本地重定向，丢掉
            } else {
                filtered.append(begin, len);
                if (nl == std::string::npos) filtered += '\n';
            }
            pos = next;
        }

        if (bHandled) {
            std::string tempPath = std::string(path) + ".tmp";
            HANDLE hTemp = CreateFile(tempPath.c_str(), GENERIC_WRITE, 0, NULL,
                                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hTemp == INVALID_HANDLE_VALUE) {
                LOG_WARN("Unlock: create %s failed: err=%lu", tempPath.c_str(), GetLastError());
            } else {
                DWORD written = 0;
                BOOL ok = WriteFile(hTemp, filtered.data(), (DWORD)filtered.size(), &written, NULL);
                FlushFileBuffers(hTemp);
                CloseHandle(hTemp);
                if (ok && written == filtered.size()) {
                    SetFileAttributes(path, FILE_ATTRIBUTE_NORMAL);
                    if (MoveFileEx(tempPath.c_str(), path, MOVEFILE_REPLACE_EXISTING)) {
                        LOG_INFO("Unlock: hosts rewritten (%lu -> %lu bytes)",
                                 (unsigned long)hosts.size(), (unsigned long)filtered.size());
                        cStatus = 1; sMsg += AS("网站限制"); sMsg += sep;
                    } else {
                        LOG_WARN("Unlock: MoveFileEx failed: err=%lu", GetLastError());
                        DeleteFile(tempPath.c_str());
                    }
                } else {
                    LOG_WARN("Unlock: write hosts.tmp failed (ok=%d, %lu/%lu)", (int)ok,
                             (unsigned long)written, (unsigned long)filtered.size());
                    DeleteFile(tempPath.c_str());
                }
            }
        }
    }

    SetWindowText(TxOut, UA("设置成功"));
    if (cStatus) {
        // 去掉末尾的分隔符：按字节 pop_back 会在非 GBK 代码页下切坏汉字
        if (sMsg.size() >= sep.size() &&
            sMsg.compare(sMsg.size() - sep.size(), sep.size(), sep) == 0)
            sMsg.resize(sMsg.size() - sep.size());
        sMsg += AS("。");
        sMsg += AS("请重启资源管理器以应用一些功能，如需恢复Tab键请注销后重新登录。");
        MessageBox(NULL, sMsg.c_str(), UA("说明"), MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
    }
    LOG_INFO("UnlockSystemPrograms done, changed=%d", (int)cStatus);
}

void RemoveNetworkRestrictions() {
    LOG_INFO("RemoveNetworkRestrictions start");
    // 步骤1：通过设备驱动解除网络限制
    HANDLE hNetFilter = CreateFile("\\\\.\\TDNetFilter", GENERIC_READ | GENERIC_WRITE,
                                    FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hNetFilter != INVALID_HANDLE_VALUE) {
        LOG_INFO("TDNetFilter device opened OK");
        DWORD bytesReturned = 0;
        if (DeviceIoControl(hNetFilter, 0x120014, NULL, 0, NULL, 0, &bytesReturned, NULL))
            Print(UA("解除网络限制：发送停止指令成功"));
        else
            PrtError(UA("解除网络限制：发送停止指令"), GetLastError());
        CloseHandle(hNetFilter);
    } else {
        LOG_WARN("TDNetFilter device open failed: err=%lu", GetLastError());
        PrtError(UA("解除网络限制：打开设备"), GetLastError());
    }
    // 步骤2：杀掉相关进程
    bool bStateM = KillProcess(GetProcessIDFromName("MasterHelper.exe"), KILL_DEFAULT);
    bool bStateG = KillProcess(GetProcessIDFromName("GATESRV.exe"), KILL_DEFAULT);
    LOG_INFO("Kill MasterHelper=%d GATESRV=%d", bStateM, bStateG);
    std::string text = AS("解除网络限制：停止相关进程");
    Println((text + AS(bStateM && bStateG ? "成功" : "失败")).c_str());
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
    text = AS("解除网络限制：停止限网驱动");
    Println((text + AS(bStateM ? "成功" : "失败")).c_str());
    SetWindowText(TxOut, UA("设置完成"));
}

void RemoveUSBRestrictions(HWND hwnd) {
    HHOOK hCBTHook = SetWindowsHookEx(WH_CBT, CBTProc, NULL, GetCurrentThreadId());
    int id = MessageBox(hwnd, UA("请选择关闭USB锁的模式！\n软解禁：向过滤端口发送停止请求\n硬解禁：直接删除过滤驱动，软解禁方案无效时使用！"),
                        "USB Setting", MB_YESNOCANCEL | MB_ICONQUESTION | MB_SETFOREGROUND);
    UnhookWindowsHookEx(hCBTHook);
    if (id == IDYES) {
        LoadFltLib();
        if (!pFilterConnect || !pFilterSend) { SetWindowText(TxOut, UA("设置失败：系统不支持")); return; }
        HANDLE hPort = NULL;
        HRESULT hResult = pFilterConnect(L"\\TDFileFilterPort", 0, NULL, 0, NULL, &hPort);
        if (hResult || hPort <= (HANDLE)0 || GetLastError()) { error = hResult & 0x0000FFFF; SetWindowText(TxOut, UA("设置失败")); return; }
        int lpInBuffer[4] = {8, 0, 0, 0};
        hResult = pFilterSend(hPort, lpInBuffer, 16, NULL, 0, NULL);
        ge; CloseHandle(hPort);
        SetWindowText(TxOut, !hResult ? UA("设置完成") : UA("设置失败"));
    } else if (id == IDNO) {
        SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        SC_HANDLE hFilt = OpenService(sc, "TDFileFilter", SERVICE_STOP | DELETE);
        SERVICE_STATUS ss = {};
        if (ControlService(hFilt, SERVICE_CONTROL_STOP, &ss)) SetWindowText(TxOut, UA("设置成功"));
        else { ge; SetWindowText(TxOut, UA("设置失败")); }
        DeleteService(hFilt); CloseServiceHandle(sc); CloseServiceHandle(hFilt);
    }
}
