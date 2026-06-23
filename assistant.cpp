#include "globals.h"

void KillStudentAssistant() {
    char version[6] = {};
    HKEY retKey;
    LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\WOW6432Node\\ZM软件工作室\\学生机房管理助手",
                  0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &retKey);
    DWORD size = sizeof(version);
    RegQueryValueEx(retKey, "Version", NULL, NULL, (LPBYTE)&version, &size);
    RegCloseKey(retKey);
    if (ret != ERROR_SUCCESS) { ge; SetWindowText(TxOut, "执行失败，可能未安装学生机房管理助手"); return; }

    SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE zm = OpenService(sc, "zmserv", SERVICE_STOP);
    SERVICE_STATUS ss = {};
    ControlService(zm, SERVICE_CONTROL_STOP, &ss);
    CloseServiceHandle(sc); CloseServiceHandle(zm);
    KillAllProcessWithName("zmserv.exe", KILL_DEFAULT);

    std::string sLog = "机房助手版本：";
    sLog += version;
    sLog += "\nprozs.exe进程名：";

    SYSTEMTIME time; GetLocalTime(&time);
    int n3 = time.wMonth + time.wDay, n4, n5, n6;
    DWORD prozsPid = 0;

    if (version[0] == '9' && version[2] >= '0' || version[0] == '1' && version[1] >= '0') {
        char name[10] = {};
        VBMath.m_rndSeed = 327680;
        VBMath.Randomize(double(time.wMonth * time.wDay));
        long long n = round(double(VBMath.Rnd()) * 300000.f + 1.f);
        for (int i = 4; i >= 0; i--) { name[i] = char(n % 10L + 107L); n /= 10L; }
        prozsPid = GetProcessIDFromName(strcat(name, ".exe"));
        if (!prozsPid) {
            PROCESSENTRY32 pe; pe.dwSize = sizeof(PROCESSENTRY32);
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (Process32First(hSnapshot, &pe)) {
                do {
                    size_t uImageLength = strlen(pe.szExeFile);
                    if (uImageLength >= 8) {
                        for (char* n7 = pe.szExeFile; *n7 != '.'; n7++)
                            if (!(*n7 >= 102 && *n7 <= 118)) goto IL_NEXT;
                        if (!_stricmp(pe.szExeFile, "smss.exe")) goto IL_NEXT;
                        if (!_stricmp(pe.szExeFile, "sihost.exe")) goto IL_NEXT;
                        if (!_stricmp(pe.szExeFile, "spoolsv.exe")) goto IL_NEXT;
                        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                        char path[MAX_PATH] = {}; DWORD sz;
                        bool bSuccess = QueryFullProcessImageName(hProcess, 0, path, &sz);
                        CloseHandle(hProcess);
                        if (bSuccess && _strnicmp(path, "C:\\Program Files", 16)) goto IL_NEXT;
                        sLog += pe.szExeFile; prozsPid = pe.th32ProcessID; break;
                    }
                    IL_NEXT:;
                } while (Process32Next(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        } else sLog += name;
    } else if (version[0] == '7' && version[2] >= '5') {
        PROCESSENTRY32 pe; pe.dwSize = sizeof(PROCESSENTRY32);
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (Process32First(hSnapshot, &pe)) {
            do {
                size_t uImageLength = strlen(pe.szExeFile);
                if ((version[2] == '5') ? (uImageLength == 14) : (uImageLength >= 8)) {
                    for (char* n7 = pe.szExeFile; *n7 != '.'; n7++)
                        if (!(*n7 >= 100 && *n7 <= 109)) goto IL_NEXT2;
                    sLog += pe.szExeFile; prozsPid = pe.th32ProcessID; break;
                }
                IL_NEXT2:;
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    } else if (version[0] == '7' && version[2] == '4') {
        char c1, c2, c3, c4;
        n3 = time.wMonth * time.wDay; n4 = n3 % 7; n5 = n3 % 5; n6 = n3 % 3;
        int n = n3 % 9;
        if (n3 % 2 == 0) c1=108+n4, c2=75+n, c3=98+n5, c4=65+n6;
        else c1=98+n, c2=65+n4, c3=108+n5, c4=75+n6;
        char c[5] = {c1, c2, c3, c4, '\0'};
        sLog += c; prozsPid = GetProcessIDFromName(strcat(c, ".exe"));
    } else if (version[0] == '7' && version[2] == '2') {
        char c1, c2, c3, c4;
        n4 = n3 % 7; n5 = n3 % 9; n6 = n3 % 5;
        if (n3 % 2 != 0) c1=103+n5, c2=111+n4, c3=107+n6, c4=48+n4;
        else c1=97+n4, c2=109+n5, c3=101+n6, c4=48+n5;
        char c[5] = {c1, c2, c3, c4, '\0'};
        sLog += c; prozsPid = GetProcessIDFromName(strcat(c, ".exe"));
    } else {
        n4 = n3 % 3 + 3; n5 = n3 % 4 + 4;
        char c[10] = {'p'};
        if (n3 % 2 != 0) c[1]=n5+102, c[2]=n4+98;
        else c[1]=n4+99, c[2]=n5+106;
        sLog += c; sLog += "（使用7.2前逻辑）"; prozsPid = GetProcessIDFromName(strcat(c, ".exe"));
    }

    Println(sLog.c_str());
    KillProcess(prozsPid, KILL_DEFAULT);
    KillAllProcessWithName("prozs.exe", KILL_DEFAULT);
    KillAllProcessWithName("przs.exe", KILL_DEFAULT);
    KillAllProcessWithName("jfglzs.exe", KILL_DEFAULT);
    KillAllProcessWithName("jfglzsp.exe", KILL_DEFAULT);
    KillAllProcessWithName("jfglzsn.exe", KILL_DEFAULT);
    SetWindowText(TxOut, "执行成功");
}
