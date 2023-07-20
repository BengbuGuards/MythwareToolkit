#pragma GCC optimize(3) //优化
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <fltuser.h>
#include <userenv.h>
#include <commctrl.h>
#include <versionhelpers.h>
#include <string>
#include <cstdlib>
#include <ctime>
#undef UNICODE
#undef _UNICODE
BOOL GetMythwarePasswordFromRegedit(char *str);
DWORD GetProcessIDFromName(LPCSTR szName);
bool KillProcess(DWORD dwProcessID, int way);
DWORD WINAPI ThreadProc(LPVOID lpParameter);
BOOL CALLBACK SetWindowFont(HWND hwndChild, LPARAM lParam);
BOOL CALLBACK UpdateControlDpi(HWND hwndChild, LPARAM lParam);
bool SetupTrayIcon(HWND m_hWnd, HINSTANCE hInstance);
BOOL EnableDebugPrivilege();
DWORD WINAPI KeyHookThreadProc(LPVOID lpParameter);
DWORD WINAPI MouseHookThreadProc(LPVOID lpParameter);
BOOL SuspendProcess(DWORD dwProcessID, BOOL suspend);
int GetProcessState(DWORD dwProcessID);
LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam);
LPCSTR RandomWindowTitle();
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
LONG WINAPI GlobalExceptionHandler(EXCEPTION_POINTERS* exceptionInfo);
inline void PrtError(LPCSTR szDes, LRESULT lResult);
inline LPSTR FormatLogTime();

std::string sOutPut;
#define Print(text) sOutPut=sOutPut+FormatLogTime()+text
#define Println(text) Print(text); sOutPut+="\r\n"
#define KILL_FORCE 1
#define KILL_DEFAULT 2
#define ge error = GetLastError()
HHOOK kbdHook, mseHook;
HWND hwnd, focus; /* A 'HANDLE', hence the H, or a pointer to our window */
/* This is where all the input to the window goes to */
LPCSTR MythwareFilename = "StudentMain.exe";//把这个改成别的便可以“兼容”更多电子教室
HWND hBdCst;
//LONG fullScreenStyle = WS_POPUP | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN, windowingStyle = fullScreenStyle | WS_OVERLAPPEDWINDOW ^ WS_OVERLAPPED;
NOTIFYICONDATA icon;
HMENU hMenu;//托盘菜单
int width = 528, height = 250, w, h, mwSts;
bool asking = false, ask = false, closingProcess = false;
DWORD error = -1;//用于调试
POINT p, pt;
HWND BtAbt, BtKmw, TxOut, TxLnk, BtTop, BtCur, BtKbh, BtSnp, BtWnd;
LPCSTR helpText = "极域工具包 v1.3\n\
额外功能：快捷键Alt+C双击杀掉当前进程，Alt+W最小化顶层窗口，Alt+B唤起主窗口\n\
当鼠标移至屏幕左上角/右上角时，可以选择最小化/关闭焦点窗口（你也可以关闭此功能）\n\
使用菜单栏关闭本窗口时会自动最小化防误触，若要退出可在托盘关闭或Alt+F4\n\
最小化时隐藏到任务栏托盘，左键双击打开主界面，右键单击调出菜单\n\
解禁工具可解禁Chrome和Edge的小游戏；若提示设置失败，可能是无权限或指定注册表键值不存在，在此情况下，通常本身就无需解禁\n\
解键盘锁功能如果对Alt+Ctrl+Delete无效时，重新勾选即可；对极域的大多数操作都只在2015/2016版测试通过\n\
启动时附加-s或/s命令行可以System权限启动\n\
MeltdownDFC为冰点还原密码破解工具，crdisk为其他保护系统删除工具（慎用！）";
HANDLE thread/*用来刷新置顶，用Timer会有bug*/, mouHook/*解鼠标锁*/, keyHook/*解键盘锁*/;
UINT WM_TASKBAR;


LRESULT CALLBACK WndProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
	switch (Message) {
		case WM_CREATE: {
			//获取系统版本号
			OSVERSIONINFO vi = {sizeof(OSVERSIONINFO)};
			GetVersionEx(&vi);
			SYSTEM_INFO si = {};
			GetNativeSystemInfo(&si);
			char szVersion[BUFSIZ] = {};
			sprintf(szVersion, "系统版本：%u.%u.%u %d-bit\n程序版本：%s %d-bit\n",
				vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber, (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) ? 64 : 32, 
				"1.3", sizeof(PVOID)*8);
			sOutPut += szVersion;
			EnableDebugPrivilege();//提权
			w = GetSystemMetrics(SM_CXSCREEN) - 1;//屏幕宽度（注意比实际宽度多1）
			h = GetSystemMetrics(SM_CYSCREEN) - 1;//屏幕高度
			WM_TASKBAR = RegisterWindowMessage("TaskbarCreated");//任务栏创建事件
			thread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);//置顶窗口
			keyHook = CreateThread(NULL, 0, KeyHookThreadProc, NULL, CREATE_SUSPENDED, NULL);//键盘锁
			mouHook = CreateThread(NULL, 0, MouseHookThreadProc, NULL, CREATE_SUSPENDED, NULL);//鼠标锁
			SetTimer(hwnd, 1, 1000, NULL); //检测鼠标左上角
			SetTimer(hwnd, 2, 2000, NULL); //检测极域状态、更新标题
			RegisterHotKey(hwnd, 0, MOD_ALT, 'C'); //Alt+C强制结束当前程序
			RegisterHotKey(hwnd, 1, MOD_ALT, 'W'); //Alt+W最小化顶层窗口
			if(!RegisterHotKey(hwnd, 2, MOD_ALT, 'B')) //Alt+B显示此窗口
				if(MessageBox(hwnd, "注册系统级热键 Alt+B 失败，有可能该应用的另一实例还在运行，请先关闭它再重新启动本程序！若“取消”则阻止程序继续启动", "极 域 工 具 包", MB_OKCANCEL | MB_ICONWARNING)==IDCANCEL){
					PostQuitMessage(0);
					return FALSE;
				}
			HINSTANCE hi = ((LPCREATESTRUCT) lParam)->hInstance;
			TxLnk = CreateWindow("SysLink", "极域工具包 <a href=\"https://blog.csdn.net/weixin_42112038?type=blog\">博客</a>", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 8, 8, 120, 20, hwnd, HMENU(1001), hi, NULL);
			BtAbt = CreateWindow(WC_BUTTON, "关于/帮助", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 166, 3, 90, 30, hwnd, HMENU(1002), hi, NULL);
			//获取密码
			char str[BUFSIZ] = {};
			LPCSTR psd;
			if (!GetMythwarePasswordFromRegedit(str))
				psd = "获取密码失败";
			else psd = str;
			CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, psd, WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_READONLY, 8, 36, 248, 20, hwnd, HMENU(1003), hi, NULL);
			CreateWindow(WC_BUTTON, "杀掉学生机房管理助手", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,  8, 64, 248, 50, hwnd, HMENU(1013), hi, NULL);
			BtKmw = CreateWindow(WC_BUTTON, "杀掉极域", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_SPLITBUTTON, 8, 122, 248, 50, hwnd, HMENU(1004), hi, NULL);
			TxOut = CreateWindow(STATUSCLASSNAME, "等待操作", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, HMENU(1005), hi, NULL);
			int pts[2] = {352, -1};
			SendMessage(TxOut, SB_SETPARTS, WPARAM(2), LPARAM(pts));
			CreateWindow(WC_BUTTON, "解除禁用工具", WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 264, 8, 248, 98, hwnd, NULL, hi, NULL);
			CreateWindow(WC_BUTTON, "一键解禁系统程序", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 272, 28, 112, 30, hwnd, HMENU(1007), hi, NULL);
			CreateWindow(WC_BUTTON, "解除网络限制", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 272, 66, 112, 30, hwnd, HMENU(1008), hi, NULL);
			CreateWindow(WC_BUTTON, "解除极域U盘限制", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 392, 66, 112, 30, hwnd, HMENU(1009), hi, NULL);
			CreateWindow(WC_BUTTON, "重启资源管理器", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 392, 28, 112, 30, hwnd, HMENU(1010), hi, NULL);
			CreateWindow(WC_BUTTON, "广播窗口化", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | WS_DISABLED, 264, 112, 120, 30, hwnd, HMENU(1014), hi, NULL);
			CreateWindow(WC_BUTTON, "重置助手密码(&P)", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 392, 112, 120, 30, hwnd, HMENU(1015), hi, NULL);
			CreateWindow(WC_BUTTON, "MeltdownDFC", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 264, 150, 120, 22, hwnd, HMENU(1019), hi, NULL);
			CreateWindow(WC_BUTTON, "crdisk", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 392, 150, 120, 22, hwnd, HMENU(1020), hi, NULL);
			
			BtWnd = CreateWindow(WC_BUTTON, "启用鼠标监测弹窗", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 385, 176, 130, 18, hwnd, HMENU(1012), hi, NULL);
			BtSnp = CreateWindow(WC_BUTTON, "防止截屏", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX | (IsWindows7OrGreater() ? 0 : WS_DISABLED), 309, 176, 65, 18, hwnd, HMENU(1011), hi, NULL);
			SendMessage(BtSnp, BM_SETCHECK, BST_CHECKED, NULL);
			SendMessage(hwnd, WM_COMMAND, 1011, 0);
			BtTop = CreateWindow(WC_BUTTON, "置顶此窗口", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 8, 176, 77, 18, hwnd, HMENU(1016), hi, NULL);
			SendMessage(BtTop, BM_SETCHECK, BST_CHECKED, NULL);
			BtCur = CreateWindow(WC_BUTTON, "解除鼠标限制(&M)", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 95, 176, 107, 18, hwnd, HMENU(1017), hi, NULL);
			BtKbh = CreateWindow(WC_BUTTON, "解键盘锁(&C)", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 213, 176, 85, 18, hwnd, HMENU(1018), hi, NULL);
			HFONT hFont = NULL;
			NONCLIENTMETRICS info;
			info.cbSize = sizeof(NONCLIENTMETRICS);
			if (SystemParametersInfo (SPI_GETNONCLIENTMETRICS, 0, &info, 0)) {
				hFont = CreateFontIndirect ((LOGFONT*)&info.lfMessageFont);
			}//取系统默认字体
			EnumChildWindows(hwnd, SetWindowFont, LPARAM(hFont));
			SetupTrayIcon(hwnd, hi);
			HMENU sys = GetSystemMenu(hwnd, FALSE);//系统菜单
			AppendMenu(sys, MF_STRING, 2, "显示上一个错误(&E)");
			AppendMenu(sys, MF_STRING, 4, "显示程序日志(&L)");
			AppendMenu(sys, MF_STRING, 3, "启动任务管理器(&T)");
			focus = GetDlgItem(hwnd, 1013);
			SetFocus(focus);
			SendMessage(hwnd, WM_TIMER, WPARAM(2), NULL);
			//卸载极域进程终止hook
			HMODULE hook = NULL;
			if (sizeof(PVOID) == 8)hook = GetModuleHandle("LibTDProcHook64.dll");
			else hook = GetModuleHandle("LibTDProcHook32.dll");
			if (hook)FreeModule(hook);
			break;
		}
		case WM_COMMAND: {
			switch (LOWORD(wParam)) {
				case 1002: {
					MessageBox(NULL, helpText, "关于/帮助", MB_OK | MB_ICONINFORMATION);
					break;
				}
				case 1004: {
					if (mwSts != 2) {
						if (KillProcess(GetProcessIDFromName(MythwareFilename), KILL_FORCE)) {
							SetWindowText(TxOut, "执行成功");
							Sleep(30);
							SendMessage(hwnd, WM_TIMER, WPARAM(2), NULL);
						} else {
							ge;
							SetWindowText(TxOut, "执行失败");
						}
					} else { //降权启动极域
						HKEY retKey;//先读取极域路径
						char szPath[MAX_PATH * 2];
						LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\TopDomain\\e-Learning Class Standard\\1.00", 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &retKey);
						if (ret != ERROR_SUCCESS) {
							ge;
							SetWindowText(TxOut, "读取路径失败");
							RegCloseKey(retKey);
							break;
						}
						DWORD dataLong = MAX_PATH * 2, type = REG_SZ;
						ret = RegQueryValueEx(retKey, "TargetDirectory", 0, &type, LPBYTE(szPath), &dataLong);
						RegCloseKey(retKey);

						if (ret != ERROR_SUCCESS) {
							ge;
							SetWindowText(TxOut, "读取路径失败");
							break;
						}
						HWND hwnd = FindWindow("Shell_TrayWnd", NULL);//有这个类名的窗口一定隶属于explorer.exe
						DWORD pid;
						GetWindowThreadProcessId(hwnd, &pid);//反查出窗口PID
						HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
						if (!handle) {
							SetWindowText(TxOut, "请先启动资源管理器");
							break;
						}
						HANDLE token;
						OpenProcessToken(handle, TOKEN_DUPLICATE, &token);//取得token
						DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &token);
						STARTUPINFO si = {};//必要的一些参数......
						PROCESS_INFORMATION pi = {};
						si.cb = sizeof(STARTUPINFO);
						si.dwFlags = STARTF_USESHOWWINDOW;
						si.wShowWindow = SW_SHOW;
						BOOL bResult = CreateProcessAsUser(token, strcat(szPath, MythwareFilename), NULL, NULL, NULL,
						                                   FALSE, CREATE_NEW_PROCESS_GROUP | NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi); //启动极域
						if (bResult) {
							SetWindowText(TxOut, "启动成功");
							CloseHandle(pi.hProcess);
							CloseHandle(pi.hThread);
						} else {
							ge;
							SetWindowText(TxOut, "启动失败");
						}

						CloseHandle(handle);
						CloseHandle(token);
						SendMessage(hwnd, WM_TIMER, WPARAM(2), NULL);
					}
					break;
				}
				case 1007: {
					BYTE cStatus = NO_ERROR;

					//HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System:DisableCMD->0
					HKEY retKey;
					DWORD value = 0;
					RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\System", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					LONG ret = RegSetValueEx(retKey, "DisableCMD", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					if (ret != ERROR_SUCCESS) {
						PrtError("解禁cmd失败", ret);
						cStatus = 1;
					} else Println("解禁cmd成功");
					RegCloseKey(retKey);

					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System:DisableRegistryTools->0
					RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					ret = RegSetValueEx(retKey, "DisableRegistryTools", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					if (ret != ERROR_SUCCESS) {
						PrtError("解禁注册表编辑器失败", ret);
						cStatus = 1;
					} else Println("解禁注册表编辑器成功");

					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System:DisableTaskMgr->0
					ret = RegSetValueEx(retKey, "DisableTaskMgr", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					if (ret != ERROR_SUCCESS) {
						PrtError("解禁任务管理器失败", ret);
						cStatus = 1;
					} else Println("解禁任务管理器成功");
					RegCloseKey(retKey);

					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoRun->0
					RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					ret = RegSetValueEx(retKey, "NoRun", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					if (ret != ERROR_SUCCESS) {
						PrtError("解禁Win+R运行失败", ret);
						cStatus = 1;
					} else Println("解禁Win+R运行成功，重启资源管理器即可生效");

					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer:RestrictRun->0
					ret = RegSetValueEx(retKey, "RestrictRun", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));//也有作用
					if (ret != ERROR_SUCCESS) {
						PrtError("解除程序运行限制失败", ret);
						cStatus = 1;
					} else Println("解除程序运行限制成功，重启资源管理器即可生效");
					RegCloseKey(retKey);

					//HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskkill.exe:debugger:(
					RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskkill.exe", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					ret = RegDeleteValue(retKey, "debugger");
					if (ret != ERROR_SUCCESS) {
						PrtError("解禁taskkill失败", ret);
						//cStatus = 1;
					} else Println("解禁taskkill成功");

					//HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntsd.exe:debugger:(
					RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ntsd.exe", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					ret = RegDeleteValue(retKey, "debugger");
					if (ret != ERROR_SUCCESS) {
						PrtError("解禁ntsd失败", ret);
						//cStatus = 1;
					} else Println("解禁ntsd成功");

					RegCloseKey(retKey);
					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoLogOff->0
					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer:StartMenuLogOff->0
					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System:DisableLockWorkstation->0
					RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					ret = RegSetValueEx(retKey, "NoLogOff", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					if (ret != ERROR_SUCCESS) {
						PrtError("解禁注销栏失败", ret);
						cStatus = 1;
					} else Println("解禁注销栏成功");

					ret = RegSetValueEx(retKey, "StartMenuLogOff", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					if (ret != ERROR_SUCCESS) {
						PrtError("解禁开始菜单注销失败", ret);
						cStatus = 1;
					} else Println("解禁开始菜单注销成功");
					RegCloseKey(retKey);

					RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					ret = RegSetValueEx(retKey, "DisableLockWorkstation", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					if (ret != ERROR_SUCCESS) {
						PrtError("解禁锁定失败", ret);
						cStatus = 1;
					} else Println("解禁锁定成功");
					RegCloseKey(retKey);

					RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Google\\Chrome", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					ret = RegDeleteValue(retKey, "AllowDinosaurEasterEgg");
					if (ret != ERROR_SUCCESS) {
						PrtError("解禁Chrome恐龙游戏失败", ret);
						cStatus = 1;
					} else Println("解禁Chrome恐龙游戏成功");
					RegCloseKey(retKey);

					RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Edge", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					ret = RegDeleteValue(retKey, "AllowSurfGame");
					if (ret != ERROR_SUCCESS) {
						PrtError("解禁Edge冲浪游戏失败", ret);
						cStatus = 1;
					} else Println("解禁Edge冲浪游戏成功");
					RegCloseKey(retKey);

					if (cStatus == NO_ERROR)SetWindowText(TxOut, "设置成功");
					else SetWindowText(TxOut, "设置部分失败。。");
					break;
				}
				case 1008: {
					//TODO: 检验多种状况
					//发送终止指令
					HANDLE hNetFilter = CreateFile("\\\\.\\TDNetFilter", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
					if(!GetLastError()){
						DeviceIoControl(hNetFilter, 0x120014, NULL, 0, NULL, 0, NULL, 0);
						PrtError("解除网络限制：发送终止指令", GetLastError());
						CloseHandle(hNetFilter);
					} else PrtError("解除网络限制：打开网络驱动", GetLastError());
					//杀掉网关服务及其守护进程
					bool bStateM = KillProcess(GetProcessIDFromName("MasterHelper.exe"),KILL_DEFAULT);
					bool bStateG = KillProcess(GetProcessIDFromName("GATESRV.exe"),KILL_DEFAULT);
					std::string text = "解除网络限制：停止相关进程";
					Println(text + ((bStateM && bStateG) ? "成功" : "失败"));
					//停止网络过滤驱动
					SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
					SC_HANDLE hFilt = OpenService(sc, "TDNetFilter", SERVICE_STOP | DELETE);
					SERVICE_STATUS ss = {};
					bStateM = ControlService(hFilt, SERVICE_CONTROL_STOP, &ss);
					DeleteService(hFilt);
					CloseServiceHandle(sc);
					CloseServiceHandle(hFilt);
					text = "解除网络限制：停止限网驱动";
					Println(text + (bStateM ? "成功" : "失败"));
					SetWindowText(TxOut, "设置完成");
					break;
				}
				case 1009: {
					HHOOK hCBTHook = SetWindowsHookEx(WH_CBT, CBTProc, NULL, GetCurrentThreadId());
					int id = MessageBox(hwnd, "请选择关闭USB锁的模式！\n软解禁：向过滤端口发送停止请求\n硬解禁：直接删除过滤驱动，软解禁方案无效时使用！", "USB Setting", MB_YESNOCANCEL | MB_ICONQUESTION | MB_SETFOREGROUND);
					UnhookWindowsHookEx(hCBTHook);
					if (id == IDYES) {//LibTDUsbHook10.dll
						//连接过滤端口（TDUsbFilterInit）
						HANDLE hPort = NULL;
						HRESULT hResult = FilterConnectCommunicationPort(L"\\TDFileFilterPort", 0, NULL, 0, NULL, &hPort);
						if(hResult || hPort <= (HANDLE)0 || GetLastError()){
							error = hResult & 0x0000FFFF;
							SetWindowText(TxOut, "设置失败");
							break;
						}
						//发送消息（TDUsbFiltFree）
						int lpInBuffer[4] = {8, 0, 0, 0}; // [esp+0h] [ebp-10h] BYREF
						//memset(&lpInBuffer[1], 0, 12);
						//lpInBuffer[0] = 8;
						hResult = FilterSendMessage(hPort, lpInBuffer, 16/*0x10u*/, NULL, 0, NULL);
						ge;
						//关闭句柄（TDUsbFilterDone）
						CloseHandle(hPort);
						SetWindowText(TxOut, !hResult ? "设置完成" : "设置失败");
					} else if (id == IDNO) {
						SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
						SC_HANDLE hFilt = OpenService(sc, "TDFileFilter", SERVICE_STOP | DELETE);
						SERVICE_STATUS ss = {};
						if(ControlService(hFilt, SERVICE_CONTROL_STOP, &ss))
							SetWindowText(TxOut, "设置成功");
						else{
							ge;
							SetWindowText(TxOut, "设置失败");
						}
						DeleteService(hFilt);
						CloseServiceHandle(sc);
						CloseServiceHandle(hFilt);
					}
					break;
				}
				case 1010: {
					HWND hwnd = FindWindow("Shell_TrayWnd", NULL);//有这个类名的窗口一定隶属于explorer.exe
					DWORD pid;
					GetWindowThreadProcessId(hwnd, &pid);//反查出窗口PID
					if (pid == 0 || hwnd == NULL) { //资源管理器没在运行
						WinExec("explorer.exe", SW_SHOW);//先直接运行，系统检测到explorer.exe是系统权限会自动重启它以降权（否则权限被继承，出现奇妙问题）
						break;
						//pid = GetProcessIDFromName("explorer.exe");
					}
					HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
					if (TerminateProcess(handle, 2))//退出码为2
						SetWindowText(TxOut, "执行成功");
					else {
						ge;
						SetWindowText(TxOut, "执行失败");
					}
					CloseHandle(handle);
					break;
				}
				case 1013: {
					char version[6] = {};//考虑极端值如6.9.5
					HKEY retKey;
					LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\ZM软件工作室\\学生机房管理助手", 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &retKey);
					DWORD size = sizeof(version);
					RegQueryValueEx(retKey, "Version", NULL, NULL, (LPBYTE)&version, &size);
					RegCloseKey(retKey);
					if (ret != ERROR_SUCCESS) {
						ge;
						SetWindowText(TxOut, "执行失败，可能未安装学生机房管理助手");
						break;
					}
					std::string sLog = "机房助手版本：";
					sLog += version;
					sLog += "\nprozs.exe进程名：";
					//取时间用于计算prozs.exe的随机进程名
					SYSTEMTIME time;
					GetLocalTime(&time);
					int n3 = time.wMonth + time.wDay;
					int n4, n5, n6;
					DWORD prozsPid;
					if (version[0] == '9' && version[2] == '0'){
						//以下为9.0版本逻辑
						PROCESSENTRY32 pe;
						pe.dwSize = sizeof(PROCESSENTRY32);
						HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
						if (Process32First(hSnapshot, &pe)) {
							do {
								//筛选长度为大于等于4（9.0）的进程名（不包含末尾“.exe”）
								size_t uImageLength = strlen(pe.szExeFile);
								if (uImageLength >= 8) {
									//遍历字符
									for (size_t j = 0; ((version[2] == '5')?(j < 10):(j < uImageLength - 4)); j++) {
										char n7 = pe.szExeFile[j];
										//符不符合f-o之间
										if (!(n7 >= 102 && n7 <= 111))goto IL_13A;
									}
									//就是你！
									sLog += pe.szExeFile;
									prozsPid = pe.th32ProcessID;
									break;
								}
								IL_13A:;
							} while (Process32Next(hSnapshot, &pe));
						}
						CloseHandle(hSnapshot);
					} else if (version[0] == '7' &&(version[2] == '5' || version[2] == '8')) {
						//以下为7.5、7.8版本逻辑
						PROCESSENTRY32 pe;
						pe.dwSize = sizeof(PROCESSENTRY32);
						HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
						if (Process32First(hSnapshot, &pe)) {
							do {
								//筛选长度为10（7.5）或大于等于4（7.8）的进程名（不包含末尾“.exe”）
								size_t uImageLength = strlen(pe.szExeFile);
								if ((version[2] == '5')?(uImageLength == 14):(uImageLength >= 8)) {
									//遍历字符
									for (size_t j = 0; ((version[2] == '5')?(j < 10):(j < uImageLength - 4)); j++) {
										char n7 = pe.szExeFile[j];
										//符不符合d-m之间
										if (!(n7 >= 100 && n7 <= 109))goto IL_226;
									}
									//就是你！
									sLog += pe.szExeFile;
									prozsPid = pe.th32ProcessID;
									break;
								}
								IL_226:;
							} while (Process32Next(hSnapshot, &pe));
						}
						CloseHandle(hSnapshot);
					} else if (version[0] == '7' && version[2] == '4') {
						//以下为7.4版本逻辑
						char c1, c2, c3, c4;
						n3 = time.wMonth * time.wDay, n4 = n3 % 7, n5 = n3 % 5, n6 = n3 % 3;
						int n = n3 % 9;
						if (n3 % 2 == 0)
							c1 = 108 + n4,  c2 = 75 + n,  c3 = 98 + n5,  c4 = 65 + n6;
						else
							c1 = 98 + n,  c2 = 65 + n4,  c3 = 108 + n5,  c4 = 75 + n6;
						char c[5] = {c1, c2, c3, c4, '\0'};
						sLog += c;
						prozsPid = GetProcessIDFromName(strcat(c, ".exe"));
					} else if (version[0] == '7' && version[2] == '2') {
						char c1, c2, c3, c4;
						//以下为7.2版本逻辑
						n4 = n3 % 7, n5 = n3 % 9, n6 = n3 % 5;
						if (n3 % 2 != 0)
							c1 = 103 + n5,  c2 = 111 + n4,  c3 = 107 + n6,  c4 = 48 + n4;
						else 
							c1 = 97 + n4,   c2 = 109 + n5,  c3 = 101 + n6,  c4 = 48 + n5;
						char c[5] = {c1, c2, c3, c4, '\0'};
						sLog += c;
						prozsPid = GetProcessIDFromName(strcat(c, ".exe"));
					} else {
						//以下为7.2版本之前的逻辑
						n4 = n3 % 3 + 3, n5 = n3 % 4 + 4;
						char c[4] = {'p'};
						if (n3 % 2 != 0)
							c[1] = n5 + 102, c[2] = n4 + 98;
						else
							c[1] = n4 + 99,  c[2] = n5 + 106;
						sLog += c;
						sLog += "（使用7.2前的逻辑）";
						prozsPid = GetProcessIDFromName(strcat(c, ".exe"));
					}
					Println(sLog);
					KillProcess(prozsPid, KILL_DEFAULT);
					KillProcess(GetProcessIDFromName("jfglzs.exe"), KILL_DEFAULT);
					//停止zmserv服务防止关机
					SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
					SC_HANDLE zm = OpenService(sc, "zmserv", SERVICE_STOP);
					SERVICE_STATUS ss = {};
					ControlService(zm, SERVICE_CONTROL_STOP, &ss);
					CloseServiceHandle(sc);
					CloseServiceHandle(zm);
					SetWindowText(TxOut, "执行成功");
					break;
				}
				case 1011: {
					LRESULT check = SendMessage(BtSnp, BM_GETCHECK, NULL, NULL);
					if (check == BST_CHECKED)
						SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
					else
						SetWindowDisplayAffinity(hwnd, WDA_NONE);
					break;
				}
				case 1012: {
					LRESULT check = SendMessage(BtWnd, BM_GETCHECK, NULL, NULL);
					ask = check == BST_CHECKED;
					break;
				}
				case 1014: {
					//找到工具条
					HWND menuBar = FindWindowEx(hBdCst, NULL, "AfxWnd80u", NULL);
					/*//显示工具条
					  ShowWindow(menuBar, SW_SHOWDEFAULT);
					  SetWindowPos(menuBar, HWND_TOP, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
					  //隐藏工具条
					  ShowWindow(menuBar, SW_NORMAL);
					  SetWindowPos(menuBar, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);*/
					//解禁全屏按钮
					//EnableWindow(GetDlgItem(menuBar, 1004),FALSE);
					//模拟点击
					BOOL bWindowing;
					LONG lStyle = GetWindowLong(hBdCst, GWL_STYLE);
					if (lStyle & WS_SYSMENU)bWindowing = TRUE;
					PostMessage(hBdCst, WM_COMMAND, MAKEWPARAM(1004, BM_CLICK), NULL);
					SetWindowText(TxOut, bWindowing ? "全屏化完成" : "窗口化完成");
					SendMessage(hwnd, WM_TIMER, WPARAM(2), NULL);
					break;
				}
				case 1015: {
					if (MessageBox(hwnd, "你是否要将学生机房管理助手的密码设成12345678？仅7.1-9.0版本有效，该操作不可逆！！", "警告", MB_YESNO | MB_ICONWARNING) == IDYES) {
						std::string c = "8a29cc29f5951530ac69f4";
						HKEY retKey;
						LONG ret = RegOpenKeyEx(HKEY_CURRENT_USER, "Software", 0, KEY_SET_VALUE, &retKey);
						if (ret != ERROR_SUCCESS) {
							ge;
							SetWindowText(TxOut, "设置失败");
							RegCloseKey(retKey);
							break;
						}
						ret = RegSetValueEx(retKey, "n", 0, REG_SZ, (CONST BYTE*)c.c_str(), c.size() + 1);
						SetWindowText(TxOut, "设置成功");
						RegCloseKey(retKey);
					}
					break;
				}
				case 1016: {
					LRESULT check = SendMessage(BtTop, BM_GETCHECK, NULL, NULL);
					if (check == BST_CHECKED) {
						ResumeThread(thread);
					} else {
						SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
						SuspendThread(thread);
					}
					break;
				}
				case 1017: {
					LRESULT check = SendMessage(BtCur, BM_GETCHECK, NULL, NULL);
					if (check == BST_CHECKED) {
						ResumeThread(mouHook);
					} else {
						SuspendThread(mouHook);
						UnhookWindowsHookEx(mseHook);
					}
					break;
				}
				case 1018: {
					LRESULT check = SendMessage(BtKbh, BM_GETCHECK, NULL, NULL);
					if (check == BST_CHECKED) {
						ResumeThread(keyHook);
						//打开符号链接
						HANDLE hDevice = CreateFile("\\\\.\\TDKeybd", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
						if (GetLastError()) {
							PrtError(GetLastError() == ERROR_FILE_NOT_FOUND ? "解驱动键盘锁：驱动未安装" : "解驱动键盘锁：设置失败", GetLastError());
							break;
						}
						BOOL bEnable = TRUE;
						//发送控制代码
						if (DeviceIoControl(hDevice, 0x220000, &bEnable, 4, NULL, 0, NULL, NULL))
							Print("解驱动键盘锁：设置成功");
						else
							PrtError("解驱动键盘锁：设置失败",GetLastError());
						CloseHandle(hDevice);
					} else {
						SuspendThread(keyHook);
						UnhookWindowsHookEx(kbdHook);
					}
					break;
				}
				case 1019: {
					//判断是否已在运行
					DWORD dwPID = GetProcessIDFromName("MeltdownDFC.exe");
					if(dwPID) break;
					//取缓存路径，创建文件
					char szTempPath[MAX_PATH];
					GetTempPath(MAX_PATH, szTempPath);
					HANDLE hFile = CreateFile(strcat(szTempPath, "\\MeltdownDFC.exe"), GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
					if(hFile != INVALID_HANDLE_VALUE){
						//获取资源信息
						HRSRC hResInfo = FindResource(NULL, MAKEINTRESOURCE(2), RT_RCDATA);
						HGLOBAL hResData = LoadResource(NULL, hResInfo);
						DWORD dwSize = SizeofResource(NULL, hResInfo);
						LPVOID pData = LockResource(hResData);
						if(pData){
							//写入文件
							if(!WriteFile(hFile, pData, dwSize + 1, NULL, NULL)){
								SetWindowText(TxOut, "写入失败");
								CloseHandle(hFile);
								break;
							}
							FlushFileBuffers(hFile);
							CloseHandle(hFile);
							//执行程序
							if(WinExec(szTempPath, SW_SHOW) < 32)
								SetWindowText(TxOut, "启动失败");
							else SetWindowText(TxOut, "启动完成");
						} else SetWindowText(TxOut, "写入失败");
					} else SetWindowText(TxOut, "启动失败");
					break;
				}
				case 1020: {
					//同上
					DWORD dwPID = GetProcessIDFromName("crdisk.exe");
					if(dwPID) break;
					char szTempPath[MAX_PATH];
					GetTempPath(MAX_PATH, szTempPath);
					HANDLE hFile = CreateFile(strcat(szTempPath, "\\crdisk.exe"), GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
					if(hFile != INVALID_HANDLE_VALUE){
						HRSRC hResInfo = FindResource(NULL, MAKEINTRESOURCE(3), RT_RCDATA);
						HGLOBAL hResData = LoadResource(NULL, hResInfo);
						DWORD dwSize = SizeofResource(NULL, hResInfo);
						LPVOID pData = LockResource(hResData);
						if(pData){
							if(!WriteFile(hFile, pData, dwSize + 1, NULL, NULL)){
								SetWindowText(TxOut, "写入失败");
								CloseHandle(hFile);
								break;
							}
							FlushFileBuffers(hFile);
							CloseHandle(hFile);
							if(WinExec(szTempPath, SW_SHOW) < 32)
								SetWindowText(TxOut, "启动失败");
							else SetWindowText(TxOut, "启动完成");
						} else SetWindowText(TxOut, "写入失败");
					} else SetWindowText(TxOut, "启动失败");
					break;
				}
			}
			return 0;
		}
		case WM_HOTKEY:
			switch (wParam) {
				case 0://Alt+C
					if (closingProcess) { //第二次
						closingProcess = false;
						KillTimer(hwnd, 3);
						HWND topHwnd = GetForegroundWindow();
						DWORD pid;
						GetWindowThreadProcessId(topHwnd, &pid);
						if(pid != GetCurrentProcessId())//避免焦点在当前程序时，关闭自己
						KillProcess(pid, KILL_FORCE);
					} else { //第一次
						closingProcess = true;
						SetTimer(hwnd, 3, 750, NULL);
					}
					break;
				case 1: { //Alt+W
					HWND topHwnd = GetForegroundWindow();
					if(!IsHungAppWindow(topHwnd))//应用程序无响应时不作处理。防止使自己堵塞，导致无响应。TODO: 此函数可能即将弃用，等待更好解决方法
						ShowWindow(topHwnd, SW_MINIMIZE);
					break;
				}
				case 2://Alt+B
					ShowWindow(hwnd, SW_SHOWNORMAL);
					SetForegroundWindow(hwnd);
			}
			return 0;
		case WM_TIMER:
			switch (wParam) {
				case 1:
					if (!asking && ask) {
						//检测鼠标左上角事件
						GetCursorPos(&p);
						if (p.x == 0 && p.y == 0) {
							asking = true;
							HWND topHwnd = GetForegroundWindow();
							if (MessageBox(hwnd, "检测到了鼠标位置变化！是否最小化焦点窗口？", "实时监测", MB_YESNO | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST) == IDYES) {
								if(!IsHungAppWindow(topHwnd))//同上
									ShowWindow(topHwnd, SW_MINIMIZE);
							}
							asking = false;
						} else if (p.x == w && p.y == 0) {
							asking = true;
							HWND topHwnd = GetForegroundWindow();
							HHOOK hCBTHook = SetWindowsHookEx(WH_CBT, CBTProc, NULL, GetCurrentThreadId());
							int id = MessageBox(hwnd, "检测到了鼠标位置变化！是否关闭焦点窗口？", "实时监测", MB_YESNOCANCEL | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST);
							UnhookWindowsHookEx(hCBTHook);
							if (id == IDYES) {
								PostMessage(topHwnd, WM_CLOSE, 0, 0); //异步
							} else if (id == IDNO) {
								//创建一个透明零大小的父窗口
								HWND hParent = CreateWindowEx(0, WC_STATIC, "", 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
								//将目标窗口设为子窗口
								SetParent(topHwnd, hParent);
								ge;
								//关闭父窗口，子窗口也将一并销毁
								PostMessage(hParent, WM_CLOSE, 0, 0);
							}
							asking = false;
						}
						break;
					}
				case 2: {
					SetWindowText(hwnd, RandomWindowTitle());
					DWORD id = GetProcessIDFromName(MythwareFilename);
					if (id == 0) {
						SendMessage(TxOut, SB_SETTEXT, 1, LPARAM("极域未运行"));
						mwSts = 2;
						SetWindowText(BtKmw, "启动极域");
					} else {
						mwSts = GetProcessState(id);
						std::string show;
						if (mwSts == -1)show = "极域状态未知";
						else if (mwSts == 0)show = "极域运行中";
						else if (mwSts == 1)show = "极域已挂起";
						sprintf(show.data(), "%s[PID:%d]", show.c_str(), int(id));
						SendMessage(TxOut, SB_SETTEXT, 1, LPARAM(show.c_str()));
						SetWindowText(BtKmw, "杀掉极域");
						//判断广播状态
						HWND* bdCst = new HWND;
						*bdCst = NULL;
						BOOL bWindowing = FALSE;
						EnumWindows(EnumWindowsProc, LPARAM(bdCst));
						if (*bdCst) {
							LONG lStyle = GetWindowLong(*bdCst, GWL_STYLE);
							if (lStyle & WS_SYSMENU)bWindowing = TRUE;
						}
						hBdCst = *bdCst;
						EnableWindow(GetDlgItem(hwnd, 1014), *bdCst ? TRUE : FALSE);
						SetDlgItemText(hwnd, 1014, bWindowing ? "广播全屏化" : "广播窗口化");
					}
					break;
				}
				case 3: {
					closingProcess = false;
					KillTimer(hwnd, 3);//立刻解除
				}
			}
			break;
		case WM_DESTROY:
			UnregisterHotKey(hwnd, 0);
			UnregisterHotKey(hwnd, 1);
			UnregisterHotKey(hwnd, 2);
			CloseHandle(thread);
			CloseHandle(keyHook);
			CloseHandle(mouHook);
			Shell_NotifyIcon(NIM_DELETE, &icon); //删除托盘图标，否则只有鼠标划过图标才消失
			UnhookWindowsHookEx(mseHook);
			UnhookWindowsHookEx(kbdHook);
			PostQuitMessage(0);
			break;
		case WM_ACTIVATE: {
			if (LOWORD(wParam) == WA_INACTIVE) {
				if (GetWindowLong(hwnd, GWL_STYLE)&WS_VISIBLE) {
					focus = GetFocus();
					char c[7];
					GetClassName(focus, c, 7);
					if (_stricmp(c, "Button") == 0) {
						LONG style = GetWindowLong(focus, GWL_STYLE);
						if ((style & BS_AUTOCHECKBOX) != BS_AUTOCHECKBOX)
							SendMessage(focus, BM_SETSTYLE, 0, TRUE);
					}
				}
			} else {
				SetFocus(focus);
				char c[7];
				GetClassName(focus, c, 7);
				if (_stricmp(c, "Button") == 0) {
					LONG style = GetWindowLong(focus, GWL_STYLE);
					if ((style & BS_AUTOCHECKBOX) != BS_AUTOCHECKBOX)
						SendMessage(focus, BM_SETSTYLE, BS_DEFPUSHBUTTON, TRUE);
				}
			}
			return FALSE;
		}
		case WM_USER + 3:
			if (lParam == WM_LBUTTONDBLCLK) { //左键双击
				ShowWindow(hwnd, SW_SHOWNORMAL);
				SetForegroundWindow(hwnd);
			} else if (lParam == WM_RBUTTONUP) { //右键单击
				GetCursorPos(&pt);
				SetForegroundWindow(hwnd);
				HMENU hMenu = CreatePopupMenu();//托盘菜单
				AppendMenu(hMenu, MF_STRING, 1, "关闭程序");
				AppendMenu(hMenu, MF_STRING, 2, "打开界面");
				int i = TrackPopupMenu(hMenu, TPM_RETURNCMD, pt.x, pt.y, NULL, hwnd, NULL);
				switch (i) {
					case 1:
						//TODO
						PostMessage(hwnd, WM_CLOSE, 0, 0);
						break;
					case 2:
						ShowWindow(hwnd, SW_SHOWNORMAL);
						SetForegroundWindow(hwnd);
						break;
				}
			}
			return FALSE;
		case WM_NOTIFY:
			switch (((LPNMHDR)lParam)->code) {
				case BCN_DROPDOWN: {
					NMBCDROPDOWN* pDropDown = (NMBCDROPDOWN*)lParam;
					if (pDropDown->hdr.hwndFrom == BtKmw) {
						// Get screen coordinates of the button.
						POINT pt;
						pt.x = pDropDown->rcButton.left;
						pt.y = pDropDown->rcButton.bottom;
						ClientToScreen(pDropDown->hdr.hwndFrom, &pt);
						// Create a menu and add items.
						HMENU hSplitMenu = CreatePopupMenu();
						LPCSTR show;
						if (mwSts != 1)show = "挂起极域";
						else if (mwSts == 1)show = "恢复极域";
						AppendMenu(hSplitMenu, MF_BYPOSITION, 1, show);
						EnableMenuItem(hSplitMenu, 1, mwSts != 2 ? MF_ENABLED : MF_GRAYED);
						// Display the menu.
						SuspendThread(thread);
						int i = TrackPopupMenu(hSplitMenu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD, pt.x, pt.y, 0, hwnd, NULL);
						ResumeThread(thread);
						switch (i) {
							case 1: {
								BOOL sts = SuspendProcess(GetProcessIDFromName(MythwareFilename), !mwSts);
								if (sts)SetWindowText(TxOut, "挂起/恢复成功");
								else SetWindowText(TxOut, "挂起/恢复失败");
								SendMessage(hwnd, WM_TIMER, WPARAM(2), NULL);
								break;
							}
						}
						return TRUE;
					}
					break;
				}
				case NM_CLICK:
					if (((LPNMHDR)lParam)->hwndFrom == TxOut) {
						focus = GetFocus();
						char c[7];
						GetClassName(focus, c, 7);
						if (_stricmp(c, "Button") == 0) {
							LONG style = GetWindowLong(focus, GWL_STYLE);
							if ((style & BS_AUTOCHECKBOX) != BS_AUTOCHECKBOX)
								SendMessage(focus, BM_SETSTYLE, BS_DEFPUSHBUTTON, TRUE);
						}
						break;//避免点击输出栏发生异常
					}
				case NM_RETURN: {
					PNMLINK pNMLink = (PNMLINK)lParam;
					LITEM   item    = pNMLink->item;
					if ((((LPNMHDR)lParam)->hwndFrom == TxLnk) && (item.iLink == 0)) {
						ShellExecuteW(NULL, L"open", item.szUrl, NULL, NULL, SW_SHOW);
					} else if (wcscmp(item.szID, L"idInfo") == 0) {
						MessageBox(hwnd, "This isn't much help.", "Example", MB_OK);
					}
					break;
				}
			}
			break;
		case WM_LBUTTONDOWN:
			//实现空白处随意拖动
			SendMessage(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
			break;
		case WM_SYSCOMMAND:
			switch (wParam) {
				case 2: {
					if (error == -1)error = GetLastError();
					LPSTR szError = NULL;
					FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
					              NULL, error, 0, (PTSTR)&szError, 0, NULL);
					char s[BUFSIZ] = {};
					sprintf(s, "GetLastError上一个错误：\n%u：%s", error, szError);
					LocalFree(HLOCAL(szError));
					MessageBox(hwnd, s, "上一个错误", MB_OK | MB_ICONINFORMATION);
					error = -1;
					break;
				}
				case 3: {
					//判断有没有启动
					HWND h = FindWindow("TaskManagerWindow", NULL);
					BYTE nCount = 0;
					if (!h) {
						//如果还没有就先启动
						WinExec("taskmgr", SW_SHOW);
						ge;
						do {
							//最多等待5秒，否则停止搜寻，防止无响应
							if (++nCount == 100) {
								SetWindowText(TxOut, "启动失败");
								return FALSE;
							}
							//等待窗口创建完成
							Sleep(50);
							h = FindWindow("TaskManagerWindow", NULL);
						} while (!h);
					}
					//获取菜单，取得勾选状态
					HMENU hm = GetMenu(h);
					MENUITEMINFO mii = {sizeof(MENUITEMINFO), MIIM_STATE};
					GetMenuItemInfo(hm, 0x7704, FALSE, &mii);
					//如果未勾选就模拟勾选
					if (!(mii.fState & MFS_CHECKED))
						PostMessage(h, WM_COMMAND, 0x7704, 0);
					SetWindowText(TxOut, "启动完成");
					break;
				}
				case 4: {
					//获取缓存目录，保存日志
					char szTempPath[MAX_PATH];
					GetTempPath(MAX_PATH, szTempPath);
					HANDLE hFile = CreateFile(strcat(szTempPath, "\\ToolkitLog.txt"), GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
					WriteFile(hFile, sOutPut.c_str(), sOutPut.size() + 1, NULL, NULL);
					FlushFileBuffers(hFile);
					//打开文件句柄
					ShellExecute(hwnd, "open", szTempPath, NULL, NULL, SW_SHOW);
					CloseHandle(hFile);
					break;
				}
				case SC_CLOSE:
					if((GetAsyncKeyState(VK_MENU) & 1)/* && (GetAsyncKeyState(VK_F4) & 1)*/)break;//Alt+F4不最小化，直接关闭
					PostMessage(hwnd, WM_SYSCOMMAND, SC_MINIMIZE, lParam);//改为最小化
					return TRUE;
				case SC_MINIMIZE:
					SetActiveWindow(hwnd);//TODO: 检查崩溃问题
					focus = GetFocus();//防止最小化后焦点失效
			}
			return DefWindowProc(hwnd, Message, wParam, lParam);
		case WM_SIZE:
			if (wParam == SIZE_MINIMIZED) {
				ShowWindow(hwnd, SW_HIDE); //隐藏
				return TRUE;
			}
		/* All other messages (a lot of them) are processed using default procedures */
		default:
			if (Message == WM_TASKBAR)
				Shell_NotifyIcon(NIM_ADD, &icon);
			return DefWindowProc(hwnd, Message, wParam, lParam);
	}
	return TRUE;
}
/* The 'main' function of Win32 GUI programs: this is where execution starts */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	//SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
	SetUnhandledExceptionFilter(GlobalExceptionHandler);
	//判断是否为系统权限
	//https://www.cnblogs.com/idebug/p/11124664.html
	BOOL bIsLocalSystem = FALSE;
	PSID psidLocalSystem;
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	BOOL fSuccess = AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
	                0, 0, 0, 0, 0, 0, 0, &psidLocalSystem);
	if (fSuccess) {
		fSuccess = CheckTokenMembership(0, psidLocalSystem, &bIsLocalSystem);
		FreeSid(psidLocalSystem);
	}
	//以System权限启动自身
	//详见https://blog.csdn.net/weixin_42112038/article/details/126308315
	int argc; bool bStartAsSystem = false;
	LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argv){
		bStartAsSystem = (!_wcsicmp(argv[1], L"-s") || !_wcsicmp(argv[1], L"/s"));
		LocalFree(argv);
	}
	if (!bIsLocalSystem && bStartAsSystem) {
		EnableDebugPrivilege();
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetProcessIDFromName("lsass.exe"));
		if (!hProcess)hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetProcessIDFromName("winlogon.exe"));
		HANDLE hTokenx, hToken;
		OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hTokenx);
		DuplicateTokenEx(hTokenx, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hToken);
		CloseHandle(hProcess);
		CloseHandle(hTokenx);
		STARTUPINFOW si;
		PROCESS_INFORMATION pi;
		ZeroMemory(&si, sizeof(STARTUPINFOW));
		si.cb = sizeof(STARTUPINFOW);
		GetStartupInfoW(&si);
		BOOL bResult = CreateProcessWithTokenW(hToken, LOGON_NETCREDENTIALS_ONLY, NULL, GetCommandLineW(), NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi);
		error = GetLastError();
		CloseHandle(hToken);
		if (bResult)return 0;
		else MessageBox(NULL, "无法以系统权限运行本程序，已以普通方式运行。欲了解更多信息，请查看上一个错误。", "极域工具包", MB_ICONERROR | MB_OK);
	}
	//主程序开始
	WNDCLASSEX wc; /* A properties struct of our window */
	MSG msg; /* A temporary location for all messages */
	/* zero out the struct and set the stuff we want to modify */
	memset(&wc, 0, sizeof(wc));
	wc.cbSize		 = sizeof(WNDCLASSEX);
	wc.lpfnWndProc	 = WndProc; /* This is where we will send messages to */
	wc.hInstance	 = hInstance;
	wc.hCursor		 = LoadCursor(NULL, IDC_ARROW);

	/* White, COLOR_WINDOW is just a #define for a system color, try Ctrl+Clicking it */
	wc.hbrBackground = (HBRUSH)COLOR_WINDOW;
	wc.lpszClassName = "WindowClass";
	wc.hIcon		 = LoadIcon(hInstance, "A"); /* Load a standard icon */
	wc.hIconSm		 = LoadIcon(hInstance, "A"); /* use the name "A" to use the project icon */

	if (!RegisterClassEx(&wc)) {
		MessageBox(NULL, "窗口类注册失败！这是一个很罕见的问题，建议是重启或稍后重试。", "极 域 工 具 包", MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	//随机窗口名
	hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, "WindowClass", RandomWindowTitle(), (WS_OVERLAPPEDWINDOW | WS_VISIBLE)^WS_MAXIMIZEBOX ^ WS_SIZEBOX, 0, 0, width, height, NULL, NULL, hInstance, NULL);

	if (hwnd == NULL) {
		MessageBox(NULL, "窗口创建失败！这是一个很罕见的问题，建议是重启或稍后重试。", "极 域 工 具 包", MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	ShowWindow(hwnd, nCmdShow);
	UpdateWindow(hwnd);
	/*
		This is the heart of our program where all input is processed and
		sent to WndProc. Note that GetMessage blocks code flow until it receives something, so
		this loop will not produce unreasonably high CPU usage
	*/
	while (GetMessage(&msg, NULL, 0, 0) > 0) { /* If no error is received... */
		if (!IsDialogMessage(hwnd, &msg)) {
			TranslateMessage(&msg); /* Translate key codes to chars if present */
			DispatchMessage(&msg); /* Send it to WndProc */
		}
	}
	return msg.wParam;
}

//https://blog.csdn.net/yanglx2022/article/details/46582629
DWORD GetProcessIDFromName(LPCSTR szName) {
	DWORD id = 0;       // 进程ID
	PROCESSENTRY32 pe;  // 进程信息
	pe.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // 获取系统进程列表
	if (Process32First(hSnapshot, &pe)) {   // 返回系统中第一个进程的信息
		do {
			if (0 == _stricmp(pe.szExeFile, szName)) { // 不区分大小写比较
				id = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe));     // 下一个进程
	}
	CloseHandle(hSnapshot);     // 删除快照
	return id;
}

//https://blog.csdn.net/liu_zhou_zhou/article/details/118603143
BOOL GetMythwarePasswordFromRegedit(char *str) {
	HKEY retKey;
	BYTE retKeyVal[MAX_PATH * 2] = { 0 };
	DWORD nSize = MAX_PATH * 2;
	LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\TopDomain\\e-Learning Class\\Student", 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &retKey);
	if (ret != ERROR_SUCCESS) {
		return FALSE;
	}
	ret = RegQueryValueExA(retKey, "knock1", NULL, NULL, (LPBYTE)retKeyVal, &nSize);
	RegCloseKey(retKey);
	if (ret != ERROR_SUCCESS) {
		return FALSE;
	}
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

//用杀掉每个线程的方法解决某些进程hook住了TerminateProcess()的问题
bool KillProcess(DWORD dwProcessID, int way) {
	if (way == KILL_FORCE) {
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessID);
		if (hSnapshot != INVALID_HANDLE_VALUE) {
			bool rtn = true;
			THREADENTRY32 te = {sizeof(te)};
			BOOL fOk = Thread32First(hSnapshot, &te);
			for (; fOk; fOk = Thread32Next(hSnapshot, &te)) {
				if (te.th32OwnerProcessID == dwProcessID) {
					HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, te.th32ThreadID);
					if (!TerminateThread(hThread, 0)) rtn = false;
					CloseHandle(hThread);
				}
			}
			CloseHandle(hSnapshot);
			return rtn;
		}
		return false;
	} else if (way == KILL_DEFAULT) {
		//默认方法，稳定安全
		HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessID);
		WINBOOL sta = TerminateProcess(handle, 0);
		CloseHandle(handle);
		return sta;
	}
	return false;
}

DWORD WINAPI ThreadProc(LPVOID lpParameter) {
	while (true) {
		SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
		Sleep(40);//无需过快置顶，这个东西特别耗CPU
	}
	return 0L;
}

LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {
	return FALSE;
}
//https://www.52pojie.cn/thread-542884-1-1.html 有删改 TODO: 尝试FreeModule(libTDMaster.dll)
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
		ClipCursor(0);
		Sleep(25);
		UnhookWindowsHookEx(mseHook);
	}
	return 0;
}

LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HCBT_ACTIVATE) {
		HWND msgHwnd = HWND(wParam);
		char szClass[7];
		GetClassName(msgHwnd, szClass, 7);
		if (_stricmp("#32770", szClass) == 0) { //判断传入窗口是否是MessageBox的窗口
			//获取窗口标题
			int nLength = GetWindowTextLength(msgHwnd);
			char szName[nLength + 2];
			GetWindowText(msgHwnd, szName, nLength + 1);
			if (_stricmp(szName, "实时监测") == 0) {
				SetDlgItemText(msgHwnd, IDYES, "关闭");
				SetDlgItemText(msgHwnd, IDNO, "强制关闭");
				SetDlgItemText(msgHwnd, IDCANCEL, "取消");
				HMENU msgMenu = GetSystemMenu(msgHwnd, FALSE);
				EnableMenuItem(msgMenu, SC_CLOSE, MF_GRAYED);
			} else if (_stricmp(szName, "USB Setting") == 0) {
				SetDlgItemText(msgHwnd, IDYES, "软解禁");
				SetDlgItemText(msgHwnd, IDNO, "硬解禁");
			} else if (_stricmp(szName, "程序出现异常") == 0) {
				SetDlgItemText(msgHwnd, IDYES, "终止程序");
				SetDlgItemText(msgHwnd, IDNO, "继续");
			}
			
		}
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

BOOL CALLBACK SetWindowFont(HWND hwndChild, LPARAM lParam) {
	SendMessage(hwndChild, WM_SETFONT, WPARAM(lParam), 0);
	return TRUE;
}

//https://blog.csdn.net/zuishikonghuan/article/details/47746451
BOOL EnableDebugPrivilege() {
	HANDLE hToken;
	LUID Luid;
	TOKEN_PRIVILEGES tp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))return FALSE;

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid)) {
		CloseHandle(hToken);
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = Luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL)) {
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);
	return TRUE;
}

//挂起进程，调用未公开函数NtSuspendProcess。suspend参数决定挂起/恢复
typedef NTSTATUS(NTSYSAPI NTAPI *NtSuspendProcess)(IN HANDLE Process);
typedef NTSTATUS(NTSYSAPI NTAPI *NtResumeProcess)(IN HANDLE Process);
BOOL SuspendProcess(DWORD dwProcessID, BOOL suspend) {
	NtSuspendProcess mNtSuspendProcess;
	NtResumeProcess mNtResumeProcess;
	HMODULE ntdll = GetModuleHandle("ntdll.dll");
	HANDLE handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, dwProcessID);
	if (suspend) {
		mNtSuspendProcess = (NtSuspendProcess)GetProcAddress(ntdll, "NtSuspendProcess");
		return mNtSuspendProcess(handle) == 0;
	} else {
		mNtResumeProcess = (NtResumeProcess)GetProcAddress(ntdll, "NtResumeProcess");
		return mNtResumeProcess(handle) == 0;
	}
}

//在原结构之后加上不影响结构大小的线程数组，巧妙运用越界带来的跨结构访问后面的线程结构
typedef struct _MYSYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG PageDirectoryBase;
	VM_COUNTERS VirtualMemoryCounters;
	SIZE_T PrivatePageCount;
	IO_COUNTERS IoCounters;
	//以上为原结构内容
	SYSTEM_THREAD_INFORMATION Threads[0];
} MYSYSTEM_PROCESS_INFORMATION, *PMYSYSTEM_PROCESS_INFORMATION;

//覆盖原定义
#define SYSTEM_PROCESS_INFORMATION MYSYSTEM_PROCESS_INFORMATION
#define PSYSTEM_PROCESS_INFORMATION PMYSYSTEM_PROCESS_INFORMATION

//定义函数原型
typedef NTSTATUS(NTSYSAPI NTAPI *FunNtQuerySystemInformation)
(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation,
 IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);

//获取进程的状态
//返回-1，表示发生异常
//返回0，表示进程没有被挂起
//返回1，表示进程处于挂起状态
int GetProcessState(DWORD dwProcessID) {
	int nStatus = -1;
	//取函数地址
	FunNtQuerySystemInformation mNtQuerySystemInformation = FunNtQuerySystemInformation(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation"));
	//先调用一次，获取所需缓冲区大小
	DWORD dwSize;
	mNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &dwSize);
	//申请缓冲区
	HGLOBAL hBuffer = GlobalAlloc(LPTR, dwSize);
	if (hBuffer == NULL)
		return nStatus;
	PSYSTEM_PROCESS_INFORMATION pInfo = PSYSTEM_PROCESS_INFORMATION(hBuffer);
	//查询
	NTSTATUS lStatus = mNtQuerySystemInformation(SystemProcessInformation, pInfo, dwSize, 0);
	if (!NT_SUCCESS(lStatus)) {
		GlobalFree(hBuffer);
		//NTSTATUS 转 win32 error
		typedef DWORD (NTAPI *RtlNtStatusToDosErrorNoTeb)(NTSTATUS Status);
		RtlNtStatusToDosErrorNoTeb mRtlNtStatusToDosErrorNoTeb = RtlNtStatusToDosErrorNoTeb(GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlNtStatusToDosErrorNoTeb"));
		error = mRtlNtStatusToDosErrorNoTeb(lStatus);
		return nStatus;
	}
	//遍历进程
	while (true) {
		//判断是否是目标进程
		if (((DWORD)(ULONG_PTR) pInfo->UniqueProcessId) == dwProcessID) {
			nStatus = 1;
			//遍历线程
			for (ULONG i = 0; i < pInfo->NumberOfThreads; i++) {
				//如果不是在挂起，就表明程序存活，可以返回（堵塞、无响应不算挂起）
				if (pInfo->Threads[i].WaitReason != Suspended) {
					nStatus = 0;
					break;
				}
			}
			break;
		}
		//遍历进程完成
		if (pInfo->NextEntryOffset == 0)
			break;
		//移动到下一个进程信息结构的地址
		pInfo = PSYSTEM_PROCESS_INFORMATION(PBYTE(pInfo) + pInfo->NextEntryOffset);
	}
	//释放缓冲区
	GlobalFree(hBuffer);
	return nStatus;
}

//屏幕广播标题
LPCSTR sBdCst[2] = {"屏幕广播", " 正在共享屏幕"};
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
	//是否是afx类名（极域使用了MFC框架），这样减少很多比较，提高效率的同时又能减少误杀
	char szClass[5];
	GetClassName(hwnd, szClass, 5);
	if (_stricmp(szClass, "Afx:") == 0) {
		//获取窗口标题
		int nLength = GetWindowTextLength(hwnd);
		char szName[nLength + 2];
		GetWindowText(hwnd, szName, nLength + 1);
		//比较标题，分别是全文比较和比较末尾
		if (_stricmp(szName, sBdCst[0]) == 0 ||
		    _stricmp(szName + nLength - strlen(sBdCst[1]), sBdCst[1]) == 0) {
			//将目标窗口句柄通过lParam传回调用处
			HWND* pBdCst = (HWND*) lParam;
			*pBdCst = hwnd;
			return FALSE;
		}
	}
	return TRUE;
}

bool SetupTrayIcon(HWND m_hWnd, HINSTANCE hInstance) {
	icon.cbSize = sizeof(NOTIFYICONDATA); // 结构大小
	icon.hWnd = m_hWnd; // 接收 托盘通知消息 的窗口句柄
	icon.uID = 0;
	icon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; //表示uCallbackMessage 有效
	icon.uCallbackMessage = WM_USER + 3; // 消息被发送到此窗口过程
	icon.hIcon = LoadIcon(hInstance, "A");
	strcpy(icon.szTip, "极域工具包");             // 提示文本
	return 0 != Shell_NotifyIcon(NIM_ADD, &icon);
}

inline LPCSTR RandomWindowTitle() {
	//随机窗口名
	std::srand((unsigned) time(NULL));
	LPSTR title = new char[11];
	memset(title, 0, 11);
	for (int i = 0; i < 10; i++) {
		int u = std::rand(), c = u % 31;//求余31是为了减少数字出现概率
		if (c < 5)title[i] = u % 10 + '0';
		else if (c < 18)title[i] = u % 26 + 'a';
		else title[i] = u % 26 + 'A';
	}
	return title;
}

// 定义全局异常处理函数
LONG WINAPI GlobalExceptionHandler(EXCEPTION_POINTERS* exceptionInfo)
{
	// 弹出对话框并显示异常内容
	char message[BUFSIZ * 2] = {};
	sprintf(message, "异常代码：0x%08X\n程序将%s，如此问题依旧存在，请联系开发者", exceptionInfo->ExceptionRecord->ExceptionCode,
		((exceptionInfo -> ExceptionRecord -> ExceptionFlags) & EXCEPTION_NONCONTINUABLE) ? "退出" : "尝试继续执行");
	HHOOK hCBTHook = SetWindowsHookEx(WH_CBT, CBTProc, NULL, GetCurrentThreadId());
	int id = MessageBox(NULL, message, "程序出现异常", MB_ICONERROR | MB_YESNO | MB_DEFBUTTON2);
	UnhookWindowsHookEx(hCBTHook);
	if(id == IDYES){
		//LPSTR szCmd = GetCommandLine();
		//WinExec(szCmd, SW_SHOW);
		//return EXCEPTION_EXECUTE_HANDLER;
		return EXCEPTION_CONTINUE_SEARCH;
	} else if(id == IDNO){
		// 返回处理结果，继续执行程序或退出
		return ((exceptionInfo -> ExceptionRecord -> ExceptionFlags) & EXCEPTION_NONCONTINUABLE)?
		EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_EXECUTION;
	}
}

inline void PrtError(LPCSTR szDes, LRESULT lResult) {
	DWORD dwError = lResult == NULL ? GetLastError() : lResult & 0x0000FFFF;
	LPSTR szError = NULL;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
	              NULL, dwError, 0, (PTSTR)&szError, 0, NULL);
	char s[BUFSIZ] = {};
	sprintf(s, "%s：%u-%s", szDes, dwError, szError);
	LocalFree(HLOCAL(szError));
	size_t uSize = strlen(s);
	//过滤末尾换行符
	if(*(s+uSize-1) == '\n')*(WORD*)(s+uSize-2) = 0;
	Println(s);
}

inline LPSTR FormatLogTime(){
	//申请内存，获得时间
	LPVOID lpBuffer = VirtualAlloc(NULL, 64, MEM_COMMIT, PAGE_READWRITE);
	SYSTEMTIME time;
	GetLocalTime(&time);
	LPSTR szBuffer = LPSTR(lpBuffer);
	//格式化
	sprintf(szBuffer, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] ", 
		time.wYear, time.wMonth, time.wDay,
		time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
	return szBuffer;
}
