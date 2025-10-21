#pragma GCC optimize(3) //�Ż�
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <fltuser.h>
#include <userenv.h>
#include <commctrl.h>
#include <versionhelpers.h>
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <cmath>
#undef UNICODE
#undef _UNICODE

BOOL GetMythwarePasswordFromRegedit(char *str);
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
DWORD WINAPI KeyHookThreadProc(LPVOID lpParameter);
DWORD WINAPI MouseHookThreadProc(LPVOID lpParameter);

DWORD WINAPI ThreadProc(LPVOID lpParameter);
BOOL CALLBACK SetWindowFont(HWND hwndChild, LPARAM lParam);
bool SetupTrayIcon(HWND m_hWnd, HINSTANCE hInstance);
LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam);

void InitNTAPI();
LPCSTR RandomWindowTitle();
BOOL EnableDebugPrivilege();
DWORD GetProcessIDFromName(LPCSTR szName);
bool KillProcess(DWORD dwProcessID, int way);
bool KillAllProcessWithName(LPCSTR name, int way);
BOOL SuspendProcess(DWORD dwProcessID, BOOL suspend);
int GetProcessState(DWORD dwProcessID);
#define KILL_FORCE 1
#define KILL_DEFAULT 2
#define Set(dest, source) *(PVOID*)&(dest) = (PVOID)(source) //ǿ���޸Ĳ�ָͬ�������ݵ�ֵ

LONG WINAPI GlobalExceptionHandler(EXCEPTION_POINTERS* exceptionInfo);
inline void PrtError(LPCSTR szDes, LRESULT lResult);
inline LPSTR FormatLogTime();

std::string sOutPut;
#define Print(text) sOutPut=sOutPut+FormatLogTime()+text
#define Println(text) Print(text); sOutPut+="\r\n"
#define ge error = GetLastError()
HHOOK kbdHook, mseHook;
HWND hwnd, focus; /* A 'HANDLE', hence the H, or a pointer to our window */
/* This is where all the input to the window goes to */
LPCSTR MythwareFilename = "StudentMain.exe";//������ĳɱ�ı���ԡ����ݡ�������ӽ���
HWND hBdCst;
//LONG fullScreenStyle = WS_POPUP | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN, windowingStyle = fullScreenStyle | WS_OVERLAPPEDWINDOW ^ WS_OVERLAPPED;
NOTIFYICONDATA icon;
HMENU hMenu;//���̲˵�
int width = 528, height = 250, w, h, mwSts;
bool asking = false, ask = false, closingProcess = false;
DWORD error = -1;//���ڵ���
POINT p, pt;
HWND BtAbt, BtKmw, TxOut, TxLnk, BtTop, BtCur, BtKbh, BtSnp, BtWnd;
LPCSTR helpText = "���򹤾߰� v1.2.4 | С�����ƶ� | ����Ⱥ828869154����Ⱥ��ע�����򹤾߰���\n\
���⹦�ܣ�1. ��ݼ�Alt+C˫��ɱ����ǰ���̣�Alt+W��С�����㴰�ڣ�Alt+B����������\n\
2. �����������Ļ���Ͻ�/���Ͻ�ʱ������ѡ����С��/�رս��㴰�ڣ���Ҳ���Թرմ˹��ܣ�\n\
3. ��С��ʱ���ص����������̣����˫���������棬�Ҽ����������˵�\n\
4. ������߿ɽ��Chrome��Edge��С��Ϸ������ʾ����ʧ�ܣ���������Ȩ�޻�ָ��ע�����ֵ�����ڣ��ڴ�����£�ͨ��������������\n\
5. ����������������Alt+Ctrl+Delete��Чʱ�����¹�ѡ���ɣ��Լ���Ĵ����������ֻ��2015/2016�����ͨ��\n\
6. ����ʱ����-s��/s�����п���SystemȨ������\n\
7. MeltdownDFCΪ���㻹ԭ�����ƽ⹤�ߣ�crdiskΪ��������ϵͳɾ�����ߣ����ã���";
HANDLE thread/*����ˢ���ö�����Timer����bug*/, mouHook/*�������*/, keyHook/*�������*/;
UINT WM_TASKBAR;
enum RunLevel {RL_UNKNOWN, RL_USER, RL_ADMIN, RL_SYSTEM} eLevel;
struct MW_INFO {
	HWND hwndOfBoardcast;
	DWORD pid;
	bool bNotResponding;
};
struct { //����ʵ��VB�����������
	int m_rndSeed = 327680;
	void Randomize(double Number) {
		int num = m_rndSeed, num2;
		unsigned char bytes[sizeof(double)];
		memcpy(bytes, &Number, sizeof(double));
		memcpy(&num2, bytes + 4, sizeof(int));
		num2 = ((num2 & 65535) ^ (num2 >> 16)) << 8;
		num = (num & -16776961) | num2;
		m_rndSeed = num;
	}
	float Rnd() {
		return Rnd(1.f);
	}
	float Rnd(float Number) {
		int num = m_rndSeed;
		if ((double)Number != 0.0) {
			if ((double)Number < 0.0) {
				num = *(int*)(&Number);
				long long num2 = (long long)num & (long long)((unsigned long long)(-1));
				num = (int)((num2 + (num2 >> 24)) & 16777215L);
			}
			num = (int)(((long long)num * 1140671485L + 12820163L) & 16777215L);
		}
		m_rndSeed = num;
		return (float)num / 16777216.f;
	}
} VBMath;

LRESULT CALLBACK WndProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
	switch (Message) {
		case WM_CREATE: {
			//��ȡϵͳ�汾��
			OSVERSIONINFO vi = {sizeof(OSVERSIONINFO)};
			GetVersionEx(&vi);
			SYSTEM_INFO si = {};
			GetNativeSystemInfo(&si);
			char szVersion[BUFSIZ] = {};
			sprintf(szVersion, "ϵͳ�汾��%u.%u.%u %d-bit\n����汾��%s %d-bit\n",
				vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber, (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) ? 64 : 32, 
				"1.2.4", sizeof(PVOID)*8);
			sOutPut += szVersion;
			EnableDebugPrivilege();//��Ȩ
			w = GetSystemMetrics(SM_CXSCREEN) - 1;//��Ļ���ȣ�ע���ʵ�ʿɴﵽ�������1��
			h = GetSystemMetrics(SM_CYSCREEN) - 1;//��Ļ�߶�
			WM_TASKBAR = RegisterWindowMessage("TaskbarCreated");//�����������¼�
			thread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);//�ö�����
			keyHook = CreateThread(NULL, 0, KeyHookThreadProc, NULL, CREATE_SUSPENDED, NULL);//������
			mouHook = CreateThread(NULL, 0, MouseHookThreadProc, NULL, CREATE_SUSPENDED, NULL);//�����
			SetTimer(hwnd, 1, 1000, NULL); //���������Ͻ�
			SetTimer(hwnd, 2, 2000, NULL); //��⼫��״̬�����±���
			RegisterHotKey(hwnd, 0, MOD_ALT, 'C'); //Alt+C+Cǿ�ƽ�����ǰ����
			RegisterHotKey(hwnd, 1, MOD_ALT, 'W'); //Alt+W��С�����㴰��
			if(!RegisterHotKey(hwnd, 2, MOD_ALT, 'B')) //Alt+B��ʾ�˴���
				if(MessageBox(hwnd, "ע��ϵͳ���ȼ� Alt+B ʧ�ܣ��п��ܸ�Ӧ�õ���һʵ���������У����ȹر������������������򣡷��򻽳����ڹ��ܽ�ʧЧ���������ȡ��������ֹ�����������", "�� �� �� �� ��", MB_OKCANCEL | MB_ICONWARNING)==IDCANCEL){
					PostQuitMessage(0);
					return FALSE;
				}
			HINSTANCE hi = ((LPCREATESTRUCT) lParam)->hInstance;
			TxLnk = CreateWindow("SysLink", "���򹤾߰� <a href=\"https://github.com/BengbuGuards/MythwareToolkit\">GitHub</a>", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 8, 8, 120, 20, hwnd, HMENU(1001), hi, NULL);
			BtAbt = CreateWindow(WC_BUTTON, "����/����", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 166, 3, 90, 30, hwnd, HMENU(1002), hi, NULL);
			//��ȡ����
			char str[BUFSIZ] = {};
			LPCSTR psd;
			if (!GetMythwarePasswordFromRegedit(str))
				psd = "��ȡ����ʧ��";
			else psd = str;
			CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, psd, WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_READONLY, 8, 36, 248, 20, hwnd, HMENU(1003), hi, NULL);
			CreateWindow(WC_BUTTON, "ɱ��ѧ��������������", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,  8, 64, 248, 50, hwnd, HMENU(1013), hi, NULL);
			BtKmw = CreateWindow(WC_BUTTON, "ɱ������", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_SPLITBUTTON, 8, 122, 248, 50, hwnd, HMENU(1004), hi, NULL);
			TxOut = CreateWindow(STATUSCLASSNAME, "�ȴ�����", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, HMENU(1005), hi, NULL);
			int pts[2] = {352, -1};
			SendMessage(TxOut, SB_SETPARTS, WPARAM(2), LPARAM(pts));
			CreateWindow(WC_BUTTON, "������ù���", WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 264, 8, 248, 98, hwnd, NULL, hi, NULL);
			CreateWindow(WC_BUTTON, "һ�����ϵͳ����", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 272, 28, 112, 30, hwnd, HMENU(1007), hi, NULL);
			CreateWindow(WC_BUTTON, "���������������", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 272, 66, 112, 30, hwnd, HMENU(1008), hi, NULL);
			CreateWindow(WC_BUTTON, "�������U������", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 392, 66, 112, 30, hwnd, HMENU(1009), hi, NULL);
			CreateWindow(WC_BUTTON, "������Դ������", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 392, 28, 112, 30, hwnd, HMENU(1010), hi, NULL);
			CreateWindow(WC_BUTTON, "�㲥���ڻ�", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | WS_DISABLED, 264, 112, 120, 30, hwnd, HMENU(1014), hi, NULL);
			CreateWindow(WC_BUTTON, "������������(&P)", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 392, 112, 120, 30, hwnd, HMENU(1015), hi, NULL);
			CreateWindow(WC_BUTTON, "MeltdownDFC", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 264, 150, 120, 22, hwnd, HMENU(1019), hi, NULL);
			CreateWindow(WC_BUTTON, "crdisk", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 392, 150, 120, 22, hwnd, HMENU(1020), hi, NULL);
			
			BtWnd = CreateWindow(WC_BUTTON, "��������ⵯ��", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 385, 176, 130, 18, hwnd, HMENU(1012), hi, NULL);
			BtSnp = CreateWindow(WC_BUTTON, "��ֹ����", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX | (IsWindows7OrGreater() ? 0 : WS_DISABLED), 309, 176, 65, 18, hwnd, HMENU(1011), hi, NULL);
			SendMessage(BtSnp, BM_SETCHECK, BST_CHECKED, 0);
			SendMessage(hwnd, WM_COMMAND, 1011, 0);
			BtTop = CreateWindow(WC_BUTTON, "�ö��˴���", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 8, 176, 77, 18, hwnd, HMENU(1016), hi, NULL);
			SendMessage(BtTop, BM_SETCHECK, BST_CHECKED, 0);
			BtCur = CreateWindow(WC_BUTTON, "����������(&M)", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 95, 176, 107, 18, hwnd, HMENU(1017), hi, NULL);
			BtKbh = CreateWindow(WC_BUTTON, "�������(&C)", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 213, 176, 85, 18, hwnd, HMENU(1018), hi, NULL);
			
			HWND hToolTip = CreateWindowEx(WS_EX_TOPMOST, TOOLTIPS_CLASS, NULL, WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hwnd, NULL, hi, NULL);
			TOOLINFO ti = { sizeof(ti) };
			ti.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
			ti.hwnd = hwnd;
			ti.uId = (UINT_PTR)TxOut;
			switch(eLevel){
				case RL_USER:
					ti.lpszText = "�û�Ȩ��";
					break;
				case RL_ADMIN:
					ti.lpszText = "����ԱȨ��";
					break;
				case RL_SYSTEM:
					ti.lpszText = "ϵͳȨ��";
					break;
				default:
					ti.lpszText = "Ȩ��δ֪";
			}
			SendMessage(hToolTip, TTM_ADDTOOL, 0, (LPARAM)&ti);

			HFONT hFont = NULL;
			NONCLIENTMETRICS info;
			info.cbSize = sizeof(NONCLIENTMETRICS);
			if (SystemParametersInfo (SPI_GETNONCLIENTMETRICS, 0, &info, 0)) {
				hFont = CreateFontIndirect ((LOGFONT*)&info.lfMessageFont);
			}//ȡϵͳĬ������
			EnumChildWindows(hwnd, SetWindowFont, LPARAM(hFont));
			SetupTrayIcon(hwnd, hi);
			HMENU sys = GetSystemMenu(hwnd, FALSE);//ϵͳ�˵�
			AppendMenu(sys, MF_STRING, 2, "��ʾ��һ������(&E)");
			AppendMenu(sys, MF_STRING, 4, "��ʾ������־(&L)");
			AppendMenu(sys, MF_STRING, 3, "�������������(&T)");
			// EnableMenuItem(sys, SC_CLOSE, MF_BYCOMMAND | MF_GRAYED);
			DrawMenuBar(hwnd);
			focus = GetDlgItem(hwnd, 1013);
			SetFocus(focus);
			SendMessage(hwnd, WM_TIMER, WPARAM(2), 0);
			//ж�ؼ��������ֹhook
			HMODULE hook = NULL;
			if (sizeof(PVOID) == 8)hook = GetModuleHandle("LibTDProcHook64.dll");
			else hook = GetModuleHandle("LibTDProcHook32.dll");
			if (hook)FreeModule(hook);
			break;
		}
		case WM_INITMENU: { //˫��ͼ��Ĭ����С��
			HMENU sys = GetSystemMenu(hwnd, FALSE);
			SetMenuDefaultItem(sys, SC_MINIMIZE, 0);
			break;
		}
		case WM_COMMAND: {
			switch (LOWORD(wParam)) {
				case 1002: {
					MessageBox(NULL, helpText, "����/����", MB_OK | MB_ICONINFORMATION);
					break;
				}
				case 1004: {
					if (mwSts != 2) {
						if (KillProcess(GetProcessIDFromName(MythwareFilename), KILL_FORCE)) {
							SetWindowText(TxOut, "ִ�гɹ�");
							Sleep(30);
							SendMessage(hwnd, WM_TIMER, WPARAM(2), 0);
						} else {
							ge;
							SetWindowText(TxOut, "ִ��ʧ��");
						}
					} else { //��Ȩ��������
						HKEY retKey;//�ȶ�ȡ����·��
						char szPath[MAX_PATH * 2];
						LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\TopDomain\\e-Learning Class Standard\\1.00", 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &retKey);
						if (ret != ERROR_SUCCESS) {
							ge;
							SetWindowText(TxOut, "��ȡ·��ʧ��");
							RegCloseKey(retKey);
							break;
						}
						DWORD dataLong = MAX_PATH * 2, type = REG_SZ;
						ret = RegQueryValueEx(retKey, "TargetDirectory", 0, &type, LPBYTE(szPath), &dataLong);
						RegCloseKey(retKey);

						if (ret != ERROR_SUCCESS) {
							ge;
							SetWindowText(TxOut, "��ȡ·��ʧ��");
							break;
						}
						HWND hwnd = FindWindow("Shell_TrayWnd", NULL);//����������Ĵ���һ��������explorer.exe
						DWORD pid;
						GetWindowThreadProcessId(hwnd, &pid);//���������PID
						HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
						if (!handle) {
							SetWindowText(TxOut, "����������Դ������");
							break;
						}
						HANDLE token;
						OpenProcessToken(handle, TOKEN_DUPLICATE, &token);//ȡ��token
						DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &token);
						STARTUPINFO si = {};//��Ҫ��һЩ����......
						PROCESS_INFORMATION pi = {};
						si.cb = sizeof(STARTUPINFO);
						si.dwFlags = STARTF_USESHOWWINDOW;
						si.wShowWindow = SW_SHOW;
						BOOL bResult = CreateProcessAsUser(token, strcat(szPath, MythwareFilename), NULL, NULL, NULL,
						                                   FALSE, CREATE_NEW_PROCESS_GROUP | NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi); //��������
						if (bResult) {
							SetWindowText(TxOut, "�����ɹ�");
							CloseHandle(pi.hProcess);
							CloseHandle(pi.hThread);
						} else {
							ge;
							SetWindowText(TxOut, "����ʧ��");
						}

						CloseHandle(handle);
						CloseHandle(token);
						SendMessage(hwnd, WM_TIMER, WPARAM(2), 0);
					}
					break;
				}
				case 1007: {
					BYTE cStatus = 0;
					HKEY retKey;
					LONG ret;
					DWORD value = 0, out = 0, cb;
					char szPath[BUFSIZ], outputBuf[BUFSIZ];

					std::string sMsg = "������ɡ��ѽ������Ŀ�У�";

					//Ҫ��Ϊ0����Ŀ
					static const std::pair<LPCSTR, std::vector<std::pair<LPCSTR, LPCSTR>>> paths[] = {
						{"SOFTWARE\\Policies\\Microsoft\\Windows\\System", {{"DisableCMD","������ʾ��"}}},
						{"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", {
							{"DisableRegistryTools", "ע����༭��"},
							{"DisableTaskMgr", "���������"},
							{"DisableLockWorkstation", "�����˻�"},
							{"DisableChangePassword", "�޸�����"},
							{"DisableSwitchUserOption", "�л��û�"},}},
						{"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", {
							{"NoRun", "Win+R����"},
							{"RestrictRun", "������������"},
							{"NoLogOff", "ע��"},
							{"StartMenuLogOff", "��ʼ�˵�ע����ť"},
							{"NoTrayContextMenu", "�������Ҽ��˵�"},
							{"Hidden", "ǿ����ʾ�����ļ�"}, //����CurrentVersion\Explorer\Advanced\Hidden��ShowSuperHidden��HideFileExt����ѡ��������û����ã����ֶ������������������
							{"NoFolderOptions", "�ļ���ѡ��"}}},
						{"SOFTWARE\\Policies\\Microsoft\\MMC", {{"RestrictToPermittedSnapins", "΢����������̨"}}},
						{"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3", {
							{"1803", "IE��������"},
							{"2200", "IE ActiveX�ؼ�"}
						}}
					};
					for (auto p:paths){
						RegOpenKeyEx(HKEY_CURRENT_USER, p.first, 0, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
						for (auto v:p.second){
							ret = RegQueryValueEx(retKey, v.first, 0, NULL, (BYTE*)&out, &cb);
							if (out){
								ret &= RegSetValueEx(retKey, v.first, 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
								if (ret == ERROR_SUCCESS) {
									cStatus = 1;
									sprintf(outputBuf, "���%s�ɹ�", v.second);
									Println(outputBuf);
									sMsg += v.second; sMsg += "��";
								}
							}
						}
						RegCloseKey(retKey);
					}

					//Ҫɾ����ӳ��ٳ���Ŀ
					static const std::pair<LPCSTR, LPCSTR> images[] = {
						{"taskkill.exe","taskkill"},
						{"ntsd.exe", "ntsd"},
						{"tasklist.exe","tasklist"},
						{"sethc.exe","�������ܿ�ݼ���sethc.exe��"},
						{"sidebar.exe", "Win7�������"},
						{"Chess.exe", "Win7���壨Chess Titans��"},
						{"FreeCell.exe", "Win7�յ�����"},
						{"Hearts.exe", "Win7���Ĵ�ս"},
						{"Minesweeper.exe", "ɨ�ף�Minesweeper.exe��"},
						{"PurblePlace.exe", "Win7 Purble Place"},
						{"Mahjong.exe", "Win7�齫��Mahjong Titans��"},
						{"SpiderSolitaire.exe", "Win7֩��ֽ��"},
						{"bckgzm.exe", "Internet˫½��"},
						{"chkrzm.exe", "Internet����"},
						{"shvlzm.exe", "Internet������"},
						{"Solitaire.exe", "Win7ֽ��"},
						{"winmine.exe", "ɨ�ף�winmine.exe��"},
						{"Magnify.exe", "�Ŵ�"},
						{"QQPCTray.exe", "QQPCTray"}
					};
					for (std::pair<LPCSTR, LPCSTR> p:images){
						strcpy(szPath, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\");
						strcat(szPath, p.first);
						RegOpenKeyEx(HKEY_LOCAL_MACHINE, szPath, 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
						ret = RegDeleteValue(retKey, "debugger");
						if (ret == ERROR_SUCCESS) {
							sprintf(outputBuf, "���%s�ɹ�", p.second);
							Println(outputBuf);
							sMsg += p.second; sMsg += "��";
							cStatus = 1;
						}
						RegCloseKey(retKey);
					}

					//Ҫɾ������Ŀ���ָ�Ĭ��)
					static const std::pair<LPCSTR, std::vector<std::pair<LPCSTR, LPCSTR>>> deletePaths[] = {
						{"SOFTWARE\\Policies\\Google\\Chrome", {
							{"AllowDinosaurEasterEgg", "Chrome������Ϸ"},
							{"DownloadRestrictions", "Chrome��������"},
							{"SaveAs", "Chrome����Ϊ"},
							{"DeveloperToolsAvailability", "Chrome�����߹���"}}},
						{"SOFTWARE\\Policies\\Microsoft\\Edge", {
							{"AllowSurfGame", "Edge������Ϸ"},
							{"WebWidgetAllowed", "Edge������"},
							{"DownloadRestrictions", "Edge��������"},
							{"SaveAs", "Edge����Ϊ"},
							{"DeveloperToolsAvailability", "Edge�����߹���"}}},
						{"SOFTWARE\\Policies\\Mozilla\\Firefox", {
							{"DisableDownloads", "Firefox��������1"},
							{"BlockAboutDownloads", "Firefox��������2"},
							{"DeveloperToolsAvailability", "Firefox�����߹���"}
						}},
						{"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", {{"AllowMultipleTSSessions","���ն˷���Ự"}}},
						{"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", {{"HideFastUserSwitching","�����û��л�"}}},
						{"SOFTWARE\\Policies\\Microsoft\\WindowsStore", {{"RemoveWindowsStore", "WindowsӦ���̵�"}}},
					};
					for (auto p:deletePaths){
						RegOpenKeyEx(HKEY_LOCAL_MACHINE, p.first, 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
						for (auto v:p.second){
							ret = RegDeleteValue(retKey, v.first);
							if (ret == ERROR_SUCCESS) {
								cStatus = 1;
								sprintf(outputBuf, "���%s�ɹ�", v.second);
								Println(outputBuf);
								sMsg += v.second; sMsg += "��";
							}
						}
						RegCloseKey(retKey);
					}
					RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Internet Explorer\\Restrictions", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					ret = RegDeleteValue(retKey, "NoBrowserSaveAs");
					if (ret == ERROR_SUCCESS) {
						Println("���IE����Ϊ�ɹ�");
						sMsg += "IE����Ϊ��";
						cStatus = 1;
					}
					RegCloseKey(retKey);
					RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					ret = RegDeleteValue(retKey, "ShowTaskViewButton");
					if (ret == ERROR_SUCCESS) {
						Println("���������ͼ��ť�ɹ�");
						sMsg += "������ͼ��ť��";
						cStatus = 1;
					}
					RegCloseKey(retKey);
					RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					ret = RegDeleteValue(retKey, "Scancode Map");
					if (ret == ERROR_SUCCESS) {
						Println("�������ӳ��ɹ�");
						sMsg += "Tab����������ӳ�䣩��";
						cStatus = 1;
					}
					RegCloseKey(retKey);

					//����������ֶ�ĳЩ��ҳ�ķ�ɱ��v10.2�𣬰���poki��������һЩ��վ������һ�����ֶ����Ҳ��
					LPCSTR path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
					bool bHandled = false;
					HANDLE hFile = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL,
											  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
					std::string tempPath = path + std::string(".tmp");
					HANDLE hTemp = CreateFile(tempPath.c_str(), GENERIC_WRITE, 0, NULL,
											  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
					if(hFile != INVALID_HANDLE_VALUE && hTemp != INVALID_HANDLE_VALUE) {
						char buf[4096];
						DWORD read;
						std::string line;
     while (ReadFile(hFile, buf, sizeof(buf), &read, NULL) && read > 0) {
							for (DWORD i = 0; i < read; ++i) {
								if (buf[i] == '\n') {
									if (line.find("127.0.0.1") != 0 ||
										line.find_first_not_of(" \t") < line.find("127.0.0.1")) {
										line += '\n';
										WriteFile(hTemp, line.c_str(), line.size(), NULL, NULL);
									} else bHandled = true;
									line.clear();
								}
								else
									line += buf[i];
							}
						}   
						if (!line.empty()){
							if (!line.empty() && (line.find("127.0.0.1") != 0 ||
												  line.find_first_not_of(" \t") < line.find("127.0.0.1"))) {
								WriteFile(hTemp, line.c_str(), line.size(), NULL, NULL);
							} else bHandled = true;
						}
						CloseHandle(hFile);
						CloseHandle(hTemp);
						//ȥ��ϵͳ+����+ֻ�����Բ��滻�ļ�
						SetFileAttributes(path, FILE_ATTRIBUTE_NORMAL);
						DeleteFile(path);
						bool bReplaced = MoveFile(tempPath.c_str(), path);
						if(bHandled && bReplaced){
							cStatus = 1;
							sMsg += "������վ���ơ�";
						}
					}
					SetWindowText(TxOut, "���óɹ�");
					if (cStatus) {
						sMsg.pop_back(), sMsg.pop_back(); sMsg += "��";
						sMsg += "����������Դ������Ӧ��һЩ���ܣ���Ҫ�ָ�Tab��������ע�����µ�¼��";
						MessageBox(hwnd, sMsg.c_str(), "˵��", MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
					}
					break;
				}
				case 1008: {
					//TODO: �������״��
					//������ָֹ��
					HANDLE hNetFilter = CreateFile("\\\\.\\TDNetFilter", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
					if(!GetLastError()){
						DeviceIoControl(hNetFilter, 0x120014, NULL, 0, NULL, 0, NULL, 0);
						PrtError("����������ƣ�������ָֹ��", GetLastError());
						CloseHandle(hNetFilter);
					} else PrtError("����������ƣ�����������", GetLastError());
					//ɱ�����ط������ػ�����
					bool bStateM = KillProcess(GetProcessIDFromName("MasterHelper.exe"),KILL_DEFAULT);
					bool bStateG = KillProcess(GetProcessIDFromName("GATESRV.exe"),KILL_DEFAULT);
					std::string text = "����������ƣ�ֹͣ��ؽ���";
					Println(text + ((bStateM && bStateG) ? "�ɹ�" : "ʧ��"));
					//ֹͣ�����������
					SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
					SC_HANDLE hFilt = OpenService(sc, "TDNetFilter", SERVICE_STOP | DELETE);
					SERVICE_STATUS ss = {};
					bStateM = ControlService(hFilt, SERVICE_CONTROL_STOP, &ss);
					DeleteService(hFilt);
					CloseServiceHandle(sc);
					CloseServiceHandle(hFilt);
					text = "����������ƣ�ֹͣ��������";
					Println(text + (bStateM ? "�ɹ�" : "ʧ��"));
					SetWindowText(TxOut, "�������");
					break;
				}
				case 1009: {
					HHOOK hCBTHook = SetWindowsHookEx(WH_CBT, CBTProc, NULL, GetCurrentThreadId());
					int id = MessageBox(hwnd, "��ѡ��ر�USB����ģʽ��\n�����������˶˿ڷ���ֹͣ����\nӲ�����ֱ��ɾ�����������������������Чʱʹ�ã�", "USB Setting", MB_YESNOCANCEL | MB_ICONQUESTION | MB_SETFOREGROUND);
					UnhookWindowsHookEx(hCBTHook);
					if (id == IDYES) {//LibTDUsbHook10.dll
						//���ӹ��˶˿ڣ�TDUsbFilterInit��
						HANDLE hPort = NULL;
						HRESULT hResult = FilterConnectCommunicationPort(L"\\TDFileFilterPort", 0, NULL, 0, NULL, &hPort);
						if(hResult || hPort <= (HANDLE)0 || GetLastError()){
							error = hResult & 0x0000FFFF;
							SetWindowText(TxOut, "����ʧ��");
							break;
						}
						//������Ϣ��TDUsbFiltFree��
						int lpInBuffer[4] = {8, 0, 0, 0}; // [esp+0h] [ebp-10h] BYREF
						//memset(&lpInBuffer[1], 0, 12);
						//lpInBuffer[0] = 8;
						hResult = FilterSendMessage(hPort, lpInBuffer, 16/*0x10u*/, NULL, 0, NULL);
						ge;
						//�رվ����TDUsbFilterDone��
						CloseHandle(hPort);
						SetWindowText(TxOut, !hResult ? "�������" : "����ʧ��");
					} else if (id == IDNO) {
						SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
						SC_HANDLE hFilt = OpenService(sc, "TDFileFilter", SERVICE_STOP | DELETE);
						SERVICE_STATUS ss = {};
						if(ControlService(hFilt, SERVICE_CONTROL_STOP, &ss))
							SetWindowText(TxOut, "���óɹ�");
						else{
							ge;
							SetWindowText(TxOut, "����ʧ��");
						}
						DeleteService(hFilt);
						CloseServiceHandle(sc);
						CloseServiceHandle(hFilt);
					}
					break;
				}
				case 1010: {
					HWND hwnd = FindWindow("Shell_TrayWnd", NULL);//����������Ĵ���һ��������explorer.exe
					DWORD pid;
					GetWindowThreadProcessId(hwnd, &pid);//���������PID
					if (pid == 0 || hwnd == NULL) { //��Դ������û������
						WinExec("explorer.exe", SW_SHOW);//��ֱ�����У�ϵͳ��⵽explorer.exe��ϵͳȨ�޻��Զ��������Խ�Ȩ������Ȩ�ޱ��̳У������������⣩
						break;
						//pid = GetProcessIDFromName("explorer.exe");
					}
					HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
					if (TerminateProcess(handle, 2))//�˳���Ϊ2
						SetWindowText(TxOut, "ִ�гɹ�");
					else {
						ge;
						SetWindowText(TxOut, "ִ��ʧ��");
					}
					CloseHandle(handle);
					break;
				}
				case 1013: {
					char version[6] = {};//���Ǽ���ֵ��6.9.5
					HKEY retKey;
					LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\ZM����������\\ѧ��������������", 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &retKey);
					DWORD size = sizeof(version);
					RegQueryValueEx(retKey, "Version", NULL, NULL, (LPBYTE)&version, &size);
					RegCloseKey(retKey);
					if (ret != ERROR_SUCCESS) {
						ge;
						SetWindowText(TxOut, "ִ��ʧ�ܣ�����δ��װѧ��������������");
						break;
					}
					std::string sLog = "�������ְ汾��";
					sLog += version;
					sLog += "\nprozs.exe��������";
					//ȡʱ�����ڼ���prozs.exe�����������
					SYSTEMTIME time;
					GetLocalTime(&time);
					int n3 = time.wMonth + time.wDay;
					int n4, n5, n6;
					DWORD prozsPid;
					if (version[0] == '9' && version[2] >= '0' || version[0] == '1' && version[1] >= '0'){
						//����Ϊ9.x��10.x��11.x�汾�߼���Ŀǰ����֤�汾��11.06��
						//�°�ʹ�ù̶��㷨��������Ȼ����ȷ����[107, 118]��Χ��
						//ĳ�濪ʼ���·���107��Ϊ105�����ǿɱ�ģ��ƥ����⵽
						char name[10] = {};
						VBMath.m_rndSeed = 327680;
						VBMath.Randomize(double(time.wMonth * time.wDay));
						long long n = round(double(VBMath.Rnd()) * 300000.f + 1.f);
						for(int i = 4; i >= 0; i--){
							name[i] = char(n % 10L + 107L);
							n /= 10L;
						}
						prozsPid = GetProcessIDFromName(strcat(name, ".exe"));
						if (!prozsPid){
							PROCESSENTRY32 pe;
							pe.dwSize = sizeof(PROCESSENTRY32);
							HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
							if (Process32First(hSnapshot, &pe)) {
								do {
									//ɸѡ����Ϊ���ڵ���4��9.x���Ľ�������������ĩβ��.exe����
									size_t uImageLength = strlen(pe.szExeFile);
									if (uImageLength >= 8) {
										for (char* n7 = pe.szExeFile; *n7 != '.'; n7++) {
											//f-v֮��
											if (!(*n7 >= 102 && *n7 <= 118))goto IL_13A;
										}
										if(!_stricmp(pe.szExeFile, "smss.exe"))goto IL_13A;//���У����ǡ�Windows �Ự��������
										if(!_stricmp(pe.szExeFile, "sihost.exe"))goto IL_13A;//��Shell Infrastructure Host��
										if(!_stricmp(pe.szExeFile, "spoolsv.exe"))goto IL_13A;//����̨����������ϵͳӦ�á�
										//�ж��Ƿ��ڻ����������Ҹ���·����
										HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
										char path[MAX_PATH] = {}; DWORD size;
										bool bSuccess = QueryFullProcessImageName(hProcess, 0, path, &size);
										CloseHandle(hProcess);
										if (bSuccess && _strnicmp(path, "C:\\Program Files", 16))goto IL_13A;
										sLog += pe.szExeFile;
										prozsPid = pe.th32ProcessID;
										break;
									}
									IL_13A:;
								} while (Process32Next(hSnapshot, &pe));
							}
							CloseHandle(hSnapshot);
						} else sLog += name;
					} else if (version[0] == '7' &&version[2] >= '5') {
						//����Ϊ7.5��7.8�汾�߼�
						PROCESSENTRY32 pe;
						pe.dwSize = sizeof(PROCESSENTRY32);
						HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
						if (Process32First(hSnapshot, &pe)) {
							do {
								//ɸѡ����Ϊ10��7.5������ڵ���4��7.8���Ľ�������������ĩβ��.exe����
								size_t uImageLength = strlen(pe.szExeFile);
								if ((version[2] == '5')?(uImageLength == 14):(uImageLength >= 8)) {
									//�����ַ�
									for (char* n7 = pe.szExeFile; *n7 != '.'; n7++) {
										//��������d-m֮��
										if (!(*n7 >= 100 && *n7 <= 109))goto IL_226;
									}
									//�����㣡
									sLog += pe.szExeFile;
									prozsPid = pe.th32ProcessID;
									break;
								}
								IL_226:;
							} while (Process32Next(hSnapshot, &pe));
						}
						CloseHandle(hSnapshot);
					} else if (version[0] == '7' && version[2] == '4') {
						//����Ϊ7.4�汾�߼�
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
						//����Ϊ7.2�汾�߼�
						n4 = n3 % 7, n5 = n3 % 9, n6 = n3 % 5;
						if (n3 % 2 != 0)
							c1 = 103 + n5,  c2 = 111 + n4,  c3 = 107 + n6,  c4 = 48 + n4;
						else 
							c1 = 97 + n4,   c2 = 109 + n5,  c3 = 101 + n6,  c4 = 48 + n5;
						char c[5] = {c1, c2, c3, c4, '\0'};
						sLog += c;
						prozsPid = GetProcessIDFromName(strcat(c, ".exe"));
					} else {
						//����Ϊ7.2�汾֮ǰ���߼�
						n4 = n3 % 3 + 3, n5 = n3 % 4 + 4;
						char c[10] = {'p'};
						if (n3 % 2 != 0)
							c[1] = n5 + 102, c[2] = n4 + 98;
						else
							c[1] = n4 + 99,  c[2] = n5 + 106;
						sLog += c;
						sLog += "��ʹ��7.2ǰ���߼���";
						prozsPid = GetProcessIDFromName(strcat(c, ".exe"));
					}
					Println(sLog);
					KillProcess(prozsPid, KILL_DEFAULT);
					//ע�⣺v11��ʼ�������������ְ�װ�ļ����е���Ҫ�ļ���ȫ����FILE_ATTRIBUTE_SYSTEM��FILE_ATTRIBUTE_HIDDEN���ԣ������ļ����ڻ�����
					KillAllProcessWithName("prozs.exe", KILL_DEFAULT);
					KillAllProcessWithName("przs.exe", KILL_DEFAULT); //�°�prozs������
					KillAllProcessWithName("jfglzs.exe", KILL_DEFAULT);
					KillAllProcessWithName("jfglzsp.exe", KILL_DEFAULT);//�°�jfglzs������
					//ֹͣzmserv�����ֹ�ػ�
					SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
					SC_HANDLE zm = OpenService(sc, "zmserv", SERVICE_STOP);
					SERVICE_STATUS ss = {};
					ControlService(zm, SERVICE_CONTROL_STOP, &ss);
					CloseServiceHandle(sc);
					CloseServiceHandle(zm);
					KillAllProcessWithName("zmserv.exe", KILL_DEFAULT);
					SetWindowText(TxOut, "ִ�гɹ�");
					break;
				}
				case 1011: {
					LRESULT check = SendMessage(BtSnp, BM_GETCHECK, 0, 0);
					if (check == BST_CHECKED)
						SetWindowDisplayAffinity(hwnd, WDA_MONITOR);
					else
						SetWindowDisplayAffinity(hwnd, WDA_NONE);
					break;
				}
				case 1012: {
					LRESULT check = SendMessage(BtWnd, BM_GETCHECK, 0, 0);
					ask = check == BST_CHECKED;
					break;
				}
				case 1014: {
					//�ҵ�������
					HWND menuBar = FindWindowEx(hBdCst, NULL, "AfxWnd80u", NULL);
					/*//��ʾ������
					  ShowWindow(menuBar, SW_SHOWDEFAULT);
					  SetWindowPos(menuBar, HWND_TOP, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
					  //���ع�����
					  ShowWindow(menuBar, SW_NORMAL);
					  SetWindowPos(menuBar, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);*/
					//���ȫ����ť
					//EnableWindow(GetDlgItem(menuBar, 1004),FALSE);
					//ģ����
					LONG lStyle = GetWindowLong(hBdCst, GWL_STYLE);
					BOOL bWindowing = lStyle & (WS_CAPTION | WS_SIZEBOX);
					PostMessage(hBdCst, WM_COMMAND, MAKEWPARAM(1004, BM_CLICK), 0);
					SetWindowText(TxOut, bWindowing ? "ȫ�������" : "���ڻ����");
					SendMessage(hwnd, WM_TIMER, WPARAM(2), 0);
					break;
				}
				case 1015: {//TODO: ���Ϊ�´��ڣ���Ϊ������ʱ����
					if (MessageBox(hwnd, "���Ƿ�Ҫ��ѧ�������������ֵ��������12345678����7.1-9.98�汾��Ч���ò��������棡��(�߰汾�Ļ������ֿ��ܻ����������أ�", "����", MB_YESNO | MB_ICONWARNING) == IDYES) {
						std::string c = "8a29cc29f5951530ac69f4";//ò��9.9x֮���°���8a29cc29f5951530ac69
						HKEY retKey;
						LONG ret = RegOpenKeyEx(HKEY_CURRENT_USER, "Software", 0, KEY_SET_VALUE, &retKey);
						if (ret != ERROR_SUCCESS) {
							ge;
							SetWindowText(TxOut, "����ʧ��");
							RegCloseKey(retKey);
							break;
						}
						ret = RegSetValueEx(retKey, "n", 0, REG_SZ, (CONST BYTE*)c.c_str(), c.size() + 1);
						SetWindowText(TxOut, "���óɹ�");
						RegCloseKey(retKey);
					}
					break;
				}
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
				case 1017: {
					LRESULT check = SendMessage(BtCur, BM_GETCHECK, 0, 0);
					if (check == BST_CHECKED) {
						ResumeThread(mouHook);
					} else {
						SuspendThread(mouHook);
						UnhookWindowsHookEx(mseHook);
					}
					break;
				}
				case 1018: {
					LRESULT check = SendMessage(BtKbh, BM_GETCHECK, 0, 0);
					if (check == BST_CHECKED) {
						ResumeThread(keyHook);
						//�򿪷�������
						HANDLE hDevice = CreateFile("\\\\.\\TDKeybd", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
						if (GetLastError()) {
							PrtError(GetLastError() == ERROR_FILE_NOT_FOUND ? "������������������δ��װ" : "������������������ʧ��", GetLastError());
							break;
						}
						BOOL bEnable = TRUE;
						//���Ϳ��ƴ���
						if (DeviceIoControl(hDevice, 0x220000, &bEnable, 4, NULL, 0, NULL, NULL))
							Print("�����������������óɹ�");
						else
							PrtError("������������������ʧ��",GetLastError());
						CloseHandle(hDevice);
					} else {
						SuspendThread(keyHook);
						UnhookWindowsHookEx(kbdHook);
					}
					break;
				}
				case 1019: {
					//�ж��Ƿ���������
					DWORD dwPID = GetProcessIDFromName("MeltdownDFC.exe");
					if(dwPID) break;
					//ȡ����·���������ļ�
					char szTempPath[MAX_PATH];
					GetTempPath(MAX_PATH, szTempPath);
					HANDLE hFile = CreateFile(strcat(szTempPath, "\\MeltdownDFC.exe"), GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
					if(hFile != INVALID_HANDLE_VALUE){
						//��ȡ��Դ��Ϣ
						HRSRC hResInfo = FindResource(NULL, MAKEINTRESOURCE(2), RT_RCDATA);
						HGLOBAL hResData = LoadResource(NULL, hResInfo);
						DWORD dwSize = SizeofResource(NULL, hResInfo);
						LPVOID pData = LockResource(hResData);
						if(pData){
							//д���ļ�
							if(!WriteFile(hFile, pData, dwSize + 1, NULL, NULL)){
								SetWindowText(TxOut, "д��ʧ��");
								CloseHandle(hFile);
								break;
							}
							FlushFileBuffers(hFile);
							CloseHandle(hFile);
							//ִ�г���
							if(WinExec(szTempPath, SW_SHOW) < 32)
								SetWindowText(TxOut, "����ʧ��");
							else SetWindowText(TxOut, "�������");
						} else SetWindowText(TxOut, "д��ʧ��");
					} else SetWindowText(TxOut, "����ʧ��");
					break;
				}
				case 1020: {
					//ͬ��
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
								SetWindowText(TxOut, "д��ʧ��");
								CloseHandle(hFile);
								break;
							}
							FlushFileBuffers(hFile);
							CloseHandle(hFile);
							if(WinExec(szTempPath, SW_SHOW) < 32)
								SetWindowText(TxOut, "����ʧ��");
							else SetWindowText(TxOut, "�������");
						} else SetWindowText(TxOut, "д��ʧ��");
					} else SetWindowText(TxOut, "����ʧ��");
					break;
				}
			}
			return 0;
		}
		case WM_HOTKEY:
			switch (wParam) {
				case 0://Alt+C
					if (closingProcess) { //�ڶ���
						closingProcess = false;
						KillTimer(hwnd, 3);
						HWND topHwnd = GetForegroundWindow();
						DWORD pid;
						GetWindowThreadProcessId(topHwnd, &pid);
						if(pid != GetCurrentProcessId())//���⽹���ڵ�ǰ����ʱ���ر��Լ�
							KillProcess(pid, KILL_FORCE);
					} else { //��һ��
						closingProcess = true;
						SetTimer(hwnd, 3, GetDoubleClickTime(), NULL); //Ĭ��Ӧ����500ms
					}
					break;
				case 1: { //Alt+W
					HWND topHwnd = GetForegroundWindow();
					if(!IsHungAppWindow(topHwnd))//Ӧ�ó�������Ӧʱ������������ֹʹ�Լ���������������Ӧ��
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
						//���������Ͻ��¼�
						GetCursorPos(&p);
						if (p.x == 0 && p.y == 0) {
							asking = true;
							HWND topHwnd = GetForegroundWindow();
							if (MessageBox(hwnd, "��⵽�����λ�ñ仯���Ƿ���С�����㴰�ڣ�", "ʵʱ���", MB_YESNO | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST) == IDYES) {
								if(!IsHungAppWindow(topHwnd))//ͬ��
									ShowWindow(topHwnd, SW_MINIMIZE);
							}
							asking = false;
						} else if (p.x == w && p.y == 0) {
							asking = true;
							HWND topHwnd = GetForegroundWindow();
							HHOOK hCBTHook = SetWindowsHookEx(WH_CBT, CBTProc, NULL, GetCurrentThreadId());
							int id = MessageBox(hwnd, "��⵽�����λ�ñ仯���Ƿ�رս��㴰�ڣ�", "ʵʱ���", MB_YESNOCANCEL | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST);
							UnhookWindowsHookEx(hCBTHook);
							if (id == IDYES) {
								PostMessage(topHwnd, WM_CLOSE, 0, 0); //�첽
							} else if (id == IDNO) {
								//����һ��͸�����С�ĸ�����
								HWND hParent = CreateWindowEx(0, WC_STATIC, "", 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
								//��Ŀ�괰����Ϊ�Ӵ���
								SetParent(topHwnd, hParent);
								ge;
								//�رո����ڣ��Ӵ���Ҳ��һ������
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
						SendMessage(TxOut, SB_SETTEXT, 1, LPARAM("����δ����"));
						mwSts = 2;
						SetWindowText(BtKmw, "��������");
					} else {
						//�жϹ㲥״̬��˳���жϼ����Ƿ�����Ӧ
						MW_INFO info = {}; info.pid = id;
						BOOL bWindowing = FALSE;
						EnumWindows(EnumWindowsProc, LPARAM(&info));
						hBdCst = info.hwndOfBoardcast;
						if (hBdCst) {
							LONG lStyle = GetWindowLong(hBdCst, GWL_STYLE);
							if (lStyle & WS_SYSMENU)bWindowing = TRUE;
						}
						EnableWindow(GetDlgItem(hwnd, 1014), hBdCst ? TRUE : FALSE);
						SetDlgItemText(hwnd, 1014, bWindowing ? "�㲥ȫ����" : "�㲥���ڻ�");
						//����״̬
						mwSts = GetProcessState(id);
						std::string show;
						if (mwSts == -1)show = "����״̬δ֪";
						else if (mwSts == 0 && !info.bNotResponding)show = "����������";
						else if (mwSts == 0 && info.bNotResponding)show = "��������Ӧ";
						else if (mwSts == 1)show = "�����ѹ���";
						sprintf(show.data(), "%s[PID:%d]", show.c_str(), int(id));
						SendMessage(TxOut, SB_SETTEXT, 1, LPARAM(show.c_str()));
						SetWindowText(BtKmw, "ɱ������");
					}
					break;
				}
				case 3: {
					closingProcess = false;
					KillTimer(hwnd, 3);//���̽��
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
			Shell_NotifyIcon(NIM_DELETE, &icon); //ɾ������ͼ�꣬����ֻ����껮��ͼ�����ʧ
			UnhookWindowsHookEx(mseHook);
			UnhookWindowsHookEx(kbdHook);
			PostQuitMessage(0);
			break;
		case WM_ACTIVATE: { // TODO: Ŀǰ�ɹ۲⵽�ı����������Դ˴������ܴ����ڴ������������Ҫ�Ų�
			if (LOWORD(wParam) == WA_INACTIVE) {
				if (GetWindowLong(hwnd, GWL_STYLE) & WS_VISIBLE) {
					focus = GetFocus();
					char c[10] = {};
					if (GetClassName(focus, c, 7) && _stricmp(c, "Button") == 0) {
						LONG style = GetWindowLong(focus, GWL_STYLE);
						if ((style & BS_AUTOCHECKBOX) != BS_AUTOCHECKBOX)
							SendMessage(focus, BM_SETSTYLE, 0, TRUE);
					}
				}
			} else {
				SetFocus(focus);
				char c[10] = {};
				if (GetClassName(focus, c, 7) && _stricmp(c, "Button") == 0) {
					LONG style = GetWindowLong(focus, GWL_STYLE);
					if ((style & BS_AUTOCHECKBOX) != BS_AUTOCHECKBOX)
						SendMessage(focus, BM_SETSTYLE, BS_DEFPUSHBUTTON, TRUE);
				}
			}
			return FALSE;
		}
		case WM_USER + 3:
			if (lParam == WM_LBUTTONDBLCLK) { //���˫��
				ShowWindow(hwnd, SW_SHOWNORMAL);
				SetForegroundWindow(hwnd);
			} else if (lParam == WM_RBUTTONUP) { //�Ҽ�����
				GetCursorPos(&pt);
				SetForegroundWindow(hwnd);
				HMENU hMenu = CreatePopupMenu();//���̲˵�
				AppendMenu(hMenu, MF_STRING, 1, "�رճ���");
				AppendMenu(hMenu, MF_STRING, 2, "�򿪽���");
				int i = TrackPopupMenu(hMenu, TPM_RETURNCMD, pt.x, pt.y, 0, hwnd, NULL);
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
						if (mwSts != 1)show = "������";
						else if (mwSts == 1)show = "�ָ�����";
						AppendMenu(hSplitMenu, MF_BYPOSITION, 1, show);
						EnableMenuItem(hSplitMenu, 1, mwSts != 2 ? MF_ENABLED : MF_GRAYED);
						// Display the menu.
						SuspendThread(thread);
						int i = TrackPopupMenu(hSplitMenu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD, pt.x, pt.y, 0, hwnd, NULL);
						ResumeThread(thread);
						switch (i) {
							case 1: {
								BOOL sts = SuspendProcess(GetProcessIDFromName(MythwareFilename), !mwSts);
								if (sts)SetWindowText(TxOut, "����/�ָ��ɹ�");
								else SetWindowText(TxOut, "����/�ָ�ʧ��");
								SendMessage(hwnd, WM_TIMER, WPARAM(2), 0);
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
						break;//����������������쳣
					}
				case NM_RETURN: {
					PNMLINK pNMLink = (PNMLINK)lParam;
					LITEM   item    = pNMLink->item;
					if ((((LPNMHDR)lParam)->hwndFrom == TxLnk) && (item.iLink == 0))
						ShellExecuteW(NULL, L"open", item.szUrl, NULL, NULL, SW_SHOW);
					break;
				}
			}
			break;
		case WM_LBUTTONDOWN:
			//ʵ�ֿհ״������϶�
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
					sprintf(s, "GetLastError��һ������\n%u��%s", error, szError);
					LocalFree(HLOCAL(szError));
					MessageBox(hwnd, s, "��һ������", MB_OK | MB_ICONINFORMATION);
					error = -1;
					break;
				}
				case 3: {//���������������win10�汾�����ö�
					//�ж���û������
					HWND h = FindWindow("TaskManagerWindow", NULL);
					BYTE nCount = 0;
					if (!h) {
						//�����û�о�������
						DWORD value = 0; HKEY retKey;
						RegOpenKeyEx(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
						RegSetValueEx(retKey, "DisableTaskMgr", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
						RegFlushKey(retKey);
						RegCloseKey(retKey);
						WinExec("taskmgr", SW_SHOW);
						ge;
						do {
							//���ȴ�3�룬����ֹͣ��Ѱ����ֹ����Ӧ��5�룩
							if (++nCount == 60) {
								SetWindowText(TxOut, "����ʧ��");
								return FALSE;
							}
							//�ȴ����ڴ������
							Sleep(50);
							h = FindWindow("TaskManagerWindow", NULL);
						} while (!h);
					}
					//��ȡ�˵���ȡ�ù�ѡ״̬
					HMENU hm = GetMenu(h);
					MENUITEMINFO mii = {sizeof(MENUITEMINFO), MIIM_STATE};
					GetMenuItemInfo(hm, 0x7704, FALSE, &mii);
					//���δ��ѡ��ģ�⹴ѡ
					if (!(mii.fState & MFS_CHECKED))
						PostMessage(h, WM_COMMAND, 0x7704, 0);
					SetWindowText(TxOut, "�������");
					break;
				}
				case 4: {
					//��ȡ����Ŀ¼��������־
					char szTempPath[MAX_PATH];
					GetTempPath(MAX_PATH, szTempPath);
					HANDLE hFile = CreateFile(strcat(szTempPath, "\\ToolkitLog.txt"), GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
					WriteFile(hFile, sOutPut.c_str(), sOutPut.size() + 1, NULL, NULL);
					FlushFileBuffers(hFile);
					//���ļ����
					ShellExecute(hwnd, "open", szTempPath, NULL, NULL, SW_SHOW);
					CloseHandle(hFile);
					break;
				}
				/*case SC_CLOSE:
					if((GetAsyncKeyState(VK_MENU) & 1)/* && (GetAsyncKeyState(VK_F4) & 1)*)break;//Alt+F4����С����ֱ�ӹر�
					PostMessage(hwnd, WM_SYSCOMMAND, SC_MINIMIZE, lParam);//��Ϊ��С��
					return TRUE;*/
				case SC_MINIMIZE:
					SetActiveWindow(hwnd);//TODO: ����������
					focus = GetFocus();//��ֹ��С���󽹵�ʧЧ
			}
			return DefWindowProc(hwnd, Message, wParam, lParam);
		case WM_SIZE:
			if (wParam == SIZE_MINIMIZED) {
				ShowWindow(hwnd, SW_HIDE); //����
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
	//����δ����API
	InitNTAPI();
	//�жϵ�ǰ����Ȩ��
	HANDLE hToken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	DWORD dwLength = 0;
	GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength);
	PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLength);
	if(GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLength, &dwLength)){
		DWORD dwLevel = *GetSidSubAuthority(pTIL->Label.Sid, *GetSidSubAuthorityCount(pTIL->Label.Sid) - 1);
		if (dwLevel >= SECURITY_MANDATORY_SYSTEM_RID)
			eLevel = RL_SYSTEM;
		else if (dwLevel >= SECURITY_MANDATORY_HIGH_RID)
			eLevel = RL_ADMIN;
		else
			eLevel = RL_USER;
	} else eLevel = RL_UNKNOWN;
	//��SystemȨ��������������ȫģʽ��UserȨ�޲���
	//���https://blog.csdn.net/weixin_42112038/article/details/126308315
	int argc; bool bStartAsSystem = false;
	LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argv){
		bStartAsSystem = (!_wcsicmp(argv[1], L"-s") || !_wcsicmp(argv[1], L"/s"));
		LocalFree(argv);
	}
	if (eLevel != RL_SYSTEM && bStartAsSystem) {
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
		else MessageBox(NULL, "�޷���ϵͳȨ�����б�����������ͨ��ʽ���С����˽������Ϣ����鿴��һ������", "���򹤾߰�", MB_ICONERROR | MB_OK);
	}
	//������ʼ
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
	wc.hIcon		 = LoadIcon(hInstance, "MAINICON"); /* Load a standard icon */
	wc.hIconSm		 = LoadIcon(hInstance, "MAINICON"); /* use the name "A" to use the project icon */

	if (!RegisterClassEx(&wc)) {
		MessageBox(NULL, "������ע��ʧ�ܣ�����������", "�� �� �� �� ��", MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	//���������
	hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, "WindowClass", RandomWindowTitle(), (WS_OVERLAPPEDWINDOW | WS_VISIBLE)^WS_MAXIMIZEBOX ^ WS_SIZEBOX, 0, 0, width, height, NULL, NULL, hInstance, NULL);

	if (hwnd == NULL) {
		MessageBox(NULL, "���ڴ���ʧ�ܣ�����������", "�� �� �� �� ��", MB_ICONEXCLAMATION | MB_OK);
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

//----------����----------

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

//��Ļ�㲥����
constexpr LPCSTR sBdCst[2] = {"��Ļ�㲥", " ���ڹ�����Ļ"};
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
	MW_INFO* info = (MW_INFO*)lParam; DWORD pid;
	//���˷Ǽ��򴰿ڡ���Ȼ����������򣩵���������޷��������ͬ�����̵����
	GetWindowThreadProcessId(hwnd, &pid);
	if(pid != info->pid)return TRUE;
	//�ж��Ƿ�����Ӧ�����������ò��Ҳ����ô�жϵģ�
	HWND hOwner = GetWindow(hwnd, GW_OWNER);
	LONG l = GetWindowLong(hwnd, GWL_EXSTYLE);
	if((!hOwner || !IsWindowVisible(hOwner) || (l & WS_EX_APPWINDOW))
	   /*&& IsWindowVisible(hwnd)*/ && (l & WS_EX_TOOLWINDOW) == 0 && IsHungAppWindow(hwnd))
		info->bNotResponding = true;
	//�Ƿ���afx����������ʹ����MFC��ܣ����������ٺܶ�Ƚϣ����Ч�ʵ�ͬʱ���ܼ�����ɱ
	char szClass[5];
	if (GetClassName(hwnd, szClass, 5) && _stricmp(szClass, "Afx:") == 0) {
		//��ȡ���ڱ���
		int nLength = GetWindowTextLength(hwnd);
		char szName[nLength + 2];
		GetWindowText(hwnd, szName, nLength + 1);
		//�Ƚϱ��⣬�ֱ���ȫ�ıȽϺͱȽ�ĩβ
		if (_stricmp(szName, sBdCst[0]) == 0 ||
			_stricmp(szName + nLength - strlen(sBdCst[1]), sBdCst[1]) == 0) {
			//��Ŀ�괰�ھ��ͨ��lParam���ص��ô�
			info->hwndOfBoardcast = hwnd;
			return FALSE;
		}
	}
	return TRUE;
}
/* ����������жϴ����Ƿ�����Ӧʱ������������δ����������Ӧ�ò�Ӱ�������жϣ�������ã���¼�ڴˣ�
	User32.dll
	HWND WINAPI GhostWindowFromHungWindow(HWND hwndHung);
	HWND WINAPI HungWindowFromGhostWindow(HWND hwndGhost);
*/

//һ�д��ȫ���ײ�hook
LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {
	return FALSE;
}

//----------����----------

//https://www.52pojie.cn/thread-542884-1-1.html ��ɾ�� TODO: ����FreeModule(libTDMaster.dll)
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
		SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
		Sleep(40);//��������ö�����������ر��CPU
	}
	return 0L;
}

LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HCBT_ACTIVATE) {
		HWND msgHwnd = HWND(wParam);
		char szClass[7];
		GetClassName(msgHwnd, szClass, 7);
		if (_stricmp("#32770", szClass) == 0) { //�жϴ��봰���Ƿ���MessageBox�Ĵ���
			//��ȡ���ڱ���
			int nLength = GetWindowTextLength(msgHwnd);
			char szName[nLength + 2];
			GetWindowText(msgHwnd, szName, nLength + 1);
			if (_stricmp(szName, "ʵʱ���") == 0) {
				SetDlgItemText(msgHwnd, IDYES, "�ر�");
				SetDlgItemText(msgHwnd, IDNO, "ǿ�ƹر�");
				SetDlgItemText(msgHwnd, IDCANCEL, "ȡ��");
				HMENU msgMenu = GetSystemMenu(msgHwnd, FALSE);
				EnableMenuItem(msgMenu, SC_CLOSE, MF_GRAYED);
			} else if (_stricmp(szName, "USB Setting") == 0) {
				SetDlgItemText(msgHwnd, IDYES, "�����");
				SetDlgItemText(msgHwnd, IDNO, "Ӳ���");
			} else if (_stricmp(szName, "��������쳣") == 0) {
				SetDlgItemText(msgHwnd, IDYES, "��ֹ����");
				SetDlgItemText(msgHwnd, IDNO, "����");
			}
			
		}
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

BOOL CALLBACK SetWindowFont(HWND hwndChild, LPARAM lParam) {
	SendMessage(hwndChild, WM_SETFONT, WPARAM(lParam), 0);
	return TRUE;
}

inline LPCSTR RandomWindowTitle() {
	//���������
	std::srand((unsigned) time(NULL));
	LPSTR title = new char[11];
	memset(title, 0, 11);
	for (int i = 0; i < 10; i++) {
		int u = std::rand(), c = u % 31;//����31��Ϊ�˼������ֳ��ָ���
		if (c < 5)title[i] = u % 10 + '0';
		else if (c < 18)title[i] = u % 26 + 'a';
		else title[i] = u % 26 + 'A';
	}
	return title;
}

bool SetupTrayIcon(HWND m_hWnd, HINSTANCE hInstance) {
	icon.cbSize = sizeof(NOTIFYICONDATA); // �ṹ��С
	icon.hWnd = m_hWnd; // ���� ����֪ͨ��Ϣ �Ĵ��ھ��
	icon.uID = 0;
	icon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; //��ʾuCallbackMessage ��Ч
	icon.uCallbackMessage = WM_USER + 3; // ��Ϣ�����͵��˴��ڹ���
	icon.hIcon = LoadIcon(hInstance, "MAINICON");
	strcpy(icon.szTip, "���򹤾߰�");             // ��ʾ�ı�
	return 0 != Shell_NotifyIcon(NIM_ADD, &icon);
}

//----------����----------

//https://blog.csdn.net/yanglx2022/article/details/46582629
DWORD GetProcessIDFromName(LPCSTR szName) {
	DWORD id = 0;       // ����ID
	PROCESSENTRY32 pe;  // ������Ϣ
	pe.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // ��ȡϵͳ�����б�
	if (Process32First(hSnapshot, &pe)) {   // ����ϵͳ�е�һ�����̵���Ϣ
		do {
			if (0 == _stricmp(pe.szExeFile, szName)) { // �����ִ�Сд�Ƚ�
				id = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe));     // ��һ������
	}
	CloseHandle(hSnapshot);     // ɾ������
	return id;
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

//��ɱ��ÿ���̵߳ķ������ĳЩ����hookס��TerminateProcess()������
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
		//Ĭ�Ϸ������ȶ���ȫ
		HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessID);
		WINBOOL sta = TerminateProcess(handle, 0);
		CloseHandle(handle);
		return sta;
	}
	return false;
}

bool KillAllProcessWithName(LPCSTR name, int way) {
	PROCESSENTRY32 pe; bool s = false;
	pe.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(hSnapshot, &pe)) {
		do {
			if(!_stricmp(pe.szExeFile, name))
				s = KillProcess(pe.th32ProcessID, way);
		} while (Process32Next(hSnapshot, &pe));
	}
	CloseHandle(hSnapshot);
	return s;
}

//������̣�����δ��������NtSuspendProcess��suspend������������/�ָ�
NTSTATUS (NTAPI *NtSuspendProcess)(IN HANDLE Process);
NTSTATUS (NTAPI *NtResumeProcess)(IN HANDLE Process);

BOOL SuspendProcess(DWORD dwProcessID, BOOL suspend) {
	HANDLE handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, dwProcessID);
	if (suspend) {
		return NtSuspendProcess(handle) == 0;
	} else {
		return NtResumeProcess(handle) == 0;
	}
}

//��ԭ�ṹ֮����ϲ�Ӱ��ṹ��С���߳����飬��������Խ������Ŀ�ṹ���ʺ�����߳̽ṹ
typedef struct _MYSYSTEM_PROCESS_INFORMATION : SYSTEM_PROCESS_INFORMATION {
	//����Ϊԭ�ṹ����
	SYSTEM_THREAD_INFORMATION Threads[0];
} MYSYSTEM_PROCESS_INFORMATION, *PMYSYSTEM_PROCESS_INFORMATION;

//����ԭ����
#define SYSTEM_PROCESS_INFORMATION MYSYSTEM_PROCESS_INFORMATION
#define PSYSTEM_PROCESS_INFORMATION PMYSYSTEM_PROCESS_INFORMATION

//���庯��ԭ��
NTSTATUS (NTAPI *MyNtQuerySystemInformation)
(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation,
 IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);
#define NtQuerySystemInformation MyNtQuerySystemInformation
DWORD (NTAPI *RtlNtStatusToDosErrorNoTeb)(NTSTATUS Status);

//��ȡ���̵�״̬
//����-1����ʾ�����쳣
//����0����ʾ����û�б�����
//����1����ʾ���̴��ڹ���״̬
int GetProcessState(DWORD dwProcessID) {
	int nStatus = -1;
	//�ȵ���һ�Σ���ȡ���軺������С
	DWORD dwSize;
	NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &dwSize);
	//���뻺����
	HGLOBAL hBuffer = GlobalAlloc(LPTR, dwSize);
	if (hBuffer == NULL)
		return nStatus;
	PSYSTEM_PROCESS_INFORMATION pInfo = PSYSTEM_PROCESS_INFORMATION(hBuffer);
	//��ѯ
	NTSTATUS lStatus = NtQuerySystemInformation(SystemProcessInformation, pInfo, dwSize, 0);
	if (!NT_SUCCESS(lStatus)) {
		GlobalFree(hBuffer);
		//NTSTATUS ת win32 error
		error = RtlNtStatusToDosErrorNoTeb(lStatus);
		return nStatus;
	}
	//��������
	while (true) {
		//�ж��Ƿ���Ŀ�����
		if (((DWORD)(ULONG_PTR) pInfo->UniqueProcessId) == dwProcessID) {
			nStatus = 1;
			//�����߳�
			for (ULONG i = 0; i < pInfo->NumberOfThreads; i++) {
				//��������ڹ��𣬾ͱ�����������Է��أ�����������Ӧ�������
				if (pInfo->Threads[i].WaitReason != Suspended) {
					nStatus = 0;
					break;
				}
			}
			break;
		}
		//�����������
		if (pInfo->NextEntryOffset == 0)
			break;
		//�ƶ�����һ��������Ϣ�ṹ�ĵ�ַ
		pInfo = PSYSTEM_PROCESS_INFORMATION(PBYTE(pInfo) + pInfo->NextEntryOffset);
	}
	//�ͷŻ�����
	GlobalFree(hBuffer);
	return nStatus;
}

//ȡ������ַ
void InitNTAPI(){
	HMODULE ntdll = GetModuleHandle("ntdll.dll");
	Set(NtSuspendProcess, GetProcAddress(ntdll, "NtSuspendProcess"));
	Set(NtResumeProcess, GetProcAddress(ntdll, "NtResumeProcess"));
	Set(NtQuerySystemInformation, GetProcAddress(ntdll, "NtQuerySystemInformation"));
	Set(RtlNtStatusToDosErrorNoTeb, GetProcAddress(ntdll, "RtlNtStatusToDosErrorNoTeb"));
}

//----------����----------

// ����ȫ���쳣��������
LONG WINAPI GlobalExceptionHandler(EXCEPTION_POINTERS* exceptionInfo)
{
	// �����Ի�����ʾ�쳣����
	char message[BUFSIZ * 2] = {};
	sprintf(message, "�쳣���룺0x%08X��λ���ڴ��ַ��0x%X\n����%s������������ɴ��ڣ�����ϵ������", exceptionInfo->ExceptionRecord->ExceptionCode, 
		exceptionInfo->ExceptionRecord->ExceptionAddress,
		((exceptionInfo -> ExceptionRecord -> ExceptionFlags) & EXCEPTION_NONCONTINUABLE) ? "�˳�" : "���Լ���ִ��");
	HHOOK hCBTHook = SetWindowsHookEx(WH_CBT, CBTProc, NULL, GetCurrentThreadId());
	int id = MessageBox(NULL, message, "��������쳣", MB_ICONERROR | MB_YESNO | MB_DEFBUTTON2);
	UnhookWindowsHookEx(hCBTHook);
	if(id == IDYES){
		//LPSTR szCmd = GetCommandLine();
		//WinExec(szCmd, SW_SHOW);
		//return EXCEPTION_EXECUTE_HANDLER;
		return EXCEPTION_CONTINUE_SEARCH;
	} else if(id == IDNO){
		// ���ش������������ִ�г�����˳�
		return ((exceptionInfo -> ExceptionRecord -> ExceptionFlags) & EXCEPTION_NONCONTINUABLE)?
		EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_EXECUTE_HANDLER;
}

inline void PrtError(LPCSTR szDes, LRESULT lResult) {
	DWORD dwError = lResult == 0 ? GetLastError() : lResult & 0xFFFF;
	LPSTR szError = NULL;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
	              NULL, dwError, 0, (PTSTR)&szError, 0, NULL);
	char s[BUFSIZ] = {};
	sprintf(s, "%s��%u-%s", szDes, dwError, szError);
	LocalFree(HLOCAL(szError));
	size_t uSize = strlen(s);
	//����ĩβ���з�
	if(*(s+uSize-1) == '\n')*(WORD*)(s+uSize-2) = 0;
	Println(s);
}

inline LPSTR FormatLogTime(){
	//�����ڴ棬���ʱ��
	LPVOID lpBuffer = VirtualAlloc(NULL, 64, MEM_COMMIT, PAGE_READWRITE);
	SYSTEMTIME time;
	GetLocalTime(&time);
	LPSTR szBuffer = LPSTR(lpBuffer);
	//��ʽ��
	sprintf(szBuffer, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] ", 
		time.wYear, time.wMonth, time.wDay,
		time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
	return szBuffer;
}
