#pragma GCC optimize(2) //�Ż�
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <userenv.h>
#include <commctrl.h>
#include <string>
#include <cstdlib>
BOOL GetMythwarePasswordFromRegedit(char *str);
DWORD GetProcessIDFromName(LPCSTR szName);
bool KillProcess(DWORD dwProcessID, int way);
DWORD WINAPI ThreadProc(LPVOID lpParameter);
BOOL CALLBACK SetWindowFont(HWND hwndChild, LPARAM lParam);
bool SetupTrayIcon(HWND m_hWnd, HINSTANCE hInstance);
BOOL EnableDebugPrivilege();
DWORD WINAPI KeyHookThreadProc(LPVOID lpParameter);
DWORD WINAPI MouseHookThreadProc(LPVOID lpParameter);
BOOL SuspendProcess(DWORD dwProcessID, BOOL suspend);
int GetProcessState(DWORD dwProcessID);
LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam);
std::string RandomWindowTitle();

#define KILL_FORCE 1
#define KILL_DEFAULT 2
HHOOK kbdHook, mseHook;
HWND hwnd, focus; /* A 'HANDLE', hence the H, or a pointer to our window */
/* This is where all the input to the window goes to */
LPCSTR MythwareFilename = "StudentMain.exe";//������ĳɱ�ı���ԡ����ݡ�������ӽ���
//LONG fullScreenStyle = WS_POPUP | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN, windowingStyle = fullScreenStyle | WS_OVERLAPPEDWINDOW ^ WS_OVERLAPPED;
HFONT hFont;
NOTIFYICONDATA icon;
HMENU hMenu;//���̲˵�
int width = 528, height = 250, w, h, mwSts;
bool asking = false, closingProcess = false;
DWORD error = -1;//���ڵ���
POINT p, pt;
HWND BtAbt, BtKmw, TxOut, TxLnk, BtTop, BtCur, BtKbh;
LPCSTR helpText = "���򹤾߰� v1.1\n\
���⹦�ܣ���ݼ�Alt+C˫��ɱ����ǰ���̣�Alt+W��С�����㴰�ڣ�Alt+B����������\n\
�����������Ļ���Ͻ�/���Ͻ�ʱ������ѡ����С��/�رս��㴰��\n\
��С��ʱ���ص����������̣����˫���������棬�Ҽ����������˵�\n\
���������ʾ����ʧ�ܣ���������Ȩ�޻�ָ��ע����ֵ�����ڣ��ڴ�����£�ͨ�������������\n\
����������ܶ�Alt+Ctrl+Delete��Ч\n\
����ʱ����-s��/s�����п���SystemȨ������";
HANDLE thread/*����ˢ���ö�����Timer����bug*/, mouHook/*�������*/, keyHook/*�������*/;
UINT WM_TASKBAR;

LRESULT CALLBACK WndProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
	switch (Message) {
		case WM_CREATE: {
			EnableDebugPrivilege();//��Ȩ
			w = GetSystemMetrics(SM_CXSCREEN) - 1;//��Ļ��ȣ�ע���ʵ�ʿ�ȶ�1��
			h = GetSystemMetrics(SM_CYSCREEN) - 1;//��Ļ�߶�
			NONCLIENTMETRICS info;
			info.cbSize = sizeof(NONCLIENTMETRICS);
			if (SystemParametersInfo (SPI_GETNONCLIENTMETRICS, 0, &info, 0)) {
				hFont = CreateFontIndirect ((LOGFONT*)&info.lfMessageFont);
			}//ȡϵͳĬ������
			WM_TASKBAR = RegisterWindowMessage(TEXT("TaskbarCreated"));//�����������¼�
			thread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);//�ö�����
			keyHook = CreateThread(NULL, 0, KeyHookThreadProc, NULL, CREATE_SUSPENDED, NULL);//������
			mouHook = CreateThread(NULL, 0, MouseHookThreadProc, NULL, CREATE_SUSPENDED, NULL);//������
			SetTimer(hwnd, 1, 1000, NULL); //���������Ͻ�
			SetTimer(hwnd, 2, 2000, NULL); //��⼫��״̬
			RegisterHotKey(hwnd, 0, MOD_ALT, 0x43); //Alt+Cǿ�ƽ�����ǰ����
			RegisterHotKey(hwnd, 1, MOD_ALT, 0x57); //Alt+W��С�����㴰��
			RegisterHotKey(hwnd, 2, MOD_ALT, 0x42); //Alt+B��ʾ�˴���
			HINSTANCE hi = ((LPCREATESTRUCT) lParam)->hInstance;
			TxLnk = CreateWindow("SysLink", TEXT("���򹤾߰� <a href=\"https://blog.csdn.net/weixin_42112038?type=blog\">����</a>"), WS_CHILD | WS_VISIBLE | WS_TABSTOP, 8, 8, 120, 20, hwnd, HMENU(1001), hi, NULL);
			BtAbt = CreateWindow(WC_BUTTON, TEXT("����/����"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 166, 3, 90, 30, hwnd, HMENU(1002), hi, NULL);
			//��ȡ����
			char str[MAX_PATH] = {};
			LPCSTR psd;
			if (GetMythwarePasswordFromRegedit(str) == FALSE) {
				psd = TEXT("��ȡ����ʧ��");
			} else {
				psd = TEXT(str);
			}
			CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, psd, WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_READONLY, 8, 36, 248, 20, hwnd, HMENU(1003), hi, NULL);
			CreateWindow(WC_BUTTON, TEXT("ɱ��ѧ��������������"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,  8, 64, 248, 50, hwnd, HMENU(1013), hi, NULL);
			BtKmw = CreateWindow(WC_BUTTON, TEXT("ɱ������"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_SPLITBUTTON, 8, 122, 248, 50, hwnd, HMENU(1004), hi, NULL);
			TxOut = CreateWindow(STATUSCLASSNAME, TEXT("�ȴ�����"), WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, HMENU(1005), hi, NULL);
			int pts[2] = {352, -1};
			SendMessage(TxOut, SB_SETPARTS, WPARAM(2), LPARAM(pts));
			CreateWindow(WC_BUTTON, TEXT("������ù���"), WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 264, 8, 248, 174, hwnd, NULL, hi, NULL);
			CreateWindow(WC_BUTTON, TEXT("���cmd����"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 272, 28, 112, 30, hwnd, HMENU(1007), hi, NULL);
			CreateWindow(WC_BUTTON, TEXT("���ע���༭��"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 392, 28, 112, 30, hwnd, HMENU(1008), hi, NULL);
			CreateWindow(WC_BUTTON, TEXT("������������"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 272, 66, 112, 30, hwnd, HMENU(1009), hi, NULL);
			CreateWindow(WC_BUTTON, TEXT("���Win+R����"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 392, 66, 112, 30, hwnd, HMENU(1010), hi, NULL);
			CreateWindow(WC_BUTTON, TEXT("���taskkill"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 272, 104, 112, 30, hwnd, HMENU(1011), hi, NULL);
			CreateWindow(WC_BUTTON, TEXT("������Դ������"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 392, 104, 112, 30, hwnd, HMENU(1012), hi, NULL);
			CreateWindow(WC_BUTTON, TEXT("�������USB����"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 272, 142, 112, 30, hwnd, HMENU(1014), hi, NULL);
			CreateWindow(WC_BUTTON, TEXT("���ע���˻�"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 392, 142, 112, 30, hwnd, HMENU(1015), hi, NULL);
			BtTop = CreateWindow(WC_BUTTON, TEXT("�ö��˴���"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 8, 176, 77, 18, hwnd, HMENU(1016), hi, NULL);
			SendMessage(BtTop, BM_SETCHECK, BST_CHECKED, NULL);
			BtCur = CreateWindow(WC_BUTTON, TEXT("����������(&M)"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 90, 176, 87, 18, hwnd, HMENU(1017), hi, NULL);
			BtKbh = CreateWindow(WC_BUTTON, TEXT("�������(&C)"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 183, 176, 65, 18, hwnd, HMENU(1018), hi, NULL);
			EnumChildWindows(hwnd, SetWindowFont, (LPARAM)0);
			hMenu = CreatePopupMenu();//���̲˵�
			AppendMenu(hMenu, MF_STRING, 1, TEXT("�رճ���"));
			AppendMenu(hMenu, MF_STRING, 2, TEXT("�򿪽���"));
			SetupTrayIcon(hwnd, hi);
			HMENU sys = GetSystemMenu(hwnd, FALSE);//ϵͳ�˵�
			AppendMenu(sys, MF_STRING, 1, TEXT("������������(&P)"));
			AppendMenu(sys, MF_STRING, 2, TEXT("��ʾ��һ������(&E)"));
			AppendMenu(sys, MF_STRING, 3, TEXT("�������������(&T)"));
			focus = GetDlgItem(hwnd, 1013);
			SetFocus(focus);
			SendMessage(hwnd, WM_TIMER, WPARAM(2), NULL);
			//ж�ؼ���64λ������ֹhook
			HMODULE hook = GetModuleHandle("LibTDProcHook64.dll");
			if (hook)FreeModule(hook);
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
							SendMessage(hwnd, WM_TIMER, WPARAM(2), NULL);
						} else {
							SetWindowText(TxOut, "ִ��ʧ��");
						}
					} else { //��Ȩ��������
						HKEY retKey;//�ȶ�ȡ����·��
						std::string data;
						LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\TopDomain\\e-Learning Class Standard\\1.00", 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &retKey);
						if (ret != ERROR_SUCCESS) {
							SetWindowText(TxOut, "��ȡ·��ʧ��");
							RegCloseKey(retKey);
							break;
						}
						if (ret != ERROR_SUCCESS) {
							SetWindowText(TxOut, "��ȡ·��ʧ��");
							RegCloseKey(retKey);
							break;
						}
						DWORD dataLong = MAX_PATH * 2, type = REG_SZ;
						ret = RegQueryValueEx(retKey, "TargetDirectory", 0, &type, LPBYTE(data.data()), &dataLong);
						RegCloseKey(retKey);

						if (ret != ERROR_SUCCESS) {
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
						STARTUPINFO si;//��Ҫ��һЩ����......
						PROCESS_INFORMATION pi;
						ZeroMemory(&si, sizeof(STARTUPINFO));
						si.cb = sizeof(STARTUPINFO);
						si.lpDesktop = TEXT("winsta0\\default");
						BOOL bResult = CreateProcessAsUser(token, strcat(data.data(), MythwareFilename), NULL, NULL, NULL,
						                                   FALSE, CREATE_NEW_PROCESS_GROUP | NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi); //��������
						if (bResult) {
							SetWindowText(TxOut, "�����ɹ�");
							CloseHandle(pi.hProcess);
							CloseHandle(pi.hThread);
						} else SetWindowText(TxOut, "����ʧ��");
						CloseHandle(handle);
						CloseHandle(token);
						SendMessage(hwnd, WM_TIMER, WPARAM(2), NULL);
					}
					break;
				}
				case 1007: {
					//HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System:DisableCMD->0
					HKEY retKey;
					DWORD value = 0;
					LONG ret = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\System", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					ret = RegSetValueEx(retKey, "DisableCMD", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					RegCloseKey(retKey);

					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						break;
					}
					SetWindowText(TxOut, "���óɹ�");

					break;
				}
				case 1008: {
					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System:DisableRegistryTools->0
					HKEY retKey;
					DWORD value = 0;
					LONG ret = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						RegCloseKey(retKey);
						break;
					}
					ret = RegSetValueEx(retKey, "DisableRegistryTools", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					RegCloseKey(retKey);

					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						break;
					}
					SetWindowText(TxOut, "���óɹ�");
					break;
				}
				case 1009: {
					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System:DisableTaskMgr->0
					HKEY retKey;
					DWORD value = 0;
					LONG ret = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						RegCloseKey(retKey);
						break;
					}
					ret = RegSetValueEx(retKey, "DisableTaskMgr", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					RegCloseKey(retKey);

					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						break;
					}
					SetWindowText(TxOut, "���óɹ�");
					break;
				}
				case 1010: {
					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoRun->0
					HKEY retKey;
					DWORD value = 0;
					LONG ret = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						RegCloseKey(retKey);
						break;
					}
					ret = RegSetValueEx(retKey, "NoRun", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					ret = RegSetValueEx(retKey, "RestrictRun", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));//Ҳ������
					RegCloseKey(retKey);

					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						break;
					}
					SetWindowText(TxOut, "���óɹ���������Դ������������Ч");
					break;
				}
				case 1011: {
					//HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskkill.exe:debugger:(
					HKEY retKey;
					LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskkill.exe", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						RegCloseKey(retKey);
						break;
					}
					RegDeleteValue(retKey, "debugger");
					RegCloseKey(retKey);
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						break;
					}
					SetWindowText(TxOut, "���óɹ�");
					break;
				}
				case 1012: {
					/*if (KillProcess(GetProcessIDFromName("explorer.exe") ) == FALSE) {
						SetWindowText(TxOut, "ִ��ʧ��");
						break;
					}
					Sleep(200);
					//����Դ������
					WinExec("start explorer.exe", SW_HIDE);*/
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
					else
						SetWindowText(TxOut, "ִ��ʧ��");
					CloseHandle(handle);
					break;
				}
				case 1013: {
					char version[6];//���Ǽ���ֵ��6.9.5
					HKEY retKey;
					LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\ZM���������\\ѧ��������������", 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &retKey);
					DWORD size = sizeof(version);
					RegQueryValueEx(retKey, "Version", NULL, NULL, (LPBYTE)&version, &size);
					RegCloseKey(retKey);
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "ִ��ʧ�ܣ�����δ��װѧ��������������");
						break;
					}
					//ȡʱ�����ڼ���prozs.exe�����������
					SYSTEMTIME time;
					GetLocalTime(&time);
					int n3 = time.wMonth + time.wDay;
					int n4, n5, n6;
					DWORD prozsPid;
					if (version[0] == '7' && version[2] == '5') {
						//����Ϊ7.5�汾�߼�
						PROCESSENTRY32 pe;
						pe.dwSize = sizeof(PROCESSENTRY32);
						HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
						if (Process32First(hSnapshot, &pe)) {
							do {
								//ɸѡ����Ϊ10�Ľ�������������ĩβ��.exe����
								if (strlen(pe.szExeFile) == 14) {
									//�����ַ�
									for (int j = 0; j < 10; j++) {
										char n7 = pe.szExeFile[j];
										//��������d-m֮��
										if (!(n7 >= 100 && n7 <= 109))goto IL_226;
									}
									//�����㣡
									prozsPid = pe.th32ProcessID;
									break;
								}
								IL_226:
								;
							} while (Process32Next(hSnapshot, &pe));
						}
						CloseHandle(hSnapshot);
					} else if (version[0] == '7' && version[2] == '4') {
						//����Ϊ7.4�汾�߼�
						char c1, c2, c3, c4;
						n3 = time.wMonth * time.wDay, n4 = n3 % 7, n5 = n3 % 5, n6 = n3 % 3;
						int n = n3 % 9;
						if (n3 % 2 == 0) {
							c1 = 108 + n4,  c2 = 75 + n,  c3 = 98 + n5,  c4 = 65 + n6;
						} else {
							c1 = 98 + n,  c2 = 65 + n4,  c3 = 108 + n5,  c4 = 75 + n6;
						}
						char c[5] = {c1, c2, c3, c4, '\0'};
						prozsPid = GetProcessIDFromName(strcat(c, ".exe"));
					} else if (version[0] == '7' && version[2] == '2') {
						char c1, c2, c3, c4;
						//����Ϊ7.2�汾�߼�
						n4 = n3 % 7, n5 = n3 % 9, n6 = n3 % 5;
						if (n3 % 2 != 0) {
							c1 = 103 + n5,  c2 = 111 + n4,  c3 = 107 + n6,  c4 = 48 + n4;
						} else {
							c1 = 97 + n4,   c2 = 109 + n5,  c3 = 101 + n6,  c4 = 48 + n5;
						}
						char c[5] = {c1, c2, c3, c4, '\0'};
						prozsPid = GetProcessIDFromName(strcat(c, ".exe"));
					} else {
						//����Ϊ7.2�汾֮ǰ���߼�
						n4 = n3 % 3 + 3, n5 = n3 % 4 + 4;
						char c[4] = {'p'};
						if (n3 % 2 != 0)
							c[1] = n4 + 102, c[2] = n5 + 98;
						else
							c[1] = n4 + 99,  c[2] = n5 + 106;
						prozsPid = GetProcessIDFromName(strcat(c, ".exe"));
					}
					KillProcess(prozsPid, KILL_DEFAULT);
					KillProcess(GetProcessIDFromName("jfglzs.exe"), KILL_DEFAULT);
					//ֹͣzmserv�����ֹ�ػ�
					SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
					SC_HANDLE zm = OpenService(sc, TEXT("zmserv"), SERVICE_STOP);
					SERVICE_STATUS ss = {};
					ControlService(zm, SERVICE_CONTROL_STOP, &ss);
					CloseServiceHandle(sc);
					CloseServiceHandle(zm);
					SetWindowText(TxOut, "ִ�гɹ�");
					break;
				}
				case 1014: {
					//HKEY_LOCAL_MACHINE\SOFTWARE\jfglzs:usb_jianche->off
					//���ע���ġ���⡱�������
					char c[4] = "off";
					HKEY retKey;
					LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\jfglzs", 0, KEY_SET_VALUE, &retKey);
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						RegCloseKey(retKey);
						break;
					}
					ret = RegSetValueEx(retKey, "usb_jianche", 0, REG_SZ, (CONST BYTE*)&c, 4);
					SetWindowText(TxOut, "���óɹ�");
					RegCloseKey(retKey);
					break;
				}
				case 1015: {
					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoLogOff->0
					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer:StartMenuLogOff->0
					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System:DisableLockWorkstation->0
					HKEY retKey;
					DWORD value = 0;
					LONG ret = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						RegCloseKey(retKey);
						break;
					}
					ret = RegSetValueEx(retKey, "NoLogOff", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					ret = RegSetValueEx(retKey, "StartMenuLogOff", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					ret = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					ret = RegSetValueEx(retKey, "DisableLockWorkstation", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					RegCloseKey(retKey);
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						break;
					}
					SetWindowText(TxOut, "���óɹ�");
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
					} else {
						SuspendThread(keyHook);
						UnhookWindowsHookEx(kbdHook);
					}
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
						KillProcess(pid, KILL_FORCE);
					} else { //��һ��
						closingProcess = true;
						SetTimer(hwnd, 3, 750, NULL);
					}
					break;
				case 1: { //Alt+W
					HWND topHwnd = GetForegroundWindow();
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
					if (!asking) {
						//���������Ͻ��¼�
						GetCursorPos(&p);
						if (p.x == 0 && p.y == 0) {
							asking = true;
							HWND topHwnd = GetForegroundWindow();
							if (MessageBox(hwnd, "��⵽�����λ�ñ仯���Ƿ���С�����㴰�ڣ�", "ʵʱ���", MB_YESNO | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST) == IDYES) {
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
								error = GetLastError();
								//�رո����ڣ��Ӵ���Ҳ��һ������
								PostMessage(hParent, WM_CLOSE, 0, 0);
							}
							asking = false;
						}
						break;
					}
				case 2: {
					std::string title = RandomWindowTitle();
					SetWindowText(hwnd,title.c_str());
					DWORD id = GetProcessIDFromName(MythwareFilename);
					if (id == 0) {
						SendMessage(TxOut, SB_SETTEXT, 1, LPARAM("����δ����"));
						mwSts = 2;
						SetWindowText(BtKmw, "��������");
					} else {
						mwSts = GetProcessState(id);
						std::string show;
						if (mwSts == -1)show = "����״̬δ֪";
						else if (mwSts == 0)show = "����������";
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
			if (lParam == WM_LBUTTONDBLCLK) { //���˫��
				ShowWindow(hwnd, SW_SHOWNORMAL);
				SetForegroundWindow(hwnd);
			} else if (lParam == WM_RBUTTONUP) { //�Ҽ�����
				GetCursorPos(&pt);
				SetForegroundWindow(hwnd);
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
						HWND bdCst = FindWindow(NULL, "��Ļ�㲥");
						BOOL bWindowing = FALSE;
						if (bdCst) {
							LONG lStyle = GetWindowLong(bdCst, GWL_STYLE);
							if (lStyle & WS_SYSMENU)bWindowing = TRUE;
						}
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
						AppendMenu(hSplitMenu, MF_BYPOSITION, 2, bWindowing ? "�㲥ȫ����" : "�㲥���ڻ�");
						EnableMenuItem(hSplitMenu, 2, bdCst ? MF_ENABLED : MF_GRAYED);
						// Display the menu.
						SuspendThread(thread);
						int i = TrackPopupMenu(hSplitMenu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD, pt.x, pt.y, 0, hwnd, NULL);
						ResumeThread(thread);
						switch (i) {
							case 1: {
								BOOL sts = SuspendProcess(GetProcessIDFromName(MythwareFilename), !mwSts);
								if (sts)SetWindowText(TxOut, "����/�ָ��ɹ�");
								else SetWindowText(TxOut, "����/�ָ�ʧ��");
								SendMessage(hwnd, WM_TIMER, WPARAM(2), NULL);
								break;
							}
							case 2: {
								/*//��ȡ�㲥���ھ��
								HWND bdCst = FindWindow(NULL, "��Ļ�㲥");
								if (!bdCst) {
									SetWindowText(TxOut, "δ�ҵ��㲥����");
									break;
								  }*/
								//�ҵ�������
								HWND menuBar = FindWindowEx(bdCst, NULL, "AfxWnd80u", NULL);
								//��ʾ������
								/*ShowWindow(menuBar, SW_SHOWDEFAULT);
								SetWindowPos(menuBar, HWND_TOP, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);*/
								//���ȫ����ť
								//EnableWindow(GetDlgItem(menuBar, 1004),FALSE);
								//ģ����
								PostMessage(bdCst, WM_COMMAND, WPARAM((BM_CLICK << 16) | 1004), NULL);
								SetWindowText(TxOut, bWindowing ? "ȫ�������" : "���ڻ����");
								break;
							}/*
				case 3: {
					HWND bdCst = FindWindow(NULL, "��Ļ�㲥");
					if (!bdCst) {
						SetWindowText(TxOut, "δ�ҵ��㲥����");
						break;
					}
					HWND menuBar = FindWindowEx(bdCst, NULL, "AfxWnd80u", NULL);
					ShowWindow(menuBar, SW_NORMAL);
					SetWindowPos(menuBar, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
					SetWindowText(TxOut, "ȫ�������");
					break;
				}*/
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
			//ʵ�ֿհ״������϶�
			SendMessage(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
			break;
		case WM_SYSCOMMAND:
			switch (wParam) {
				case 1: {
					if (MessageBox(hwnd, "���Ƿ�Ҫ��ѧ�������������ֵ��������12345678����7.1-7.5�汾��Ч���ò��������棡��", "����", MB_YESNO | MB_ICONWARNING) == IDYES) {
						std::string c = "8a29cc29f5951530ac69f4";
						HKEY retKey;
						LONG ret = RegOpenKeyEx(HKEY_CURRENT_USER, "Software", 0, KEY_SET_VALUE, &retKey);
						if (ret != ERROR_SUCCESS) {
							SetWindowText(TxOut, "����ʧ��");
							RegCloseKey(retKey);
							break;
						}
						ret = RegSetValueEx(retKey, "n", 0, REG_SZ, (CONST BYTE*)c.c_str(), c.size() + 1);
						SetWindowText(TxOut, "���óɹ�");
						RegCloseKey(retKey);
						break;
					}
				}
				case 2: {
					if (error == -1)error = GetLastError();
					HLOCAL LocalAddress = NULL;
					FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
					              NULL, error, 0, (PTSTR)&LocalAddress, 0, NULL);
					LPSTR msg = LPSTR(LocalAddress);
					std::string s;
					sprintf(s.data(), "GetLastError��һ������\n%u��%s", error, msg);
					LocalFree(LocalAddress);
					MessageBox(hwnd, TEXT(s.c_str()), TEXT("��һ������"), MB_OK | MB_ICONINFORMATION);
					error = -1;
					break;
				}
				case 3:{
					//�ж���û������
					HWND h=FindWindow("TaskManagerWindow", NULL);
					if(!h){
						//�����û�о�������
						WinExec("taskmgr", SW_SHOW);
						do{
							//�ȴ����ڴ������
							Sleep(50);
							h=FindWindow("TaskManagerWindow", NULL);
						}while(!h);
					}
					//��ȡ�˵���ȡ�ù�ѡ״̬
					HMENU hm = GetMenu(h);
					MENUITEMINFO mii = {sizeof(MENUITEMINFO), MIIM_STATE};
					GetMenuItemInfo(hm, 0x7704, FALSE, &mii);
					//���δ��ѡ��ģ�⹴ѡ
					if(!(mii.fState & MFS_CHECKED))
						PostMessage(h, WM_COMMAND, 0x7704, 0);
					SetWindowText(TxOut, "�������");
				}
				case SC_MINIMIZE:
					focus = GetFocus();//��ֹ��С���󽹵�ʧЧ
			}
			return DefWindowProc(hwnd, Message, wParam, lParam);
		case WM_SIZE:
			if (wParam == SIZE_MINIMIZED) {
				ShowWindow(hwnd, SW_HIDE); //����
				break;
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
	//�ж��Ƿ�ΪϵͳȨ��
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
	//��SystemȨ����������
	//���https://blog.csdn.net/weixin_42112038/article/details/126308315
	if (!bIsLocalSystem && (_stricmp(lpCmdLine, "-s") == 0 || _stricmp(lpCmdLine, "/s") == 0)) {
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
		si.lpDesktop = L"winsta0\\default";
		BOOL bResult = CreateProcessWithTokenW(hToken, LOGON_NETCREDENTIALS_ONLY, NULL, GetCommandLineW(), NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi);
		error = GetLastError();
		CloseHandle(hToken);
		if (bResult)return 0;
		else MessageBox(0, "�޷���ϵͳȨ�����б�����������ͨ��ʽ���С����˽������Ϣ����鿴��һ������", "��������", MB_ICONERROR | MB_OK);
	}
	//������ʼ
	InitCommonControls();

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
		MessageBox(NULL, "Window Registration Failed!", "Error!", MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	//���������
	std::string title = RandomWindowTitle();

	hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, "WindowClass", title.c_str(), (WS_OVERLAPPEDWINDOW | WS_VISIBLE)^WS_MAXIMIZEBOX ^ WS_SIZEBOX,
	                      0, /* x */
	                      0, /* y */
	                      width, /* width */
	                      height, /* height */
	                      NULL, NULL, hInstance, NULL);

	if (hwnd == NULL) {
		MessageBox(NULL, "Window Creation Failed!", "Error!", MB_ICONEXCLAMATION | MB_OK);
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

//https://blog.csdn.net/liu_zhou_zhou/article/details/118603143
BOOL GetMythwarePasswordFromRegedit(char *str) {
	HKEY retKey;
	BYTE retKeyVal[MAX_PATH * 10] = { 0 };
	DWORD nSize = MAX_PATH * 10;
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

//��ɱ��ÿ���̵߳ķ������ĳЩ����hookס��TerminateProcess()������
bool KillProcess(DWORD dwProcessID, int way) {
	if (way == KILL_FORCE) {
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessID);

		if (hSnapshot != INVALID_HANDLE_VALUE) {
			bool rtn = false;
			THREADENTRY32 te = {sizeof(te)};
			BOOL fOk = Thread32First(hSnapshot, &te);
			for (; fOk; fOk = Thread32Next(hSnapshot, &te)) {
				if (te.th32OwnerProcessID == dwProcessID) {
					HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, te.th32ThreadID);
					if (TerminateThread(hThread, 0)) rtn = true;
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

DWORD WINAPI ThreadProc(LPVOID lpParameter) {
	while (true) {
		SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
		Sleep(40);//��������ö�����������ر��CPU
	}
	return 0L;
}


LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {
	//KBDLLHOOKSTRUCT *pkbhs = (KBDLLHOOKSTRUCT *)lParam;
	//HWND hwnd=GetForegroundWindow();
	//PostMessage(hwnd, UINT(wParam), WPARAM(pkbhs->vkCode), NULL/*TODO*/);
	return FALSE;//CallNextHookEx(NULL, nCode, wParam, lParam);
}
//https://www.52pojie.cn/thread-542884-1-1.html ��ɾ��
DWORD WINAPI KeyHookThreadProc(LPVOID lpParameter) {
	while (true) {
		kbdHook = (HHOOK)SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)HookProc, GetModuleHandle(NULL), 0);
		Sleep(25);
		UnhookWindowsHookEx(kbdHook);
	}
	return 0;
}
DWORD WINAPI MouseHookThreadProc(LPVOID lpParameter) {
	while (true) {
		mseHook = (HHOOK)SetWindowsHookEx(WH_MOUSE_LL, (HOOKPROC)HookProc, GetModuleHandle(NULL), 0);
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
		if (_stricmp("#32770", szClass) == 0) { //�жϴ��봰���Ƿ���MessageBox�Ĵ���
			SetDlgItemText(msgHwnd, IDYES, "�ر�");
			SetDlgItemText(msgHwnd, IDNO, "ǿ�ƹر�");
			SetDlgItemText(msgHwnd, IDCANCEL, "ȡ��");
			HMENU msgMenu = GetSystemMenu(msgHwnd, FALSE);
			EnableMenuItem(msgMenu, SC_CLOSE, MF_GRAYED);
		}
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

BOOL CALLBACK SetWindowFont(HWND hwndChild, LPARAM lParam) {
	SendMessage(hwndChild, WM_SETFONT, WPARAM(hFont), 0);
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

//������̣�����δ��������NtSuspendProcess��suspend������������/�ָ�
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

//��ԭ�ṹ֮����ϲ�Ӱ��ṹ��С���߳����飬��������Խ������Ŀ�ṹ���ʺ�����߳̽ṹ
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
	//����Ϊԭ�ṹ����
	SYSTEM_THREAD_INFORMATION Threads[0];
} MYSYSTEM_PROCESS_INFORMATION, *PMYSYSTEM_PROCESS_INFORMATION;

//����ԭ����
#define SYSTEM_PROCESS_INFORMATION MYSYSTEM_PROCESS_INFORMATION
#define PSYSTEM_PROCESS_INFORMATION PMYSYSTEM_PROCESS_INFORMATION

//���庯��ԭ��
typedef NTSTATUS(NTSYSAPI NTAPI *FunNtQuerySystemInformation)
(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation,
 IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);

//��ȡ���̵�״̬
//����-1����ʾ�����쳣
//����0����ʾ����û�б�����
//����1����ʾ���̴��ڹ���״̬
int GetProcessState(DWORD dwProcessID) {
	int nStatus = -1;
	//ȡ������ַ
	FunNtQuerySystemInformation mNtQuerySystemInformation = FunNtQuerySystemInformation(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation"));
	//�ȵ���һ�Σ���ȡ���軺������С
	DWORD dwSize;
	mNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &dwSize);
	//���뻺����
	HGLOBAL hBuffer = GlobalAlloc(LPTR, dwSize);
	if (hBuffer == NULL)
		return nStatus;
	PSYSTEM_PROCESS_INFORMATION pInfo = PSYSTEM_PROCESS_INFORMATION(hBuffer);
	//��ѯ
	NTSTATUS lStatus = mNtQuerySystemInformation(SystemProcessInformation, pInfo, dwSize, 0);
	if (!NT_SUCCESS(lStatus)) {
		GlobalFree(hBuffer);
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

bool SetupTrayIcon(HWND m_hWnd, HINSTANCE hInstance) {
	icon.cbSize = sizeof(NOTIFYICONDATA); // �ṹ��С
	icon.hWnd = m_hWnd; // ���� ����֪ͨ��Ϣ �Ĵ��ھ��
	icon.uID = 0;
	icon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; //��ʾuCallbackMessage ��Ч
	icon.uCallbackMessage = WM_USER + 3; // ��Ϣ�����͵��˴��ڹ���
	icon.hIcon = LoadIcon(hInstance, "A");
	strcpy(icon.szTip, "���򹤾߰�");             // ��ʾ�ı�
	return 0 != Shell_NotifyIcon(NIM_ADD, &icon);
}

std::string RandomWindowTitle(){
	//���������
	std::srand((unsigned) time(NULL));
	std::string title;
	for (int i = 0; i < 10; i++) {
		int u = std::rand(), c = u % 31;//����31��Ϊ�˼������ֳ��ָ���
		if (c < 5)title.push_back(u % 10 + '0');
		else if (c < 18)title.push_back(u % 26 + 'a');
		else title.push_back(u % 26 + 'A');
	}
	return title;
}
