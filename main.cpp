#include <windows.h>
//#include<ddk/ntifs.h>
//#include<ddk/ntddk.h>
#include <cstdio>
#include <tlhelp32.h>
#include <ctime>
#include <commctrl.h>
using namespace std;
BOOL GetMythwarePasswordFromRegedit(char *str);
DWORD GetProcessIDFromName(LPCSTR szName);
bool KillProcess(DWORD dwProcessID, int way);
DWORD WINAPI ThreadProc(LPVOID lpParameter);
BOOL CALLBACK SetWindowFont(HWND hwndChild, LPARAM lParam);
bool SetupTrayIcon(HWND m_hWnd, HINSTANCE hInstance);
BOOL EnableDebugPrivilege();
DWORD WINAPI Update(LPVOID lpParameter);

HWND hwnd,last; /* A 'HANDLE', hence the H, or a pointer to our window */
/* This is where all the input to the window goes to */
#define KILL_FORCE 1
#define KILL_DEFAULT 2
LPCSTR MythwareFilename = "StudentMain.exe";
HFONT hFont;
NOTIFYICONDATA icon;
HMENU hMenu;//���̲˵�
char*path;
int width = 528, height = 250, w, h;
HWND BtAbt, TxOut, TxLnk, BtTop, BtCur, BtKbh;
LPCSTR helpText = "���򹤾߰�\n\
���⹦�ܣ���ݼ�Shift+Kɱ�����֣�Shift+W��С�����㴰��\n\
�����������Ļ���Ͻ�ʱ������ѡ����С�����㴰��\n\
��С��ʱ���ص����������̣����˫���������棬�Ҽ����������˵�\n\
���������ʾ����ʧ�ܣ���������Ȩ�޻�ָ��ע����ֵ�����ڣ��ڴ�����£�ͨ�������������";
HANDLE thread/*����ˢ���ö�����Timer����bug*/,keyHook/*�������*/;
UINT WM_TASKBAR;

LRESULT CALLBACK WndProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
	POINT p;
	POINT pt;
	switch (Message) {
		case WM_CREATE: {
			EnableDebugPrivilege();//��Ȩ
			w = GetSystemMetrics(SM_CXSCREEN);//��Ļ��ȣ�ע���ʵ�ʿ�ȶ�1�������õ��ĵط���Ҫ-1��
			h = GetSystemMetrics(SM_CYSCREEN);//��Ļ�߶�
			NONCLIENTMETRICS info;
			info.cbSize = sizeof(NONCLIENTMETRICS);
			if (SystemParametersInfo (SPI_GETNONCLIENTMETRICS, 0, &info, 0))
			{
				hFont = CreateFontIndirect ((LOGFONT*)&info.lfMessageFont);
			}//ȡϵͳĬ������
			WM_TASKBAR = RegisterWindowMessage(TEXT("TaskbarCreated"));
			thread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);//�ö�����
			keyHook = CreateThread(NULL, 0, Update, NULL, CREATE_SUSPENDED, NULL);//������
			SetTimer(hwnd, 1, 1000, NULL); //���������Ͻ�
			RegisterHotKey(hwnd, 0, MOD_SHIFT, 75); //Shift+Kɱ������
			RegisterHotKey(hwnd, 1, MOD_SHIFT, 87); //Shift+W��С�����㴰��
			HINSTANCE hi = ((LPCREATESTRUCT) lParam)->hInstance;
			TxLnk = CreateWindow(TEXT("SysLink"), TEXT("���򹤾߰� <a href=\"https://blog.csdn.net/weixin_42112038?type=blog\">����</a>"), WS_CHILD | WS_VISIBLE | WS_TABSTOP, 8, 8, 120, 20, hwnd, HMENU(1), hi, NULL);
			BtAbt = CreateWindow(TEXT("Button"), TEXT("����/����"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | BS_NOTIFY, 166, 3, 90, 30, hwnd, HMENU(2), hi, NULL);
			//��ȡ����
			char str[MAX_PATH] = {0};
			LPCSTR psd;
			if (GetMythwarePasswordFromRegedit(str) == FALSE) {
				psd = TEXT("��ȡ����ʧ��");
			} else {
				psd = TEXT(str);
			}
			CreateWindow(TEXT("Edit"), psd, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY, 8, 36, 248, 20, hwnd, HMENU(3), hi, NULL);
			CreateWindow(TEXT("Button"), TEXT("ɱ������"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | BS_NOTIFY, 8, 122, 248, 50, hwnd, HMENU(4), hi, NULL);
			CreateWindow(TEXT("Button"), TEXT("ɱ��ѧ��������������"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | BS_NOTIFY,  8, 64, 248, 50, hwnd, HMENU(13), hi, NULL);
			TxOut = CreateWindow(TEXT("msctls_statusbar32"), TEXT("�ȴ�����"), WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, HMENU(5), hi, NULL);
			CreateWindow(TEXT("Button"), TEXT("������ù���"), WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 264, 8, 248, 174, hwnd, HMENU(6), hi, NULL);
			CreateWindow(TEXT("Button"), TEXT("���cmd����"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | BS_NOTIFY, 272, 28, 112, 30, hwnd, HMENU(7), hi, NULL);
			CreateWindow(TEXT("Button"), TEXT("���ע���༭��"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | BS_NOTIFY, 392, 28, 112, 30, hwnd, HMENU(8), hi, NULL);
			CreateWindow(TEXT("Button"), TEXT("������������"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | BS_NOTIFY, 272, 66, 112, 30, hwnd, HMENU(9), hi, NULL);
			CreateWindow(TEXT("Button"), TEXT("���Win+R����"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | BS_NOTIFY, 392, 66, 112, 30, hwnd, HMENU(10), hi, NULL);
			CreateWindow(TEXT("Button"), TEXT("���taskkill"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | BS_NOTIFY, 272, 104, 112, 30, hwnd, HMENU(11), hi, NULL);
			CreateWindow(TEXT("Button"), TEXT("������Դ������"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | BS_NOTIFY, 392, 104, 112, 30, hwnd, HMENU(12), hi, NULL);
			CreateWindow(TEXT("Button"), TEXT("�������USB����"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | BS_NOTIFY, 272, 142, 112, 30, hwnd, HMENU(14), hi, NULL);
			CreateWindow(TEXT("Button"), TEXT("���ע���˻�"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | BS_NOTIFY, 392, 142, 112, 30, hwnd, HMENU(15), hi, NULL);
			BtTop = CreateWindow(TEXT("Button"), TEXT("�ö��˴���"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 8, 176, 77, 18, hwnd, HMENU(16), hi, NULL);
			SendMessage(BtTop, BM_SETCHECK, BST_CHECKED, NULL);
			BtCur = CreateWindow(TEXT("Button"), TEXT("����������"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 90, 176, 87, 18, hwnd, HMENU(17), hi, NULL);
			BtKbh = CreateWindow(TEXT("Button"), TEXT("�������"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 183, 176, 87, 18, hwnd, HMENU(18), hi, NULL);
			EnumChildWindows(hwnd, SetWindowFont, (LPARAM)0);
			hMenu = CreatePopupMenu();
			AppendMenu(hMenu, MF_STRING, 1, TEXT("�رճ���"));
			AppendMenu(hMenu, MF_STRING, 2, TEXT("�򿪽���"));
			SetupTrayIcon(hwnd, hi);
			break;
		}
		case WM_COMMAND: {
			if(HIWORD(wParam)==BN_SETFOCUS){
				last=HWND(lParam);
				SetWindowLong(last,GWL_STYLE,GetWindowLong(last,GWL_STYLE)|BS_DEFPUSHBUTTON);
			}
			else if(HIWORD(wParam)==BN_KILLFOCUS)	
			{
				SetWindowLong(last,GWL_STYLE,GetWindowLong(last,GWL_STYLE)^BS_DEFPUSHBUTTON);
			}
			switch (wParam) {
				case 1: {
					break;
				}
				case 2: {
					MessageBox(NULL, helpText, "����/����", MB_OK | MB_ICONINFORMATION);
					break;
				}
				case 4: {
					if (KillProcess(GetProcessIDFromName(MythwareFilename), KILL_FORCE)) {
						SetWindowText(TxOut, "ִ�гɹ�");
					} else {
						SetWindowText(TxOut, "ִ��ʧ��");
					}
					break;
				}
				case 7: {
					//HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System:DisableCMD->0
					HKEY retKey;
					DWORD value = 0;
					LONG ret = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\System", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						break;
					}
					ret = RegSetValueEx(retKey, "DisableCMD", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					RegCloseKey(retKey);

					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						break;
					}
					SetWindowText(TxOut, "���óɹ�");

					break;
				}
				case 8: {
					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System:DisableRegistryTools->0
					HKEY retKey;
					DWORD value = 0;
					LONG ret = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
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
				case 9: {
					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System:DisableTaskMgr->0
					HKEY retKey;
					DWORD value = 0;
					LONG ret = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
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
				case 10: {
					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoRun->0
					HKEY retKey;
					DWORD value = 0;
					LONG ret = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						break;
					}
					ret = RegSetValueEx(retKey, "NoRun", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					RegCloseKey(retKey);

					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						break;
					}
					SetWindowText(TxOut, "���óɹ���������Դ������������Ч");
					break;
				}
				case 11: {
					//HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskkill.exe:debugger:(
					HKEY retKey;
					LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskkill.exe", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
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
				case 12: {
					/*if (KillProcess(GetProcessIDFromName("explorer.exe") ) == FALSE) {
						SetWindowText(TxOut, "ִ��ʧ��");
						break;
					}
					Sleep(200);
					//����Դ������
					WinExec("start explorer.exe", SW_HIDE);*/
					HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, GetProcessIDFromName("explorer.exe"));
					if (TerminateProcess(handle, 2))
						SetWindowText(TxOut, "ִ�гɹ�");
					else
						SetWindowText(TxOut, "ִ��ʧ��");
					CloseHandle(handle);
					break;
				}
				case 13: {
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
					time_t curtime;
					time(&curtime);
					tm *nowtime = localtime(&curtime);
					int n3 = 1 + nowtime->tm_mon + nowtime->tm_mday;
					int n4, n5, n6;
					DWORD prozsPid;
					if (version[0] == '7' && version[2] == '2') {
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
						char c[4] = {'p', 0, 0, '\0'};
						if (n3 % 2 != 0)
							c[1] = n4 + 102, c[2] = n5 + 98;
						else
							c[1] = n4 + 99,  c[2] = n5 + 106;
						prozsPid = GetProcessIDFromName(strcat(c, ".exe"));
					}
					KillProcess(prozsPid, KILL_DEFAULT);
					KillProcess(GetProcessIDFromName("jfglzs.exe"), KILL_DEFAULT);
					SetWindowText(TxOut, "ִ�гɹ�");
					break;
				}
				case 14: {
					//HKEY_LOCAL_MACHINE\SOFTWARE\jfglzs:usb_jianche->off
					//���ע���ġ���⡱�������
					char c[4] = "off";
					HKEY retKey;
					LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\jfglzs", 0, KEY_SET_VALUE, &retKey);
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						break;
					}
					ret = RegSetValueEx(retKey, "usb_jianche", 0, REG_SZ, (CONST BYTE*)&c, 4);
					SetWindowText(TxOut, "���óɹ�");
					RegCloseKey(retKey);
					break;
				}
				case 15: {
					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoLogOff->0
					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer:StartMenuLogOff->0
					//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System:DisableLockWorkstation->0
					HKEY retKey;
					DWORD value = 0;
					LONG ret = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						break;
					}
					ret = RegSetValueEx(retKey, "NoLogOff", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					ret = RegSetValueEx(retKey, "StartMenuLogOff", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					RegCloseKey(retKey);
					ret = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &retKey);
					ret = RegSetValueEx(retKey, "DisableLockWorkstation", 0, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));
					if (ret != ERROR_SUCCESS) {
						SetWindowText(TxOut, "����ʧ��");
						break;
					}
					SetWindowText(TxOut, "���óɹ�");
					break;
				}
				case 16:{
					LRESULT check = SendMessage(BtTop, BM_GETCHECK, NULL, NULL);
					if (check == BST_CHECKED) {
						ResumeThread(thread);
					} else {
						SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
						SuspendThread(thread);
					}
					break;
				}
				case 17:{
					LRESULT check = SendMessage(BtCur, BM_GETCHECK, NULL, NULL);
					if (check == BST_CHECKED) {
						SetTimer(hwnd, 2, 10, NULL);
					} else {
						KillTimer(hwnd, 2);
					}
					break;
				}
				case 18:{
					LRESULT check = SendMessage(BtKbh, BM_GETCHECK, NULL, NULL);
					if (check == BST_CHECKED) {
						ResumeThread(keyHook);
					} else {
						SuspendThread(keyHook);
					}
					break;
				}
			}
		}
		case WM_HOTKEY:
			switch (wParam) {
				case 0://Shift+K
					SendMessage(hwnd, WM_COMMAND, 13, lParam);
					break;
				case 1://Shift+W
					HWND topHwnd = GetForegroundWindow();
					ShowWindow(topHwnd, SW_MINIMIZE);
					break;
			}

			break;
		case WM_TIMER:
			switch (wParam) {
				case 1:
					//���������Ͻ��¼�
					GetCursorPos(&p);
					if (p.x == 0 && p.y == 0) {
						HWND topHwnd = GetForegroundWindow();
						if (MessageBox(hwnd, "��⵽�����λ�ñ仯���Ƿ���С���ö����ڣ�", "ʵʱ���", MB_YESNO | MB_ICONINFORMATION | MB_SETFOREGROUND) == IDYES) {
							ShowWindow(topHwnd, SW_MINIMIZE);
						}
					}
					else if(p.x == w-1 && p.y==0){
						HWND topHwnd = GetForegroundWindow();
						if (MessageBox(hwnd, "��⵽�����λ�ñ仯���Ƿ�ر��ö����ڣ�", "ʵʱ���", MB_YESNO | MB_ICONINFORMATION | MB_SETFOREGROUND) == IDYES) {
							PostMessage(topHwnd,WM_CLOSE,0,0);//�첽
						}
					}
					break;
				case 2:
					ClipCursor(0);
			}
			break;
		case WM_DESTROY:
			UnregisterHotKey(hwnd, 0);
			UnregisterHotKey(hwnd, 1);
			TerminateThread(thread, 0);
			KillTimer(hwnd, 1);
			KillTimer(hwnd, 2);
			Shell_NotifyIcon(NIM_DELETE, &icon); //ɾ������ͼ�꣬����ֻ����껮��ͼ�����ʧ
			PostQuitMessage(0);
			break;
		case WM_USER:
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
			break;
		case WM_NOTIFY:
			switch (((LPNMHDR)lParam)->code) {
				case NM_CLICK:
					if (((LPNMHDR)lParam)->hwndFrom == TxOut) {
						break;
					}
				case NM_RETURN: {
					PNMLINK pNMLink = (PNMLINK)lParam;
					LITEM   item    = pNMLink->item;
					if ((((LPNMHDR)lParam)->hwndFrom == TxLnk) && (item.iLink == 0)) {
						char lnk[L_MAX_URL_LENGTH];
						WideCharToMultiByte(CP_ACP, 0, item.szUrl, L_MAX_URL_LENGTH, lnk, L_MAX_URL_LENGTH, NULL, NULL);
						ShellExecute(NULL, "open", lnk, NULL, NULL, SW_SHOW);
					} else if (wcscmp(item.szID, L"idInfo") == 0) {
						MessageBox(hwnd, "This isn't much help.", "Example", MB_OK);
					}
					break;
				}
			}

			break;
		case WM_LBUTTONDOWN:
			SendMessage(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
			break;
		case WM_SIZE:
			if (wParam == SIZE_MINIMIZED){
				ShowWindow(hwnd, SW_HIDE); //����
				break;
			}
		/* All other messages (a lot of them) are processed using default procedures */
		default:
			if (Message == WM_TASKBAR)
				Shell_NotifyIcon(NIM_ADD, &icon);
			return DefWindowProc(hwnd, Message, wParam, lParam);
	}
	return 0;
}
/* The 'main' function of Win32 GUI programs: this is where execution starts */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
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
	hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, "WindowClass", "StudentManager", (WS_OVERLAPPEDWINDOW | WS_VISIBLE)^WS_MAXIMIZEBOX ^ WS_SIZEBOX,
	                      0, /* x */
	                      0, /* y */
	                      width, /* width */
	                      height, /* height */
	                      NULL, NULL, hInstance, NULL);

	if (hwnd == NULL) {
		MessageBox(NULL, "Window Creation Failed!", "Error!", MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}
	/*
		This is the heart of our program where all input is processed and
		sent to WndProc. Note that GetMessage blocks code flow until it receives something, so
		this loop will not produce unreasonably high CPU usage
	*/
	while (GetMessage(&msg, NULL, 0, 0) > 0) { /* If no error is received... */
		TranslateMessage(&msg); /* Translate key codes to chars if present */
		DispatchMessage(&msg); /* Send it to WndProc */
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
	for (int i = 0; i < int(nSize); i += 1) {
		printf("%x ", retKeyVal[i]);
		if (i % 8 == 0) puts("");
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

			THREADENTRY32 te = {sizeof(te)};
			BOOL fOk = Thread32First(hSnapshot, &te);
			for (; fOk; fOk = Thread32Next(hSnapshot, &te)) {
				if (te.th32OwnerProcessID == dwProcessID) {
					HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, te.th32ThreadID);
					TerminateThread(hThread, 0);
					CloseHandle(hThread);
				}
			}
			CloseHandle(hSnapshot);
			return true;
		}
		return false;
	} else if (way == KILL_DEFAULT) {
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

bool SetupTrayIcon(HWND m_hWnd, HINSTANCE hInstance) {
	icon.cbSize = sizeof(NOTIFYICONDATA); // �ṹ��С
	icon.hWnd = m_hWnd; // ���� ����֪ͨ��Ϣ �Ĵ��ھ��
	icon.uID = 0;
	icon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; //��ʾuCallbackMessage ��Ч
	icon.uCallbackMessage = WM_USER; // ��Ϣ�����͵��˴��ڹ���
	icon.hIcon = LoadIcon(hInstance, "A");
	strcpy(icon.szTip, "���򹤾߰�");             // ��ʾ�ı�
	return 0 != Shell_NotifyIcon(NIM_ADD, &icon);
}

HOOKPROC KeyboardProc;
//https://www.52pojie.cn/thread-542884-1-1.html ��ɾ��
DWORD WINAPI Update(LPVOID lpParameter)
{
	HHOOK m_hHOOK1 = NULL, m_hHOOK2 = NULL,m_hHOOK3 = NULL,m_hHOOK4 = NULL; 
	m_hHOOK1 = (HHOOK)SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)KeyboardProc, GetModuleHandle(NULL), 0);
	m_hHOOK2 = (HHOOK)SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)KeyboardProc, GetModuleHandle(NULL), 0);
	m_hHOOK3 = (HHOOK)SetWindowsHookEx(WH_KEYBOARD, (HOOKPROC)KeyboardProc, GetModuleHandle(NULL), 0);
	m_hHOOK4 = (HHOOK)SetWindowsHookEx(WH_KEYBOARD, (HOOKPROC)KeyboardProc, GetModuleHandle(NULL), 0);
	while(true)
	{
		UnhookWindowsHookEx(m_hHOOK1);
		UnhookWindowsHookEx(m_hHOOK3);
		m_hHOOK1 = (HHOOK)SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)KeyboardProc, GetModuleHandle(NULL), 0);
		m_hHOOK3 = (HHOOK)SetWindowsHookEx(WH_KEYBOARD, (HOOKPROC)KeyboardProc, GetModuleHandle(NULL), 0);
		UnhookWindowsHookEx(m_hHOOK2);
		UnhookWindowsHookEx(m_hHOOK4);
		m_hHOOK2 = (HHOOK)SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)KeyboardProc, GetModuleHandle(NULL), 0);
		m_hHOOK4 = (HHOOK)SetWindowsHookEx(WH_KEYBOARD, (HOOKPROC)KeyboardProc, GetModuleHandle(NULL), 0);
		Sleep(20);//����ռ��CPU����
	}
	return 0;
}

BOOL CALLBACK SetWindowFont(HWND hwndChild, LPARAM lParam) {
	SendMessage(hwndChild, WM_SETFONT, WPARAM(hFont), 0);
	return TRUE;
}

//https://blog.csdn.net/zuishikonghuan/article/details/47746451
BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	LUID Luid;
	TOKEN_PRIVILEGES tp;
	
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))return FALSE;
	
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid))
	{
		CloseHandle(hToken);
		return FALSE;
	}
	
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = Luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	
	if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL))
	{
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);
	return TRUE;
}
