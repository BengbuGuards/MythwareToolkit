#include <windows.h>
//#include<ddk/ntifs.h>
//#include<ddk/ntddk.h>
#include <cstdio>
#include <tlhelp32.h>
#include <ctime>
#include "uiaccess.h"
#include "commctrl.h"
#define KEY_DOWN(VK_NONAME) ((GetAsyncKeyState(VK_NONAME) & 0x8000) ? 1:0)
using namespace std;
BOOL GetMythwarePasswordFromRegedit(char *str);
DWORD GetProcessIDFromName(LPCSTR szName);
bool KillProcess(DWORD dwProcessID);
DWORD WINAPI ThreadProc(LPVOID lpParameter);
BOOL CALLBACK SetWindowFont(HWND hwndChild, LPARAM lParam);
bool SetupTrayIcon(HWND m_hWnd,HINSTANCE hInstance);

HWND hwnd; /* A 'HANDLE', hence the H, or a pointer to our window */
/* This is where all the input to the window goes to */
LPCSTR MythwareFilename = "StudentMain.exe";
HFONT hFont = CreateFont(-12, -6, 0, 0, 0, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, TEXT("΢���ź�"));
NOTIFYICONDATA icon;
HMENU hMenu;
char*path;
int width = 528, height = 250;
//HWND BtKbH;
HWND BtAbt;LPCSTR helpText="���򹤾߰�\n\
���⹦�ܣ���ݼ�Shift+Kɱ�����֣�Shift+W��С�����㴰��\n\
�����������Ļ���Ͻ�ʱ������ѡ����С�����㴰��\n\
��С��ʱ���ص����������̣����˫���������棬�Ҽ����������˵�\n\
���������ʾ����ʧ�ܣ���������Ȩ�޻�ָ��ע����ֵ�����ڣ��ڴ�����£�ͨ�������������";
HANDLE thread;//����ˢ���ö�����Timer����bug
//HWND TxPsd;
HWND TxOut;
/*HWND BtKps;
HWND BtKhp;
HWND RCG;
HWND BtEnCmd;
HWND BtEnReg;
HWND BtEnTgr;
HWND BtEnRun;
HWND BtEnTsk;
HWND BtRsExp;
HWND BtEnUsb;
HWND BtEnLgf;*/

LRESULT CALLBACK WndProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
	POINT p;
	UINT WM_TASKBAR=RegisterWindowMessage(TEXT("TaskbarCreated"));
	POINT pt;
	switch (Message) {
		case WM_CREATE: {
			thread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);//�ö�����
			SetTimer(hwnd,1,1000,NULL);//���������Ͻ�
			RegisterHotKey(hwnd, 0, MOD_SHIFT, 75); //Shift+Kɱ������
			RegisterHotKey(hwnd, 1, MOD_SHIFT, 87); //Shift+W��С�����㴰��	
			CreateWindow(TEXT("static"), TEXT("���򹤾߰�"), WS_CHILD | WS_VISIBLE | WS_TABSTOP, 8, 8, 120, 20, hwnd, HMENU(1), ((LPCREATESTRUCT) lParam)->hInstance, NULL);			BtAbt = CreateWindow(TEXT("button"), TEXT("����/����"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 166, 3, 90, 30, hwnd, HMENU(2), ((LPCREATESTRUCT) lParam)->hInstance, NULL);
			//��ȡ����
			char str[MAX_PATH * 10] = {0};
			LPCSTR psd;
			if (GetMythwarePasswordFromRegedit(str) == FALSE) {
				psd = TEXT("��ȡ����ʧ��");
			} else {
				psd = TEXT(str);
			}
			CreateWindow(TEXT("edit"), psd, WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_READONLY, 8, 36, 248, 20, hwnd, HMENU(3), ((LPCREATESTRUCT) lParam)->hInstance, NULL);
			CreateWindow(TEXT("button"), TEXT("ɱ������"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 8, 122, 248, 50, hwnd, HMENU(4), ((LPCREATESTRUCT) lParam)->hInstance, NULL);
			CreateWindow(TEXT("button"), TEXT("ɱ��ѧ��������������"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,  8, 64, 248, 50, hwnd, HMENU(13), ((LPCREATESTRUCT) lParam)->hInstance, NULL);
			TxOut = CreateWindow(TEXT("static"), TEXT("�ȴ�����"), WS_CHILD | WS_VISIBLE | WS_TABSTOP, 8, 188, 248, 20, hwnd, HMENU(5), ((LPCREATESTRUCT) lParam)->hInstance, NULL);
			CreateWindow(TEXT("button"), TEXT("������ù���"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_GROUPBOX, 264, 8, 248, 174, hwnd, HMENU(6), ((LPCREATESTRUCT) lParam)->hInstance, NULL);
			CreateWindow(TEXT("button"), TEXT("���cmd����"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 272, 28, 112, 30, hwnd, HMENU(7), ((LPCREATESTRUCT) lParam)->hInstance, NULL);
			CreateWindow(TEXT("button"), TEXT("���ע���༭��"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 392, 28, 112, 30, hwnd, HMENU(8), ((LPCREATESTRUCT) lParam)->hInstance, NULL);
			CreateWindow(TEXT("button"), TEXT("������������"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 272, 66, 112, 30, hwnd, HMENU(9), ((LPCREATESTRUCT) lParam)->hInstance, NULL);
			CreateWindow(TEXT("button"), TEXT("���Win+R����"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 392, 66, 112, 30, hwnd, HMENU(10), ((LPCREATESTRUCT) lParam)->hInstance, NULL);
			CreateWindow(TEXT("button"), TEXT("���taskkill"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 272, 104, 112, 30, hwnd, HMENU(11), ((LPCREATESTRUCT) lParam)->hInstance, NULL);
			CreateWindow(TEXT("button"), TEXT("������Դ������"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 392, 104, 112, 30, hwnd, HMENU(12), ((LPCREATESTRUCT) lParam)->hInstance, NULL);
			CreateWindow(TEXT("button"), TEXT("�������USB����"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 272, 142, 112, 30, hwnd, HMENU(14), ((LPCREATESTRUCT) lParam)->hInstance, NULL);
			CreateWindow(TEXT("button"), TEXT("���ע���˻�"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 392, 142, 112, 30, hwnd, HMENU(15), ((LPCREATESTRUCT) lParam)->hInstance, NULL);
			EnumChildWindows(hwnd, SetWindowFont, (LPARAM)0);
			hMenu=CreatePopupMenu();
			AppendMenu(hMenu,MF_STRING,1,TEXT("�رճ���"));
			AppendMenu(hMenu,MF_STRING,2,TEXT("�򿪽���"));
			SetupTrayIcon(hwnd,((LPCREATESTRUCT) lParam)->hInstance);
			break;
		}
		case WM_COMMAND: {
			switch (wParam) {
				case 1: {
					break;
				}
				case 2: {
					MessageBox(NULL,helpText,"����/����",MB_OK|MB_ICONINFORMATION);
					break;
				}
				case 4: {
					if (KillProcess(GetProcessIDFromName(MythwareFilename))) {
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
					if (KillProcess(GetProcessIDFromName("explorer.exe") ) == FALSE) {
						SetWindowText(TxOut, "ִ��ʧ��");
						break;
					}
					Sleep(200);
					//����Դ������
					WinExec("start explorer.exe", SW_HIDE);
					SetWindowText(TxOut, "ִ�гɹ�");
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
						SetWindowText(TxOut, "��ȡʧ��");
						break;
					}
					//ȡʱ�����ڼ���prozs.exe�����������
					time_t curtime;
					time(&curtime);
					tm *nowtime = localtime(&curtime);
					int n3 = 1 + nowtime->tm_mon + nowtime->tm_mday;int n4, n5, n6;
					char c1, c2, c3, c4;
					DWORD prozsPid;
					if (version[0]=='7'&&version[2]=='2') {
						
						//����Ϊ7.2�汾�߼�
						n4 = n3 % 7, n5 = n3 % 9, n6 = n3 % 5;
						if (n3 % 2 != 0) {
							c1 = 103 + n5,  c2 = 111 + n4,  c3 = 107 + n6,  c4 = 48 + n4;
						} else {
							c1 = 97 + n4,   c2 = 109 + n5,  c3 = 101 + n6,  c4 = 48 + n5;
						}
						char c[5] = {c1, c2, c3, c4, '\0'};
						prozsPid = GetProcessIDFromName(strcat(c, ".exe")); //ȡ��pid
					} else {
						//����Ϊ7.2�汾֮ǰ���߼�
						n4 = n3 % 3 + 3, n5 = n3 % 4 + 4;
						char str[4];
						str[0] = 'p';
						if (n3 % 2 != 0)
							str[1] = n4 + 102, str[2] = n5 + 98;
						else
							str[1] = n4 + 99,  str[2] = n5 + 106;
						str[3] = '\0';
						prozsPid = GetProcessIDFromName(strcat(str, ".exe"));
					}
					KillProcess(prozsPid);
					KillProcess(GetProcessIDFromName("jfglzs.exe"));
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
			}
			break;
		}
		case WM_HOTKEY:
			switch (wParam) {
				case 0://Shift+K
					WndProc(hwnd, WM_COMMAND, 13, lParam);
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
						if (MessageBox(hwnd,"��⵽�����λ�ñ仯���Ƿ���С���ö����ڣ�", "ʵʱ���", MB_YESNO | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST) == IDYES) {
							ShowWindow(topHwnd, SW_MINIMIZE);
						}
					}
					break;
			}
			break;
		case WM_DESTROY:
			UnregisterHotKey(hwnd, 0);
			UnregisterHotKey(hwnd, 1);
			TerminateThread(thread,0);
			KillTimer(hwnd,1);
			Shell_NotifyIcon(NIM_DELETE,&icon);//ɾ������ͼ�꣬����ֻ����껮��ͼ�����ʧ
			PostQuitMessage(0);
			break;
		case WM_SIZE:
			if(wParam==SIZE_MINIMIZED)
				ShowWindow(hwnd,SW_HIDE);//����
			break;
		case WM_USER:
			if(lParam==WM_LBUTTONDBLCLK){//���˫��
				ShowWindow(hwnd,SW_SHOWNORMAL);
				SetForegroundWindow(hwnd);
			}
			else if(lParam==WM_RBUTTONUP){//�Ҽ�����
				GetCursorPos(&pt);
				SetForegroundWindow(hwnd);
				int i=TrackPopupMenu(hMenu,TPM_RETURNCMD,pt.x,pt.y,NULL,hwnd,NULL);
				switch(i){
					case 1:
						//TODO
						WndProc(hwnd,WM_CLOSE,NULL,NULL);
						break;
					case 2:
						ShowWindow(hwnd,SW_SHOWNORMAL);
						SetForegroundWindow(hwnd);
						break;
				}
			}
			break;
		/* All other messages (a lot of them) are processed using default procedures */
		default:
			if(Message==WM_TASKBAR)
				SetupTrayIcon(hwnd,((LPCREATESTRUCT) lParam)->hInstance);
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
bool KillProcess(DWORD dwProcessID) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(
	                   TH32CS_SNAPTHREAD, dwProcessID);

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
}

DWORD WINAPI ThreadProc(LPVOID lpParameter) {
	while (true) {
		SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
		Sleep(40);
	}
	return 0L;
}

bool SetupTrayIcon(HWND m_hWnd,HINSTANCE hInstance) {
	icon.cbSize = sizeof(NOTIFYICONDATA); // �ṹ��С
	icon.hWnd = m_hWnd; // ���� ����֪ͨ��Ϣ �Ĵ��ھ��
	icon.uID = 0;
	icon.uFlags = NIF_ICON|NIF_MESSAGE|NIF_TIP; //��ʾuCallbackMessage ��Ч
	icon.uCallbackMessage = WM_USER; // ��Ϣ�����͵��˴��ڹ���
	icon.hIcon = LoadIcon(hInstance, "A"); 
	strcpy(icon.szTip, "���򹤾߰�");             // ��ʾ�ı�
	return 0 != Shell_NotifyIcon(NIM_ADD, &icon);
}

BOOL CALLBACK SetWindowFont(HWND hwndChild, LPARAM lParam) {
	SendMessage(hwndChild, WM_SETFONT, WPARAM(hFont), 0);
	return TRUE;
}
