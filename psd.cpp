#include "main.h"
#include "psd.h"

//----------助手----------

void UpdateTempPsd(HWND hwndDlg)
{
	if (!IsWindow(hwndDlg))
		return;
	CHAR szComputerName[32] = {};
	GetDlgItemText(hwndDlg, 1002, szComputerName, 32);
	if (strlen(szComputerName) == 0)
		strcpy(szComputerName, "X");
	SYSTEMTIME date = {};
	SendDlgItemMessage(hwndDlg, 1001, DTM_GETSYSTEMTIME, 0, LPARAM(&date));
	// 10.0-
	char szPsd[16] = {};
	int iPsd = 16 * (date.wYear * 91 + date.wMonth * 13 + date.wDay * 57);
	itoa(iPsd, szPsd + 1, 10);
	szPsd[0] = '8';
	SetDlgItemText(hwndDlg, 1003, szPsd);
	// 10.0-11.0
	itoa(iPsd + 11, szPsd + 1, 10);
	SetDlgItemText(hwndDlg, 1004, szPsd);
	// 11.00-11.06
	iPsd = date.wYear * 789 + date.wMonth * 123 + date.wDay * 456 + 111;
	itoa(iPsd, szPsd, 10);
	SetDlgItemText(hwndDlg, 1005, szPsd);
	// 11.06+
	char lastChar = szComputerName[strlen(szComputerName) - 1];
	iPsd = date.wMonth * 159 + date.wDay * 357 + lastChar * 258;
	itoa(iPsd, szPsd, 7);
	SetDlgItemText(hwndDlg, 1006, szPsd);
}
// namespace PsdWnd{int w = 256, h = 192;};
namespace PsdWnd
{
	int w = 136, h = 192;
};

INT_PTR CALLBACK PsdWndProc(HWND hWndDlg, UINT Message, WPARAM wParam, LPARAM lParam)
{
	switch (Message)
	{
	case WM_INITDIALOG:
	{
		CreateWindow(WC_STATIC, "日期:", WS_CHILD | WS_VISIBLE,
					 16, 16, 80, 24, hWndDlg, NULL, NULL, NULL);
		CreateWindow(DATETIMEPICK_CLASS, "", WS_CHILD | WS_VISIBLE | WS_TABSTOP | DTS_LONGDATEFORMAT,
					 104, 16, 152, 24, hWndDlg, (HMENU)1001, NULL, NULL);

		CreateWindow(WC_STATIC, "计算机名:", WS_CHILD | WS_VISIBLE,
					 16, 48, 80, 24, hWndDlg, NULL, NULL, NULL);
		DWORD dwSize = MAX_COMPUTERNAME_LENGTH + 1;
		char szName[dwSize] = {};
		GetComputerName(szName, &dwSize);
		HWND hwndEdit = CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, szName,
									   WS_CHILD | WS_VISIBLE | WS_TABSTOP,
									   104, 48, 152, 24, hWndDlg, (HMENU)1002, NULL, NULL);
		SendMessage(hwndEdit, EM_SETLIMITTEXT, MAX_COMPUTERNAME_LENGTH, 0);

		CreateWindow(WC_BUTTON, "计算结果", WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
					 8, 80, 256, 156, hWndDlg, NULL, NULL, NULL);

		CreateWindow(WC_STATIC, "10.1-", WS_CHILD | WS_VISIBLE,
					 24, 108, 72, 24, hWndDlg, NULL, NULL, NULL);
		CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, "",
					   WS_CHILD | WS_VISIBLE | ES_READONLY | WS_TABSTOP,
					   104, 104, 152, 24, hWndDlg, (HMENU)1003, NULL, NULL);

		CreateWindow(WC_STATIC, "10.x", WS_CHILD | WS_VISIBLE,
					 24, 140, 72, 24, hWndDlg, NULL, NULL, NULL);
		CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, "",
					   WS_CHILD | WS_VISIBLE | ES_READONLY | WS_TABSTOP,
					   104, 136, 152, 24, hWndDlg, (HMENU)1004, NULL, NULL);

		CreateWindow(WC_STATIC, "11.0x", WS_CHILD | WS_VISIBLE,
					 24, 172, 72, 24, hWndDlg, NULL, NULL, NULL);
		CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, "",
					   WS_CHILD | WS_VISIBLE | ES_READONLY | WS_TABSTOP,
					   104, 168, 152, 24, hWndDlg, (HMENU)1005, NULL, NULL);

		CreateWindow(WC_STATIC, "11.06~12.0", WS_CHILD | WS_VISIBLE,
					 24, 204, 72, 24, hWndDlg, NULL, NULL, NULL);
		CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, "",
					   WS_CHILD | WS_VISIBLE | ES_READONLY | WS_TABSTOP,
					   104, 200, 152, 24, hWndDlg, (HMENU)1006, NULL, NULL);

		/*CreateWindow(WC_STATIC, "普通密码的密文：", WS_CHILD | WS_VISIBLE,
					 272, 16, 128, 24, hWndDlg, NULL, NULL, NULL);
		HWND hwndCipher = CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, "",
										 WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE |
											 ES_AUTOVSCROLL | ES_WANTRETURN,
										 272, 44, 232, 48, hWndDlg, (HMENU)1101, NULL, NULL);
		SendMessage(hwndCipher, EM_SETLIMITTEXT, 1024, 0);

		// 从注册表读取密文
		HKEY retKey;
		char szEP[70] = {};
		LONG ret = RegOpenKeyEx(HKEY_CURRENT_USER, "SOFTWARE", 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &retKey);
		DWORD dataLong = 70, type = REG_SZ;
		ret = RegQueryValueEx(retKey, "n", 0, &type, LPBYTE(szEP), &dataLong);
		RegCloseKey(retKey);
		SetDlgItemText(hWndDlg, 1101, szEP);

		CreateWindow(WC_BUTTON, "hashcat暴力破解参数生成", WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
					 272, 100, 232, 272, hWndDlg, NULL, NULL, NULL);

		CreateWindow(WC_BUTTON, "小写字母", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
					 288, 120, 96, 24, hWndDlg, (HMENU)1102, NULL, NULL);

		CreateWindow(WC_BUTTON, "大写字母", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
					 392, 120, 96, 24, hWndDlg, (HMENU)1103, NULL, NULL);

		CreateWindow(WC_BUTTON, "数字", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
					 288, 144, 64, 24, hWndDlg, (HMENU)1104, NULL, NULL);
		CreateWindow(WC_BUTTON, "特殊字符", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
					 392, 144, 96, 24, hWndDlg, (HMENU)1105, NULL, NULL);

		CreateWindow(WC_BUTTON, "自定义：", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
					 288, 168, 72, 24, hWndDlg, (HMENU)1106, NULL, NULL);
		CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, "", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
					   368, 168, 128, 24, hWndDlg, (HMENU)1107, NULL, NULL);

		CreateWindow(WC_STATIC, "最小长度：", WS_CHILD | WS_VISIBLE,
					 288, 200, 72, 24, hWndDlg, NULL, NULL, NULL);
		HWND hwndMinLen = CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, "8",
										 WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_NUMBER,
										 368, 196, 64, 24, hWndDlg, (HMENU)1108, NULL, NULL);
		HWND hwndMinSpin = CreateWindow(UPDOWN_CLASS, "",
										WS_CHILD | WS_VISIBLE | UDS_ALIGNRIGHT | UDS_SETBUDDYINT | UDS_ARROWKEYS,
										0, 0, 0, 0, hWndDlg, NULL, NULL, NULL);
		SendMessage(hwndMinSpin, UDM_SETBUDDY, (WPARAM)hwndMinLen, 0);
		SendMessage(hwndMinSpin, UDM_SETRANGE, 0, MAKELPARAM(100, 1));

		CreateWindow(WC_STATIC, "最大长度：", WS_CHILD | WS_VISIBLE,
					 288, 228, 72, 24, hWndDlg, NULL, NULL, NULL);
		HWND hwndMaxLen = CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, "16",
										 WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_NUMBER,
										 368, 224, 64, 24, hWndDlg, (HMENU)1109, NULL, NULL);
		HWND hwndMaxSpin = CreateWindow(UPDOWN_CLASS, "",
										WS_CHILD | WS_VISIBLE | UDS_ALIGNRIGHT | UDS_SETBUDDYINT | UDS_ARROWKEYS,
										0, 0, 0, 0, hWndDlg, NULL, NULL, NULL);
		SendMessage(hwndMaxSpin, UDM_SETBUDDY, (WPARAM)hwndMaxLen, 0);
		SendMessage(hwndMaxSpin, UDM_SETRANGE, 0, MAKELPARAM(100, 1));

		CreateWindow(WC_BUTTON, "生成", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
					 288, 256, 96, 32, hWndDlg, (HMENU)1110, NULL, NULL);

		CreateWindow(WC_STATIC, "参数：", WS_CHILD | WS_VISIBLE,
					 288, 292, 56, 24, hWndDlg, NULL, NULL, NULL);
		HWND hwndPlainText = CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, "",
											WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_READONLY |
												ES_MULTILINE | ES_AUTOVSCROLL,
											288, 312, 208, 48, hWndDlg, (HMENU)1111, NULL, NULL);*/
		LPCSTR note = "动态密码计算器-极域工具包\n用于计算9.x~11.x版本学生机房管理助手临时密码，可用于替代普通密码。记住目标版本的密码，在退出助手密码输入框输入临时密码，并双击“确定”或“退出”按钮右侧空白处。\n使用方法详见本项目文档。";
		CreateWindow(WC_STATIC, note, WS_CHILD | WS_VISIBLE,
					 8, 248, 256, 256, hWndDlg, NULL, NULL, NULL);
		EnumChildWindows(hWndDlg, SetWindowFont, LPARAM(hFont));
		UpdateTempPsd(hWndDlg);
		return TRUE;
	}
	case WM_NOTIFY:
		if (((LPNMHDR)lParam)->code == DTN_DATETIMECHANGE)
		{
			UpdateTempPsd(hWndDlg);
			break;
		}
	case WM_NCHITTEST:
	{
		UINT nHitTest = DefWindowProc(hWndDlg, WM_NCHITTEST, wParam, lParam);
		if (nHitTest == HTCLIENT && GetAsyncKeyState(MK_LBUTTON) < 0)
			nHitTest = HTCAPTION;
		SetWindowLong(hWndDlg, DWL_MSGRESULT, nHitTest);
		return nHitTest;
	}
	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case 1002:
			if (HIWORD(wParam) == EN_CHANGE)
				UpdateTempPsd(hWndDlg);
			break;
		case 1100:;
			break;
		case IDOK:
		case IDCANCEL:
			EndDialog(hWndDlg, LOWORD(wParam));
			return TRUE;
		}
		break;
	}
	}
	return FALSE;
}

void ShowPsdWnd()
{
	HGLOBAL hgbl = GlobalAlloc(GMEM_ZEROINIT, 1024);
	if (!hgbl)
		return;
	LPDLGTEMPLATE lpdt = (LPDLGTEMPLATE)GlobalLock(hgbl);
	// Define a dialog box.

	lpdt->style = WS_POPUP | WS_BORDER | WS_SYSMENU | DS_MODALFRAME | WS_CAPTION | DS_CENTER;
	lpdt->cdit = 0; // Number of controls
	lpdt->x = 0;
	lpdt->y = 0;
	lpdt->cx = PsdWnd::w;
	lpdt->cy = PsdWnd::h;
	LPWORD lpw = (LPWORD)(lpdt + 1);
	*lpw++ = 0; // No menu
	*lpw++ = 0; // Predefined dialog box class (by default)
	LPWSTR lpwsz = (LPWSTR)lpw;
	int nchar = 1 + MultiByteToWideChar(CP_ACP, 0, "密码计算", -1, lpwsz, 50);
	lpw += nchar;
	*lpw++ = 0; // No creation data

	GlobalUnlock(hgbl);
	DialogBoxIndirect(NULL, (LPDLGTEMPLATE)hgbl, hwnd, PsdWndProc);
	GlobalFree(hgbl);
}