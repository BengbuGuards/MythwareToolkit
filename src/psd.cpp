// psd.cpp — 动态密码计算器对话框
#include "globals.h"
#include "psd.h"

void UpdateTempPsd(HWND hwndDlg) {
    if (!IsWindow(hwndDlg)) return;
    CHAR szComputerName[32] = {};
    GetDlgItemText(hwndDlg, 1002, szComputerName, 32);
    if (strlen(szComputerName) == 0) strcpy(szComputerName, "X");
    SYSTEMTIME date = {};
    SendDlgItemMessage(hwndDlg, 1001, DTM_GETSYSTEMTIME, 0, LPARAM(&date));
    char szPsd[16] = {};
    int iPsd = 16 * (date.wYear * 91 + date.wMonth * 13 + date.wDay * 57);
    itoa(iPsd, szPsd + 1, 10); szPsd[0] = '8';
    SetDlgItemText(hwndDlg, 1003, szPsd);
    itoa(iPsd + 11, szPsd + 1, 10);
    SetDlgItemText(hwndDlg, 1004, szPsd);
    iPsd = date.wYear * 789 + date.wMonth * 123 + date.wDay * 456 + 111;
    itoa(iPsd, szPsd, 10);
    SetDlgItemText(hwndDlg, 1005, szPsd);
    char lastChar = szComputerName[strlen(szComputerName) - 1];
    iPsd = date.wMonth * 159 + date.wDay * 357 + lastChar * 258;
    itoa(iPsd, szPsd, 7);
    SetDlgItemText(hwndDlg, 1006, szPsd);
}

namespace PsdWnd { int w = 136, h = 192; };

INT_PTR CALLBACK PsdWndProc(HWND hWndDlg, UINT Message, WPARAM wParam, LPARAM lParam) {
    switch (Message) {
        case WM_INITDIALOG: {
            CreateWindow(WC_STATIC, "日期:", WS_CHILD | WS_VISIBLE, 16, 16, 80, 24, hWndDlg, NULL, NULL, NULL);
            CreateWindow(DATETIMEPICK_CLASS, "", WS_CHILD | WS_VISIBLE | WS_TABSTOP | DTS_LONGDATEFORMAT,
                         104, 16, 152, 24, hWndDlg, (HMENU)1001, NULL, NULL);
            CreateWindow(WC_STATIC, "计算机名:", WS_CHILD | WS_VISIBLE, 16, 48, 80, 24, hWndDlg, NULL, NULL, NULL);
            DWORD dwSize = MAX_COMPUTERNAME_LENGTH + 1;
            char szName[dwSize] = {};
            GetComputerName(szName, &dwSize);
            HWND hwndEdit = CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, szName,
                                           WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                           104, 48, 152, 24, hWndDlg, (HMENU)1002, NULL, NULL);
            SendMessage(hwndEdit, EM_SETLIMITTEXT, MAX_COMPUTERNAME_LENGTH, 0);
            CreateWindow(WC_BUTTON, "计算结果", WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 8, 80, 256, 156, hWndDlg, NULL, NULL, NULL);
            CreateWindow(WC_STATIC, "10.1-", WS_CHILD | WS_VISIBLE, 24, 108, 72, 24, hWndDlg, NULL, NULL, NULL);
            CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, "", WS_CHILD | WS_VISIBLE | ES_READONLY | WS_TABSTOP, 104, 104, 152, 24, hWndDlg, (HMENU)1003, NULL, NULL);
            CreateWindow(WC_STATIC, "10.x", WS_CHILD | WS_VISIBLE, 24, 140, 72, 24, hWndDlg, NULL, NULL, NULL);
            CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, "", WS_CHILD | WS_VISIBLE | ES_READONLY | WS_TABSTOP, 104, 136, 152, 24, hWndDlg, (HMENU)1004, NULL, NULL);
            CreateWindow(WC_STATIC, "11.0x", WS_CHILD | WS_VISIBLE, 24, 172, 72, 24, hWndDlg, NULL, NULL, NULL);
            CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, "", WS_CHILD | WS_VISIBLE | ES_READONLY | WS_TABSTOP, 104, 168, 152, 24, hWndDlg, (HMENU)1005, NULL, NULL);
            CreateWindow(WC_STATIC, "11.06~12.0", WS_CHILD | WS_VISIBLE, 24, 204, 72, 24, hWndDlg, NULL, NULL, NULL);
            CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, "", WS_CHILD | WS_VISIBLE | ES_READONLY | WS_TABSTOP, 104, 200, 152, 24, hWndDlg, (HMENU)1006, NULL, NULL);
            LPCSTR note = "动态密码计算器-极域工具包\n用于计算9.x~11.x版本学生机房管理助手临时密码，可用于替代普通密码。记住目标版本的密码，在退出助手密码输入框输入临时密码，并双击「确定」或「退出」按钮右侧空白处。\n使用方法详见本项目文档。";
            CreateWindow(WC_STATIC, note, WS_CHILD | WS_VISIBLE, 8, 248, 256, 256, hWndDlg, NULL, NULL, NULL);
            EnumChildWindows(hWndDlg, SetWindowFont, LPARAM(hFont));
            UpdateTempPsd(hWndDlg);
            return TRUE;
        }
        case WM_NOTIFY:
            if (((LPNMHDR)lParam)->code == DTN_DATETIMECHANGE) { UpdateTempPsd(hWndDlg); break; }
        case WM_NCHITTEST: {
            UINT nHitTest = DefWindowProc(hWndDlg, WM_NCHITTEST, wParam, lParam);
            if (nHitTest == HTCLIENT && GetAsyncKeyState(MK_LBUTTON) < 0) nHitTest = HTCAPTION;
            SetWindowLong(hWndDlg, DWLP_MSGRESULT, nHitTest);
            return nHitTest;
        }
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case 1002: if (HIWORD(wParam) == EN_CHANGE) UpdateTempPsd(hWndDlg); break;
                case IDOK: case IDCANCEL: EndDialog(hWndDlg, LOWORD(wParam)); return TRUE;
            }
            break;
        }
    }
    return FALSE;
}

void ShowPsdWnd() {
    HGLOBAL hgbl = GlobalAlloc(GMEM_ZEROINIT, 1024);
    if (!hgbl) return;
    LPDLGTEMPLATE lpdt = (LPDLGTEMPLATE)GlobalLock(hgbl);
    lpdt->style = WS_POPUP | WS_BORDER | WS_SYSMENU | DS_MODALFRAME | WS_CAPTION | DS_CENTER;
    lpdt->cdit = 0;
    lpdt->x = 0; lpdt->y = 0;
    lpdt->cx = PsdWnd::w; lpdt->cy = PsdWnd::h;
    LPWORD lpw = (LPWORD)(lpdt + 1);
    *lpw++ = 0; *lpw++ = 0;
    LPWSTR lpwsz = (LPWSTR)lpw;
    int nchar = 1 + MultiByteToWideChar(CP_ACP, 0, "密码计算器", -1, lpwsz, 50);
    lpw += nchar;
    *lpw++ = 0;
    GlobalUnlock(hgbl);
    DialogBoxIndirect(NULL, (LPDLGTEMPLATE)hgbl, hwnd, PsdWndProc);
    GlobalFree(hgbl);
}
