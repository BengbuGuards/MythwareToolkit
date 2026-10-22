// ui.cpp — 主窗口控件创建
#include "ui.h"

void CreateAllControls(HWND hwnd, HINSTANCE hi) {
    int L = 14, R = 342, LW = 320, RW = 290, y;

    // ── 顶部 ──
    TxLnk = CreateWindow("SysLink",
        UA("极域工具包 <a href=\"https://github.com/BengbuGuards/MythwareToolkit\">GitHub</a>"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP, L + 2, 6, 220, 22, hwnd, HMENU(1001), hi, NULL);
    BtAbt = CreateWindow(WC_BUTTON, UA("关于/帮助"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        R + RW - 100, 2, 100, 28, hwnd, HMENU(1002), hi, NULL);

    char str[BUFSIZ] = {}; std::string psd;
    if (!GetMythwarePasswordFromRegedit(str)) psd = AS("获取密码失败"); else psd = str;
    CreateWindow(WC_STATIC, UA("极域密码:"), WS_CHILD | WS_VISIBLE, L + 218, 8, 72, 20, hwnd, NULL, hi, NULL);
    CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, psd.c_str(), WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_READONLY,
        L + 292, 6, 200, 22, hwnd, HMENU(1003), hi, NULL);

    // ── 左侧：极域控制 ──
    y = 50;
    CreateWindow(WC_BUTTON, UA("极域控制"), WS_CHILD | WS_VISIBLE | BS_GROUPBOX, L, y, LW, 150, hwnd, NULL, hi, NULL);
    CreateWindow(WC_BUTTON, UA("杀掉学生机房管理助手"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        L + 10, y + 18, LW - 20, 30, hwnd, HMENU(1006), hi, NULL);
    BtKmw = CreateWindow(WC_BUTTON, UA("杀掉极域"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_SPLITBUTTON,
        L + 10, y + 52, LW - 20, 40, hwnd, HMENU(1004), hi, NULL);
    CreateWindow(WC_BUTTON, UA("广播窗口化"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | WS_DISABLED,
        L + 10, y + 100, 140, 30, hwnd, HMENU(1014), hi, NULL);
    CreateWindow(WC_BUTTON, UA("动态密码计算器"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        L + 156, y + 100, 140, 30, hwnd, HMENU(1015), hi, NULL);

    // ── 右侧：高级工具 ──
    y = 52; int gap = RW - 16 - 134*2;
    CreateWindow(WC_BUTTON, UA("高级工具"), WS_CHILD | WS_VISIBLE | BS_GROUPBOX, R, y, RW, 150, hwnd, NULL, hi, NULL);
    CreateWindow(WC_BUTTON, UA("一键解禁系统程序"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        R + 10, y + 18, 134, 30, hwnd, HMENU(1007), hi, NULL);
    CreateWindow(WC_BUTTON, UA("重启资源管理器"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        R + 10 + 134 + gap, y + 18, 134, 30, hwnd, HMENU(1010), hi, NULL);
    CreateWindow(WC_BUTTON, UA("解除极域网络限制"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        R + 10, y + 54, 134, 30, hwnd, HMENU(1008), hi, NULL);
    CreateWindow(WC_BUTTON, UA("解除极域U盘限制"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        R + 10 + 134 + gap, y + 54, 134, 30, hwnd, HMENU(1009), hi, NULL);
    CreateWindow(WC_BUTTON, "MeltdownDFC", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        R + 10, y + 90, 134, 26, hwnd, HMENU(1019), hi, NULL);
    CreateWindow(WC_BUTTON, "crdisk", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        R + 10 + 134 + gap, y + 90, 134, 26, hwnd, HMENU(1020), hi, NULL);
    CreateWindow(WC_BUTTON, UA("退出黑屏"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        R + 10, y + 120, 134, 26, hwnd, HMENU(1021), hi, NULL);
    CreateWindow(WC_BUTTON, UA("显隐悬浮窗"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        R + 10 + 134 + gap, y + 120, 134, 26, hwnd, HMENU(1022), hi, NULL);

    // ── 底部：功能开关 ──
    y = 216; int totalW = LW + RW + 8;
    CreateWindow(WC_BUTTON, UA("功能开关"), WS_CHILD | WS_VISIBLE | BS_GROUPBOX, L, y, totalW, 52, hwnd, NULL, hi, NULL);
    BtTop = CreateWindow(WC_BUTTON, UA("置顶此窗口"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        L + 14, y + 16, 94, 22, hwnd, HMENU(1016), hi, NULL);
    SendMessage(BtTop, BM_SETCHECK, BST_CHECKED, 0);
    BtCur = CreateWindow(WC_BUTTON, UA("解鼠标锁(&M)"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        L + 120, y + 16, 92, 22, hwnd, HMENU(1017), hi, NULL);
    BtKbh = CreateWindow(WC_BUTTON, UA("解键盘锁(&C)"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        L + 224, y + 16, 92, 22, hwnd, HMENU(1018), hi, NULL);
    BtSnp = CreateWindow(WC_BUTTON, UA("防止截屏"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        R + 10, y + 16, 80, 22, hwnd, HMENU(1011), hi, NULL);
    SendMessage(BtSnp, BM_SETCHECK, BST_CHECKED, 0); SendMessage(hwnd, WM_COMMAND, 1011, 0);
    BtWnd = CreateWindow(WC_BUTTON, UA("启用鼠标检测弹窗"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        R + 100, y + 16, 170, 22, hwnd, HMENU(1012), hi, NULL);

    // ── 状态栏 ──
    TxOut = CreateWindow(STATUSCLASSNAME, UA("等待操作"), WS_CHILD | WS_VISIBLE,
        0, 0, 0, 0, hwnd, HMENU(1005), hi, NULL);
    int pts[2] = {420, -1}; SendMessage(TxOut, SB_SETPARTS, WPARAM(2), LPARAM(pts));
}
