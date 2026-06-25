#include "floating.h"

#define FLOAT_SIZE  33

static HWND     g_hFloating = NULL;
static HICON    g_hIcon     = NULL;
static POINT    g_dragBase;
static RECT     g_dragStartRect;
static bool     g_dragging  = false;
static bool     g_hovered   = false;
static UINT_PTR g_menuTimerId = 0;

// 定时器回调：查找并保护所有弹出菜单窗口
static VOID CALLBACK MenuProtectTimer(HWND, UINT, UINT_PTR, DWORD) {
    HWND hMenu = FindWindow("#32768", NULL);
    while (hMenu) {
        SetWindowDisplayAffinity(hMenu, WDA_EXCLUDEFROMCAPTURE);
        hMenu = FindWindowEx(NULL, hMenu, "#32768", NULL);
    }
}

// 受保护的 TrackPopupMenu：弹出菜单对教师端屏幕监控不可见
BOOL TrackPopupMenuProtected(HMENU hMenu, UINT uFlags, int x, int y, HWND hWnd) {
    g_menuTimerId = SetTimer(NULL, 0, 10, MenuProtectTimer);
    LOG_INFO("TrackPopupMenu with anti-capture timer (id=%lu)", g_menuTimerId);
    BOOL ret = TrackPopupMenu(hMenu, uFlags, x, y, 0, hWnd, NULL);
    if (g_menuTimerId) { KillTimer(NULL, g_menuTimerId); g_menuTimerId = 0; }
    LOG_INFO("TrackPopupMenu returned %d", ret);
    return ret;
}

// 验证图标句柄是否有效（避免畸形 .ico 文件导致 DrawIconEx 崩溃）
static bool IsValidIcon(HICON hIcon) {
    if (!hIcon) return false;
    ICONINFO ii = {};
    if (!GetIconInfo(hIcon, &ii)) return false;
    // 宽松验证：只要有位图数据就认为有效，不要求必须有 hbmColor
    bool ok = (ii.fIcon != 0);
    if (ii.hbmColor) DeleteObject(ii.hbmColor);
    if (ii.hbmMask)  DeleteObject(ii.hbmMask);
    return ok;
}

static void DrawFloatingContent(HDC hdc) {
    // 绘制图标（g_hIcon 由 WM_CREATE 保证为有效图标）
    if (g_hIcon) {
        DrawIconEx(hdc, 0, 0, g_hIcon, FLOAT_SIZE, FLOAT_SIZE, 0, NULL, DI_NORMAL);
    } else {
        HBRUSH hBg = CreateSolidBrush(RGB(60, 60, 70));
        HBRUSH hOld = (HBRUSH)SelectObject(hdc, hBg);
        Ellipse(hdc, 0, 0, FLOAT_SIZE + 1, FLOAT_SIZE + 1);
        SelectObject(hdc, hOld);
        DeleteObject(hBg);
    }

    // 悬停发光效果（多层同心圆渐亮模拟边缘光晕）
    if (g_hovered) {
        HPEN hPen, hOldPen;
        HBRUSH hOldBr = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
        // 外层：细，较暗
        hPen = CreatePen(PS_SOLID, 1, RGB(60, 120, 200));
        hOldPen = (HPEN)SelectObject(hdc, hPen);
        Ellipse(hdc, 0, 0, FLOAT_SIZE, FLOAT_SIZE);
        SelectObject(hdc, hOldPen); DeleteObject(hPen);
        // 中层：中等
        hPen = CreatePen(PS_SOLID, 2, RGB(100, 160, 230));
        hOldPen = (HPEN)SelectObject(hdc, hPen);
        Ellipse(hdc, 1, 1, FLOAT_SIZE - 1, FLOAT_SIZE - 1);
        SelectObject(hdc, hOldPen); DeleteObject(hPen);
        // 内层：亮
        hPen = CreatePen(PS_SOLID, 2, RGB(160, 200, 255));
        hOldPen = (HPEN)SelectObject(hdc, hPen);
        Ellipse(hdc, 2, 2, FLOAT_SIZE - 2, FLOAT_SIZE - 2);
        SelectObject(hdc, hOldPen); DeleteObject(hPen);
        SelectObject(hdc, hOldBr);
    }
}

LRESULT CALLBACK FloatingWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
            LOG_INFO("Floating window WM_CREATE");
            // 加载悬浮窗专用图标（float.ico），失败则用系统默认
            g_hIcon = (HICON)LoadImage(cs->hInstance, "FLOATICO", IMAGE_ICON,
                                       0, 0, LR_DEFAULTSIZE);
            if (!g_hIcon) {
                g_hIcon = LoadIcon(NULL, IDI_APPLICATION);
                LOG_WARN("FLOATICO load failed, using IDI_APPLICATION");
            } else {
                LOG_INFO("FLOATICO loaded OK (hwnd=%p)", hWnd);
            }

            HRGN hRgn = CreateEllipticRgn(0, 0, FLOAT_SIZE + 1, FLOAT_SIZE + 1);
            SetWindowRgn(hWnd, hRgn, TRUE);
            SetTimer(hWnd, 1, 400, NULL);
            int sw = GetSystemMetrics(SM_CXSCREEN);
            int sh = GetSystemMetrics(SM_CYSCREEN);
            SetWindowPos(hWnd, HWND_TOPMOST, sw - FLOAT_SIZE - 14,
                         (sh - FLOAT_SIZE) / 2, FLOAT_SIZE, FLOAT_SIZE, SWP_NOACTIVATE);
            break;
        }
        case WM_TIMER:
            SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            break;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            if (hdc) {
                HDC memDC = CreateCompatibleDC(hdc);
                if (memDC) {
                    HBITMAP memBmp = CreateCompatibleBitmap(hdc, FLOAT_SIZE, FLOAT_SIZE);
                    if (memBmp) {
                        HBITMAP hOldBmp = (HBITMAP)SelectObject(memDC, memBmp);
                        DrawFloatingContent(memDC);
                        BitBlt(hdc, 0, 0, FLOAT_SIZE, FLOAT_SIZE, memDC, 0, 0, SRCCOPY);
                        SelectObject(memDC, hOldBmp);
                        DeleteObject(memBmp);
                    }
                    DeleteDC(memDC);
                }
            }
            EndPaint(hWnd, &ps);
            break;
        }
        case WM_MOUSEMOVE: {
            if (GetCapture() == hWnd) {
                POINT ptNow; GetCursorPos(&ptNow);
                int dx = ptNow.x - g_dragBase.x;
                int dy = ptNow.y - g_dragBase.y;
                if (abs(dx) > 3 || abs(dy) > 3) g_dragging = true;
                if (g_dragging) {
                    SetWindowPos(hWnd, HWND_TOPMOST,
                                 g_dragStartRect.left + dx, g_dragStartRect.top + dy,
                                 0, 0, SWP_NOSIZE | SWP_NOACTIVATE);
                }
            }
            if (!g_hovered) {
                g_hovered = true;
                InvalidateRect(hWnd, NULL, FALSE);
                TRACKMOUSEEVENT tme = {sizeof(TRACKMOUSEEVENT)};
                tme.dwFlags = TME_LEAVE; tme.hwndTrack = hWnd;
                TrackMouseEvent(&tme);
            }
            break;
        }
        case WM_MOUSELEAVE:
            g_hovered = false;
            InvalidateRect(hWnd, NULL, FALSE);
            break;
        case WM_LBUTTONDOWN:
            g_dragging = false;
            GetCursorPos(&g_dragBase);
            GetWindowRect(hWnd, &g_dragStartRect);
            SetCapture(hWnd);
            break;
        case WM_LBUTTONUP:
            ReleaseCapture();
            if (!g_dragging) {
                if (hwnd && IsWindow(hwnd)) {
                    if (IsWindowVisible(hwnd))
                        ShowWindow(hwnd, SW_HIDE);
                    else { ShowWindow(hwnd, SW_SHOWNORMAL); SetForegroundWindow(hwnd); }
                }
            }
            break;
        case WM_MBUTTONDOWN: {
            if (hwnd && IsWindow(hwnd)) {
                ToggleBroadcastWindow();
                UpdateMythwareStatus();
            }
            break;
        }
        case WM_RBUTTONDOWN: {
            POINT pt; GetCursorPos(&pt);
            HMENU hMenu = CreatePopupMenu();
            AppendMenu(hMenu, MF_STRING, 1, (hwnd && IsWindowVisible(hwnd)) ? "隐藏面板" : "打开面板");
            AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenu(hMenu, MF_STRING, 7, "退出黑屏");
            AppendMenu(hMenu, MF_STRING, 6, "广播窗口化");
            AppendMenu(hMenu, MF_STRING, 2, "杀掉极域");
            AppendMenu(hMenu, MF_STRING, 3, "杀机房助手");
            AppendMenu(hMenu, MF_STRING, 4, "解禁系统程序");
            AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenu(hMenu, MF_STRING, 5, "退出");
            // 受保护的弹出菜单（对教师端监控不可见）
            int cmd = TrackPopupMenuProtected(hMenu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD,
                                              pt.x, pt.y, hWnd);
            DestroyMenu(hMenu);
            switch (cmd) {
                case 1:
                    if (hwnd && IsWindow(hwnd)) {
                        if (IsWindowVisible(hwnd)) ShowWindow(hwnd, SW_HIDE);
                        else { ShowWindow(hwnd, SW_SHOWNORMAL); SetForegroundWindow(hwnd); }
                    }
                    break;
                case 7: ExitBlackScreen(); break;
                case 6: ToggleBroadcastWindow(); UpdateMythwareStatus(); break;
                case 2: if (hwnd) { ControlMythware(FALSE); UpdateMythwareStatus(); } break;
                case 3: KillStudentAssistant(); break;
                case 4: UnlockSystemPrograms(hwnd); break;
                case 5: DestroyWindow(hWnd); break;
            }
            break;
        }
        case WM_DESTROY:
            LOG_INFO("Floating window WM_DESTROY");
            KillTimer(hWnd, 1);
            if (g_hIcon) { DestroyIcon(g_hIcon); g_hIcon = NULL; }
            PostQuitMessage(0);
            break;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

HWND CreateFloatingWindow(HINSTANCE hInstance) {
    LOG_INFO("CreateFloatingWindow starting");
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = FloatingWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_HAND);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.lpszClassName = "FloatingWnd";
    if (!RegisterClassEx(&wc)) {
        LOG_ERROR("RegisterClassEx failed: err=%lu", GetLastError());
        char msg[128];
        sprintf(msg, "悬浮窗 RegisterClassEx 失败\nGetLastError=%lu", GetLastError());
        MessageBox(NULL, msg, "悬浮窗错误", MB_OK | MB_ICONERROR);
        return NULL;
    }
    g_hFloating = CreateWindowEx(WS_EX_TOOLWINDOW | WS_EX_TOPMOST, "FloatingWnd", "",
                                  WS_POPUP, 0, 0, FLOAT_SIZE, FLOAT_SIZE,
                                  NULL, NULL, hInstance, NULL);
    if (!g_hFloating) {
        LOG_ERROR("CreateWindowEx failed: err=%lu", GetLastError());
        char msg[128];
        sprintf(msg, "悬浮窗 CreateWindowEx 失败\nGetLastError=%lu", GetLastError());
        MessageBox(NULL, msg, "悬浮窗错误", MB_OK | MB_ICONERROR);
        return NULL;
    }
    ShowWindow(g_hFloating, SW_SHOW);
    LOG_INFO("CreateFloatingWindow OK (hwnd=%p)", g_hFloating);
    return g_hFloating;
}

void DestroyFloatingWindow() {
    if (g_hFloating && IsWindow(g_hFloating)) {
        DestroyWindow(g_hFloating);
        g_hFloating = NULL;
    }
}
