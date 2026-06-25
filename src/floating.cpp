#include "floating.h"

#define FLOAT_SIZE  33

static HWND     g_hFloating = NULL;
static HICON    g_hIcon     = NULL;
static HICON    g_hFallback = NULL;
static POINT    g_dragBase;
static RECT     g_dragStartRect;
static bool     g_dragging  = false;
static bool     g_hovered   = false;

static void DrawFloatingContent(HDC hdc) {
    RECT rc = {0, 0, FLOAT_SIZE, FLOAT_SIZE};

    if (g_hIcon) {
        // 画 PNG 转的图标，缩放到悬浮窗大小
        DrawIconEx(hdc, 0, 0, g_hIcon, FLOAT_SIZE, FLOAT_SIZE, 0, NULL, DI_NORMAL);
    } else if (g_hFallback) {
        // 回退到应用图标
        COLORREF bg = g_hovered ? RGB(80, 80, 90) : RGB(60, 60, 70);
        HBRUSH hBg = CreateSolidBrush(bg);
        FillRect(hdc, &rc, hBg);
        DeleteObject(hBg);
        DrawIconEx(hdc, 4, 4, g_hFallback, FLOAT_SIZE - 8, FLOAT_SIZE - 8, 0, NULL, DI_NORMAL);
    }

    // 悬停高亮
    if (g_hovered) {
        HPEN hPen = CreatePen(PS_SOLID, 2, RGB(140, 160, 200));
        SelectObject(hdc, hPen);
        SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Ellipse(hdc, 1, 1, FLOAT_SIZE - 1, FLOAT_SIZE - 1);
        DeleteObject(hPen);
    }
}

LRESULT CALLBACK FloatingWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
            g_hFallback = LoadIcon(cs->hInstance, "MAINICON");
            g_hIcon = (HICON)LoadImage(cs->hInstance, "FLOATICO", IMAGE_ICON,
                                       FLOAT_SIZE, FLOAT_SIZE, LR_DEFAULTCOLOR);
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
            HDC memDC = CreateCompatibleDC(hdc);
            HBITMAP memBmp = CreateCompatibleBitmap(hdc, FLOAT_SIZE, FLOAT_SIZE);
            SelectObject(memDC, memBmp);
            DrawFloatingContent(memDC);
            BitBlt(hdc, 0, 0, FLOAT_SIZE, FLOAT_SIZE, memDC, 0, 0, SRCCOPY);
            DeleteObject(memBmp);
            DeleteDC(memDC);
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
            AppendMenu(hMenu, MF_STRING, 1, (hwnd && IsWindowVisible(hwnd)) ? "Hide Panel" : "Show Panel");
            AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenu(hMenu, MF_STRING, 6, "Toggle Broadcast");
            AppendMenu(hMenu, MF_STRING, 2, "Kill Mythware");
            AppendMenu(hMenu, MF_STRING, 3, "Kill Assistant");
            AppendMenu(hMenu, MF_STRING, 4, "Unlock System");
            AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenu(hMenu, MF_STRING, 5, "Exit");
            int cmd = TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD,
                                     pt.x, pt.y, 0, hWnd, NULL);
            DestroyMenu(hMenu);
            switch (cmd) {
                case 1:
                    if (hwnd && IsWindow(hwnd)) {
                        if (IsWindowVisible(hwnd)) ShowWindow(hwnd, SW_HIDE);
                        else { ShowWindow(hwnd, SW_SHOWNORMAL); SetForegroundWindow(hwnd); }
                    }
                    break;
                case 6:
                    if (hwnd && IsWindow(hwnd)) {
                        if (!IsWindowVisible(hwnd)) ShowWindow(hwnd, SW_SHOWNORMAL);
                        SetForegroundWindow(hwnd);
                        ToggleBroadcastWindow(); UpdateMythwareStatus();
                    }
                    break;
                case 2: if (hwnd) { ControlMythware(FALSE); UpdateMythwareStatus(); } break;
                case 3: KillStudentAssistant(); break;
                case 4: UnlockSystemPrograms(hwnd); break;
                case 5: DestroyWindow(hWnd); break;
            }
            break;
        }
        case WM_DESTROY:
            KillTimer(hWnd, 1);
            if (g_hIcon) { DestroyIcon(g_hIcon); g_hIcon = NULL; }
            PostQuitMessage(0);
            break;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

HWND CreateFloatingWindow(HINSTANCE hInstance) {
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = FloatingWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_HAND);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.lpszClassName = "FloatingWnd";
    if (!RegisterClassEx(&wc)) return NULL;
    g_hFloating = CreateWindowEx(WS_EX_TOOLWINDOW | WS_EX_TOPMOST, "FloatingWnd", "",
                                  WS_POPUP, 0, 0, FLOAT_SIZE, FLOAT_SIZE,
                                  NULL, NULL, hInstance, NULL);
    if (g_hFloating) ShowWindow(g_hFloating, SW_SHOW);
    return g_hFloating;
}

void DestroyFloatingWindow() {
    if (g_hFloating && IsWindow(g_hFloating)) {
        DestroyWindow(g_hFloating);
        g_hFloating = NULL;
    }
}
