#include "floating.h"
#include <gdiplus.h>

#define FLOAT_SIZE  33

static HWND             g_hFloating     = NULL;
static Gdiplus::Bitmap* g_pBitmap       = NULL;
static HICON            g_hFallback     = NULL;
static POINT            g_dragBase;
static RECT             g_dragStartRect;
static bool             g_dragging      = false;
static bool             g_hovered       = false;
static ULONG_PTR        g_gdiToken      = 0;
static bool             g_gdiOk         = false;

// ── GDI+ 初始化（延迟调用，仅一次）──────────────────────────
static void InitGDIPlus() {
    if (g_gdiToken) return;
    Gdiplus::GdiplusStartupInput si;
    g_gdiOk = (Gdiplus::GdiplusStartup(&g_gdiToken, &si, NULL) == Gdiplus::Ok);
}

// ── 从资源加载 JPG（GDI+）───────────────────────────────────
static void LoadFloatingImage(HINSTANCE hInst) {
    if (g_pBitmap) return;
    InitGDIPlus();
    if (!g_gdiOk) return;

    HRSRC   hRes = FindResource(hInst, MAKEINTRESOURCE(4), RT_RCDATA);
    if (!hRes) return;
    HGLOBAL hData = LoadResource(hInst, hRes);
    DWORD   dwSize = SizeofResource(hInst, hRes);
    LPVOID  pData = LockResource(hData);
    if (!pData) return;

    HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, dwSize);
    if (!hGlobal) return;
    void* pMem = GlobalLock(hGlobal);
    memcpy(pMem, pData, dwSize);
    GlobalUnlock(hGlobal);

    IStream* pStream = NULL;
    CreateStreamOnHGlobal(hGlobal, TRUE, &pStream);
    g_pBitmap = Gdiplus::Bitmap::FromStream(pStream);
    pStream->Release();
}

// ── 绘制悬浮窗内容 ──────────────────────────────────────────
static void DrawFloatingContent(HDC hdc) {
    RECT rc = {0, 0, FLOAT_SIZE, FLOAT_SIZE};

    if (g_gdiOk && g_pBitmap) {
        Gdiplus::Graphics gfx(hdc);
        gfx.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
        gfx.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
        Gdiplus::GraphicsPath path;
        path.AddEllipse(0, 0, FLOAT_SIZE - 1, FLOAT_SIZE - 1);
        gfx.SetClip(&path);
        gfx.DrawImage(g_pBitmap, 0, 0, FLOAT_SIZE, FLOAT_SIZE);
        if (g_hovered) {
            Gdiplus::SolidBrush hl(Gdiplus::Color(30, 255, 255, 255));
            gfx.FillEllipse(&hl, 0, 0, FLOAT_SIZE - 1, FLOAT_SIZE - 1);
        }
    } else {
        // 回退：画应用图标
        COLORREF bg = g_hovered ? RGB(80, 80, 90) : RGB(60, 60, 70);
        HBRUSH hBg = CreateSolidBrush(bg);
        FillRect(hdc, &rc, hBg);
        DeleteObject(hBg);
        if (g_hFallback)
            DrawIconEx(hdc, 4, 4, g_hFallback, FLOAT_SIZE - 8, FLOAT_SIZE - 8, 0, NULL, DI_NORMAL);
    }
}

LRESULT CALLBACK FloatingWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
            g_hFallback = LoadIcon(cs->hInstance, "MAINICON");
            InitGDIPlus();
            if (g_gdiOk) LoadFloatingImage(cs->hInstance);
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
            AppendMenu(hMenu, MF_STRING, 1, (hwnd && IsWindowVisible(hwnd)) ? "隐藏面板" : "打开面板");
            AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenu(hMenu, MF_STRING, 6, "广播窗口化");
            AppendMenu(hMenu, MF_STRING, 2, "杀掉极域");
            AppendMenu(hMenu, MF_STRING, 3, "杀机房助手");
            AppendMenu(hMenu, MF_STRING, 4, "解禁系统程序");
            AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenu(hMenu, MF_STRING, 5, "退出");
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
            delete g_pBitmap; g_pBitmap = NULL;
            if (g_gdiToken) { Gdiplus::GdiplusShutdown(g_gdiToken); g_gdiToken = 0; }
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
