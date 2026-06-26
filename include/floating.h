// floating.h — 圆形悬浮窗
#pragma once

#include "globals.h"

HWND CreateFloatingWindow(HINSTANCE hInstance);   // 创建悬浮窗
void DestroyFloatingWindow();                       // 销毁悬浮窗
