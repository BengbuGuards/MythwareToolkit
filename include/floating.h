// floating.h — 圆形悬浮窗
#pragma once

#include "globals.h"

HWND CreateFloatingWindow(HINSTANCE hInstance);   // 创建悬浮窗
void DestroyFloatingWindow();                       // 销毁悬浮窗
void ToggleFloatingWindow();                        // 显示/隐藏切换
void ResetFloatingWindowPos();                      // 复位到默认位置
HWND GetFloatingWindow();                           // 当前悬浮窗句柄（可能为 NULL）
void MinimizeFocusWindow();                         // 最小化焦点窗口，跳过本程序悬浮窗
