# 更新日志

## v2.0.0 — 2026-06-24

### 代码重构（开发质量）

- **模块化拆分**：`main.cpp` 从 1623 行精简至约 500 行，拆分为 9 个独立模块
  - `main.cpp` — WinMain 入口 + WndProc 消息循环 + 托盘图标
  - `utils.cpp` — 日志格式化、错误处理、随机标题、权限提升、异常处理、日志文件写入
  - `process.cpp` — 进程查杀、挂起/恢复、状态检测、ntdll 动态加载
  - `bypass.cpp` — 注册表解禁、网络限制解除、USB 限制解除、hosts 清理
  - `assistant.cpp` — 学生机房管理助手全版本（v7.2 ~ v12.98）检测与杀进程
  - `mythware.cpp` — 极域密码读取、广播窗口检测、极域进程控制
  - `hooks.cpp` — 键盘钩子、鼠标钩子、窗口置顶线程
  - `floating.cpp` — 圆形悬浮窗（嵌入图片 + GDI+ 抗锯齿渲染）
  - `psd.cpp` — 动态密码计算器对话框
- **公共头文件**：新增 `globals.h`，集中管理宏定义、全局变量声明、函数原型
- **编码统一**：所有源文件从 GBK 转为 UTF-8，IDE 中不再出现乱码
- **编译标志**：新增 `-fexec-charset=UTF-8`，配合 manifest `activeCodePage` 解决 ANSI 模式下中文显示

### 新功能 — 圆形悬浮窗

- 圆形悬浮窗，GDI+ 抗锯齿渲染，嵌入自定义图片（从资源段加载，exe 单文件自带）
- 始终置顶（`HWND_TOPMOST`），刷新频率优化为 250ms（减少与屏幕广播窗口的 Z 序冲突）
- **左键** → 切换主面板显示/隐藏
- **中键** → 屏幕广播窗口化/全屏化（一键操作）
- **右键** → 快捷菜单（打开面板/广播窗口化/杀掉极域/杀机房助手/解禁系统/退出）
- 支持拖拽移动（屏幕绝对坐标追踪，快速拖动不丢失）
- 悬停时微弱高亮反馈
- 主窗口关闭时悬浮窗常驻，点击可重新唤起；悬浮窗关闭时程序彻底退出

### UI 重设计

- 窗口尺寸：528×250 → **640×380**，空间充裕不再拥挤
- 左右分栏布局，各带 GroupBox（"极域控制" / "高级工具"）
- 按钮宽度自动适配列宽，文字不截断
- 底部功能开关独立 GroupBox（52px 高），间距均匀，彻底解决重叠问题
- "关于/帮助"移至右上角
- 密码字段添加"极域密码:"标签
- 版本号更新为 2.0.0

### 内存泄漏修复

- `RandomWindowTitle()`：`new char[11]` 永不释放 → `static char[11]` 缓冲区复用
- `FormatLogTime()`：`VirtualAlloc(64)` 永不释放 → `static char[64]` 缓冲区复用

### 默认行为优化

- 解鼠标锁、解键盘锁默认勾选并启用（开箱即用）
- 状态栏显示极域版本号（从注册表读取）
- 悬浮窗尺寸 33px，圆形纯图片无边框

### 日志自动落盘

- 每次启动自动写入 `%TEMP%\MythwareToolkit.log`
- 所有 Print/Println 输出同时写入内存和文件
- 程序退出时自动 Flush + Close，方便排查偶发 Bug

### 编译修复

- 补回 `#define SYSTEM_PROCESS_INFORMATION` 宏（`process.cpp`）
- `DWL_MSGRESULT` → `DWLP_MSGRESULT`（新版 MinGW 兼容）
- 中文智能引号 `""` → `「」`（UTF-8 编译兼容）
- `sys.manifest` 添加 `xmlns:asmv3` 命名空间声明
- 新增 `-lgdiplus -lole32` 链接（悬浮窗 GDI+ 图片加载）

### 构建系统

- **CMakeLists.txt**：支持 `cmake -B build -G "MinGW Makefiles" && cmake --build build`
- **build.bat**：自动检测 `D:\Dev\mingw64` / `C:\mingw64` / `C:\msys64\mingw64` / PATH，换电脑不需修改
- **Makefile**：9 个 `.o` 编译目标 + 完整头文件依赖

### 部署与签名

- **UIAccess 版**：需签名，部署到 `C:\Program Files\`，享受完整超级置顶
- **便携版**：`MythwareToolkit_Portable.exe`，不需签名、不挑路径、U盘即用
- `deploy.bat`：一键部署脚本（管理员运行，自动安装证书并复制文件）
- `sign.ps1`：PowerShell 自签名脚本
- `sys_portable.manifest`：便携版清单（`uiAccess=false`）

### 代码健壮性

- 卸载机房助手钩子 DLL（`LibTDProcHook` + `LibTDMaster`，32/64 位）
- `WM_ACTIVATE` / `NM_CLICK` 缓冲区 `c[10]` → `c[64]`，增加空指针检查

---

## 原作者版本

原仓库：[BengbuGuards/MythwareToolkit](https://github.com/BengbuGuards/MythwareToolkit)

- v0.5 ~ v1.2.5：原始版本，参见原仓库 Release 页面
