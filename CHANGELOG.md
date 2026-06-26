# 更新日志

## v2.1.1 — 2026-06-25

### 新功能
- **退出黑屏安静**：主界面 + 悬浮窗右键均可触发。4 级递进（隐藏黑窗 → 取消置顶最小化 → 模拟 ESC → 确认后杀进程），前 3 级无感
- **UAC 提权**：MeltdownDFC/crdisk 和解除网络限制点击时自动弹 UAC 提权窗口
- **极域进程名多样识别**：依次尝试 `StudentMain.exe` / `StudentM.exe` / `StudentMain64.exe` / `Student.exe` / `MasterHelper.exe`
- **防杀进程**：启动即修改进程 ACL，任务管理器"结束任务"直接拒绝访问
- **全局对话框保护**：所有弹窗（关于/帮助/错误提示等）对教师端监控不可见

### 置顶机制重构
- **UIAccess 版移除 ThreadProc**：UIAccess 自带真正置顶（编译宏 `-DUIACCESS_BUILD`）
- **便携版事件驱动**：新增 `WM_WINDOWPOSCHANGED` 处理，只在被挤下去时才重新置顶
- **悬浮窗右键菜单**：不再呼出主界面，消除 Z 序闪烁

### Bug 修复
- **修复 ThreadProc Z 序闪烁**：窗口隐藏时跳过置顶、降低轮询频率
- **修复找不到极域进程**：`UpdateMythwareStatus` + `ControlMythware` 多项进程名匹配 + 详细日志
- **修复悬浮窗/对话框被截屏**：悬浮窗 `WM_CREATE` 加 `SetWindowDisplayAffinity`；启动时挂永久 WH_CBT 钩子，所有主线程弹窗自动防截屏

### 构建 / 脚本
- **`scripts/package.bat`**：编译+签名+打包 ZIP，一步到位
- **`scripts/cleanup.bat`**：一键清理证书、程序、快捷方式、临时文件
- **bin 目录**：`.o`/`.res`/`.exe` → `bin/`，产出 → `bin/pkg/`
- **源码注释**：13 个源文件全部添加模块说明注释

### 文档
- **README 目录**：章节索引快速跳转
- **RELEASE.md**：发行版说明，面向最终用户
- **DEV.md**：开发者文档（编译部署、脚本、故障排查、附录）

---

## v2.1.0 — 2026-06-25

### 关键 Bug 修复

- **修复学生机崩溃（0xC0000005）**：移除对极域注入 DLL（`LibTDProcHook`/`LibTDMaster`）的暴力卸载。`FreeModule` 后系统钩子仍指向已释放内存，悬浮窗收到窗口消息时触发 DEP 崩溃。保留 DLL 加载，通过自带钩子覆盖其行为
- **修复悬浮窗图标问题**：移除 GDI+ 依赖，改用纯 GDI `LoadImage(ICON)` + `DrawIconEx`。修复 `.ico` 文件格式（BMP DIB, wPlanes=1, 多分辨率 16~128px），兼容 `windres` 编译
- **修复 GDI 资源泄漏**：WM_PAINT 中 `SelectObject` 返回值全部保存/恢复，消除 Bitmap/Pen 对象泄漏
- **修复便携版弹"从服务器返回一个参照"**：便携版 manifest 编译时正确嵌入 `uiAccess=false`
- **修复解除网络限制无效**：`RemoveNetworkRestrictions` 中 `CreateFile` 判断改用 `INVALID_HANDLE_VALUE` 而非 `GetLastError`
- **修复 MeltdownDFC/crdisk 无法启动**：`RunEmbeddedExe` 改用 `CreateProcess`（替换废弃的 `WinExec`），修复 `WriteFile` 多写 1 字节溢出

### 新功能 / 增强

- **运行时日志系统**：所有关键操作写入 `%TEMP%\MythwareToolkit_run.log`（追加模式），含时间戳、级别（INFO/WARN/ERROR/CRASH）、函数名。`LOG_INFO/LOG_WARN/LOG_ERROR` 宏全局可用
- **崩溃日志增强**：完整寄存器转储（RIP/RSP/RBP/RAX/RBX/RCX/RDX/RSI/RDI/R8/R9）+ RBP 链栈回溯 + 模块定位 + 访问类型（READ/WRITE/EXECUTE）
- **弹出菜单防截屏**：悬浮窗右键、托盘右键、下拉菜单均通过 `SetWindowDisplayAffinity` 对教师端监控不可见

### 构建 / 工具

- **`convert_icon.ps1` + `convert_icon.bat`**：高质量 PNG→ICO 转换，多分辨率输出（16/24/32/48/64/128px），HighQualityBicubic 缩放，BMP DIB 格式
- **Makefile 清理**：移除便携版未使用的 `-lgdiplus`
- **资源管理**：`FLOATICO` 和 `MAINICON` 独立指向，方便后续替换悬浮窗图标

### 代码质量

- `CreateFloatingWindow` 失败时弹诊断框（仅失败时）
- 悬浮窗 `WM_CREATE` 增加 `IDI_APPLICATION` 兜底
- 图标绘制前通过 `GetIconInfo` 验证有效性
- `TrackPopupMenuProtected` 封装防截屏逻辑，统一调用

---

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
  - `floating.cpp` — 圆形悬浮窗（嵌入图片 ）
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
