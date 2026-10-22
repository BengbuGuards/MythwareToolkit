# 开发者文档

> 面向开发者的编译、部署、项目结构说明。
> 用户使用说明见 [README](README.md)。

---

## 项目结构

```
MythwareToolkit/
├── src/             ← 源码（10 个 .cpp）
├── include/         ← 头文件（5 个 .h）
├── res/             ← 资源（图标/manifest/嵌入式exe）
├── scripts/         ← 编译、签名、打包、清理、完整性检查
├── cert/            ← 证书 + 部署 + 故障排查
├── bin/             ← 编译产物 + 打包输出
│   └── pkg/         ← 发行版文件（EXE + ZIP）
├── Makefile
├── README.md        ← 项目说明
├── CHANGELOG.md     ← 更新日志
└── DEV.md           ← 开发者文档
```
```
src/
├── main.cpp       ← WinMain 入口 + 消息循环 + 托盘图标 + 内嵌工具启动
├── ui.cpp         ← 主窗口控件布局
├── utils.cpp      ← 日志 / 异常处理 / CBT 钩子 / 随机标题 + UA/AS 编码适配
├── process.cpp    ← 进程查杀、挂起/恢复、状态检测、防杀 ACL
├── bypass.cpp     ← 注册表解禁、网络/USB 限制解除、hosts 清理
├── assistant.cpp  ← 学生机房管理助手检测与杀进程
├── mythware.cpp   ← 极域进程控制、广播窗口化、退出黑屏、密码读取
├── hooks.cpp      ← 键盘/鼠标钩子线程、置顶轮询线程
├── psd.cpp        ← 动态密码计算器对话框
└── floating.cpp   ← 圆形悬浮窗

include/
├── globals.h      ← 公共宏、全局变量、函数原型
├── version.h      ← 版本号单一来源
├── floating.h     ← 悬浮窗声明
├── psd.h          ← 密码计算器声明
└── ui.h           ← 控件创建声明
```


---

## 编译与部署

### UIAccess 完整版

```batch
scripts\build.bat            →  交互选择 x64 / x86，编译 + 自动签名
scripts\build.bat x64        →  直接编译 64 位
scripts\build.bat x86        →  直接编译 32 位
scripts\package.bat          →  一次产出 x64 + x86 两个 ZIP
cert\deploy.bat              →  部署到 C:\Program Files\
```

| 脚本 | 做什么 | 输出 |
|------|--------|------|
| `scripts\build.bat [x64\|x86]` | 编译 + 自动签名；无参数时交互选择架构 | `bin\MythwareToolkit.v<版本号>.<arch>.exe` |
| `scripts\build_portable.bat [x64\|x86]` | 编译便携版；无参数时交互选择架构 | `bin\MythwareToolkit.v<版本号>.<arch>.Portable.exe` |
| `scripts\package.bat` | 一次构建 + 签名两个架构，各打一个 ZIP | `bin\pkg\MythwareToolkit.v<版本号>.x64.zip`、`.x86.zip` |
| `cert\deploy.bat` | 部署到 Program Files + 桌面快捷方式 | `C:\Program Files\MythwareToolkit\` |

> `build.bat` 支持 `NOSIGN=1`（跳过签名）和 `NOPAUSE=1`（不暂停），`package.bat` 在 `NOSIGN=1` 下无需管理员权限。

### 架构选择

`build.bat` / `build_portable.bat` 无参数运行时（双击）会提示选择架构：

```
Select target architecture:
  [1] x64 - 64-bit Windows
  [2] x86 - 32-bit Windows
Enter choice [1/2]:
```

- 带参数（`x64` / `x86`）时跳过提示；`package.bat` 内部就是这样调用的。
- 设置了 `NOPAUSE=1` 但未传架构时，默认 x64（避免自动化流程卡住）。
- 脚本会自动在以下目录查找工具链，并校验 `-dumpmachine` 是否匹配所选架构：
  - x64：`D:\Dev\msys64\ucrt64`、`C:\msys64\ucrt64`、`D:\Dev\mingw64`、`C:\mingw64`、`C:\msys64\mingw64`
  - x86：`D:\Dev\msys64\mingw32`、`D:\Dev\mingw32`、`C:\mingw32`、`C:\msys64\mingw32`
- 对象文件按架构分目录（`bin\obj_x64` / `bin\obj_x86`，便携版为 `bin\objp_<arch>`），互不污染。
- 32 位程序在 64 位 Windows 上以 WOW64 运行；但它无法挂起/结束纯 64 位进程。内置的 `MeltdownDFC.exe` / `crdisk.exe` 均为 32 位，两种架构包都可正常使用。

### 两个版本的区别

| | UIAccess 版 | 便携版 |
|------|------------|--------|
| 构建 | `build.bat`（编译+签名一步完成） | `build_portable.bat` |
| 编译宏 | `-DUIACCESS_BUILD` | 无 |
| uiAccess | `true`（超级置顶） | `false`（普通置顶） |
| 签名 | build.bat 自动签名 | 不需要 |
| 使用位置 | `C:\Program Files\` | 任意位置 |
| 置顶间隔 | 3000ms | 250ms |
| 架构 | x64 / x86 均可 | x64 / x86 均可 |

### 其他工具脚本

| 脚本 | 用途 |
|------|------|
| `scripts\check_literals.py` | 字面量完整性门禁，扫描漏包的中文字面量（`python scripts\check_literals.py`） |
| `scripts\cleanup.bat` | 自动提权 → 清除程序目录、桌面快捷方式、根证书、签名证书、日志与临时文件（运行中会拒绝执行） |
| `scripts\sign.bat` | 手动签名已存在的 `bin\MythwareToolkit.v*.<arch>.exe`（x64/x86 都会签；内部调用 `sign.ps1 -Arch`） |
| `scripts\sign.ps1` | 签名底层实现：生成/复用代码签名证书、装信任根、Authenticode 签名 |

### 依赖

- 64 位：MSYS2 `ucrt64`（`pacman -S mingw-w64-ucrt-x86_64-gcc`）或 [MinGW64](https://github.com/niXman/mingw-builds-binaries)（x86_64-XX.X.X-release-win32-seh-ucrt）
- 32 位：MSYS2 `mingw32`（`pacman -S mingw-w64-i686-gcc`）或 i686 XX.X.X-release-win32-dwarf/msvcrt
- Windows 7 或更高版本（32/64 位；原生 Win7 需装 KB2999226，见「编码与 Win7 兼容」）
- PowerShell（签名和打包）
- Python 3（`scripts\check_literals.py` 完整性检查）

Makefile 支持 `mingw32-make ARCH=x64|x86` 和 `mingw32-make ARCH=x86 portable`，产物命名与 bat 脚本一致，版本号直接读取 `include/version.h`。注意：

- recipe 使用 cmd 语法（`if not exist` / `copy`），需在 cmd 的 `mingw32-make` 下运行，git bash 下会报语法错误。
- 不做工具链自动查找，也不自动签名；需自行把对应架构的 MinGW 放进 `PATH`，签名仍走 `scripts\sign.bat`。
- 日常推荐直接用 `scripts\build.bat` / `scripts\package.bat`。

---

## 保护机制

### 防杀进程

启动时调用 `ToggleProcessProtection()`，通过 ACL 修改进程安全描述符：给 `Everyone` 添加 `PROCESS_TERMINATE` 的 `DENY` 条目。任务管理器"结束任务"返回"拒绝访问"。

实现位于 `process.cpp`，使用 `GetSecurityInfo` / `SetEntriesInAclA` / `SetSecurityInfo`。

### 全局对话框保护

启动时在 `WM_CREATE` 中安装永久 `WH_CBT` 钩子（不存储句柄，进程退出时自动清理）。所有 `#32770`（对话框）窗口激活时自动调用 `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`，对教师端屏幕监控不可见。

`CBTProc` 位于 `utils.cpp`，在 `HCBT_ACTIVATE` 中同时处理：按钮文字定制（异常对话框、USB 设置等）和防截屏。永久钩子安装位于 `main.cpp` `WM_CREATE`。

### 悬浮窗保护

`floating.cpp` `WM_CREATE` 中直接调用 `SetWindowDisplayAffinity(hWnd, WDA_EXCLUDEFROMCAPTURE)`。

### 弹出菜单保护

`TrackPopupMenuProtected()` 包装函数，在菜单显示期间用定时器轮询 `FindWindow("#32768")` 并施加防截屏保护。详见 `floating.cpp`。

---

## 日志系统

| 文件 | 内容 | 行为 |
|------|------|------|
| `%TEMP%\MythwareToolkit.log` | 界面操作日志（`Print` / `Println`） | 每次启动覆盖，开头写入会话头 |
| `%TEMP%\MythwareToolkit_run.log` | 运行日志（`LOG_INFO` / `LOG_WARN` / `LOG_ERROR` / `CRASH`） | 追加写入，UTF-8（带 BOM） |
| `%TEMP%\MythwareToolkit_crash.log` | 崩溃详情（寄存器 + 栈回溯） | 追加写入 |

运行日志格式：

```
[2026-10-22 18:07:42.943][INFO ][TID:22580] FunctionName: message
```

- **会话头**：每次启动写入版本、架构、PID、OS 版本、ACP、权限级别和 exe 路径，便于对照日志与程序版本。
- **轮转**：三个日志超过 2 MB 时，在下次启动时改名为 `*.old`（只保留一份历史）。
- **并发安全**：运行日志通过 `INIT_ONCE` 初始化、长期持有单个句柄，`CRITICAL_SECTION` 加锁后单次 `WriteFile` 写入整行，多线程不会丢日志或互相穿插。句柄以 `FILE_SHARE_READ | FILE_SHARE_WRITE` 打开，多实例可共用。
- **避免刷屏**：周期性刷新（如每 2 秒一次的 `UpdateMythwareStatus`）只在状态变化时记录，不做逐次日志。
- 旧实现每次调用都重新打开文件，且只允许读共享——并发时会出现丢日志；已修复。

## 故障排查

如遇崩溃或功能异常，按顺序查看：
- `%TEMP%\MythwareToolkit_run.log`（最近的运行路径与错误）
- `%TEMP%\MythwareToolkit_crash.log`（寄存器 + 栈回溯）
- `%TEMP%\MythwareToolkit.log`（界面操作记录）

## 版本号规范

和原开发者沟通后，将原先定为 2.0.x 的更改为 1.3.0，现版本为 **1.3.1**。

版本号单一来源在 `include/version.h`：升级时只改该文件，`main.cpp` / `resource.rc` / `scripts\package.bat` 自动引用。文档（README / CHANGELOG）里的版本号仍需发版时手动同步。

打包产物命名：`MythwareToolkit.v<版本号>.<arch>.exe` / `.zip` / `.Portable.exe`，其中 `<arch>` 为 `x64` 或 `x86`。均由脚本从 `version.h` 读取版本号生成。`scripts\package.bat` 一次产出两个架构的 zip。

发版流程：

1. 改 `include/version.h` 的版本号
2. 同步 README / CHANGELOG 中的版本号（文档无法自动读取）
3. 运行 `scripts\package.bat`（需管理员，用于签名），得到 `bin\pkg\MythwareToolkit.v<版本号>.x64.zip` 与 `.x86.zip`

历史版本号有跳号：原作者停在 v1.2.5，本仓库接手后一度用了 v2.0.0 ~ v2.1.1（实为 v1.2.5 的延续，现统称 v2.0.0 ~ v2.1.1 为 v1.3.0）， CHANGELOG 中 v2.x 保留原号。

---

## 编码与 Win7 兼容

### 源码字面量编码适配（UA/AS）

项目以 `-fexec-charset=UTF-8` 编译，中文字面量在二进制里是 UTF-8 字节；但全程调用 ANSI (A) 系列 Win32 API，这些 API 按**进程 ACP** 解码。

- manifest 的 `<activeCodePage>UTF-8</activeCodePage>` 本想把 ACP 抬成 UTF-8，但实测 **Win7 与 Win11 26200 都无效**（`GetACP()` 仍返回 936），已从三个 manifest 移除。
- 新增运行时转换层 `UA(str)` / `AS(str)`（`utils.cpp` 实现、`globals.h` 声明）：纯 ASCII 或 `GetACP()==CP_UTF8` 时原样返回，否则 UTF-8 → GBK。`UA` 返回环形缓冲指针、仅本表达式内有效；`AS` 返回持有的 `std::string`。
- 漏包一处编译器不报错、只静默乱码，故用 `scripts/check_literals.py` 扫描并要求 0 处漏包（含豁免区白名单）。

### 已知上限

- 原生 Win7 依赖 UCRT（`api-ms-win-crt-*.dll`），需装 KB2999226；`-static` 与 `-mcrtdll=msvcrt` 均无法去除该依赖。
- 非中文 ACP（如英文版 1252）上中文显示为 `?`，这是 ANSI 架构固有上限，彻底解决需迁移 Unicode API。

---