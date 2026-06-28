# 开发者文档

> 面向开发者的编译、部署、项目结构说明。用户使用说明见 [README](README.md)。

---

## 项目结构

```
MythwareToolkit/
├── src/          ← 源码（9个 .cpp）
├── include/      ← 头文件（4个 .h）
├── res/          ← 资源（图标/图片/manifest/嵌入式exe）
├── scripts/      ← 编译 + 打包 + 签名 + 清理 + 图标转换
├── cert/         ← 证书 + 部署（deploy.bat / mythware.cer ）
├── bin/          ← 编译产物 + 打包输出
│   └── pkg/      ← 发行版文件（EXE + ZIP）
├── Makefile
├── README.md
├── CHANGELOG.md
├── RELEASE.md
└── DEV.md
```

---

## 编译与部署

### UIAccess 完整版（超级置顶）

两步走，全部双击运行：

```batch
scripts\build.bat    →  编译 + 自动签名（自动提权）
cert\deploy.bat      →  部署到 C:\Program Files\
```

| 脚本 | 做什么 | 输出 |
|------|--------|------|
| `scripts\build.bat` | 编译 + 自动签名 + 随机命名输出到 `bin/pkg/` | `bin\MythwareToolkit.exe` |
| `scripts\build_portable.bat` | 编译便携版 + 输出到 `bin/pkg/` | `bin\MythwareToolkit_Portable.exe` |
| `scripts\package.bat` | 打包 ZIP（EXE + deploy.bat + mythware.cer） | `bin\pkg\MythwareToolkit.zip` |
| `cert\deploy.bat` | 部署到 Program Files + 桌面快捷方式 | `C:\Program Files\MythwareToolkit\` |

### 两个版本的区别

| | UIAccess 版 | 便携版 |
|------|------------|--------|
| 构建 | `build.bat`（编译+签名一步完成） | `build_portable.bat` |
| 编译宏 | `-DUIACCESS_BUILD` | 无 |
| uiAccess | `true`（超级置顶） | `false`（普通置顶） |
| 签名 | build.bat 自动签名 | 不需要 |
| 使用位置 | `C:\Program Files\` | 任意位置 |
| 置顶间隔 | 3000ms | 250ms |

### 其他工具脚本

| 脚本 | 用途 |
|------|------|
| `scripts\cleanup.bat` | 管理员运行 → 清除证书/程序/快捷方式/临时文件 |
| `scripts\sign.bat` | 手动签名 `bin\MythwareToolkit.exe`（build.bat 已自动调用） |
| `convert_icon.bat` | PNG→ICO 多分辨率高清转换 → `res\float.ico` |

### 依赖

- [MinGW64](https://github.com/niXman/mingw-builds-binaries)（x86_64-XX.X.X-release-win32-seh-ucrt）
- Windows 10 或更高版本（64 位）
- PowerShell（签名和打包）

Makefile 也支持：`make` / `make portable`。

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

## 故障排查

### 崩溃 / 0xC0000005

v2.1 已修复学生机崩溃问题。如仍遇崩溃，查看：
- `%TEMP%\MythwareToolkit_crash.log`（寄存器 + 栈回溯）
- `%TEMP%\MythwareToolkit_run.log`（运行日志）
