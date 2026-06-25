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
| `scripts\build.bat` | 编译 + 自动签名 | `bin\MythwareToolkit.exe` |
| `scripts\package.bat` | 编译+签名+验证签名+打包 ZIP | `bin\pkg\MythwareToolkit.zip` |
| `cert\deploy.bat` | 部署到 Program Files + 桌面快捷方式 | `C:\Program Files\MythwareToolkit\` |

### 便携版（免签名免安装）

```batch
scripts\build_portable.bat
```

输出 `bin\MythwareToolkit_Portable.exe`，同时自动复制到 `bin\pkg\`。

### 两个版本的区别

| | UIAccess 版 | 便携版 |
|------|------------|--------|
| 构建 | `build.bat`（编译+签名一步完成） | `build_portable.bat` |
| 编译宏 | `-DUIACCESS_BUILD` | 无 |
| uiAccess | `true`（超级置顶） | `false`（普通置顶） |
| 签名 | build.bat 自动签名 | 不需要 |
| 使用位置 | `C:\Program Files\` | 任意位置 |
| 置顶机制 | 系统 UIAccess 真正置顶 | 轮询 + `WM_WINDOWPOSCHANGED` |

### 其他工具脚本

| 脚本 | 用途 |
|------|------|
| `scripts\cleanup.bat` | 管理员运行 → 清除证书/程序/快捷方式/临时文件 |
| `convert_icon.bat` | PNG→ICO 多分辨率高清转换 → `res\float.ico` |

### 依赖

- [MinGW64](https://github.com/niXman/mingw-builds-binaries)（x86_64-XX.X.X-release-win32-seh-ucrt）
- Windows 10 或更高版本（64 位）
- PowerShell（签名和打包）

Makefile 也支持：`make` / `make portable`。

---

## 故障排查

### 崩溃 / 0xC0000005

v2.1 已修复学生机崩溃问题。如仍遇崩溃，查看：
- `%TEMP%\MythwareToolkit_crash.log`（寄存器 + 栈回溯）
- `%TEMP%\MythwareToolkit_run.log`（运行日志）
