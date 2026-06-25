# MythwareToolkit

> 基于 [BengbuGuards/MythwareToolkit](https://github.com/BengbuGuards/MythwareToolkit) 源码进行 AI+人工修改，在此感谢原作者！

> **[更新日志](CHANGELOG.md)** — 查看 v2.1.0 所有改动

极域工具包，支持多种控制极域以及学生机房管理助手的工具。StudentMain、Mythware、Jiyu

![截图](https://img-blog.csdnimg.cn/60d799d3637b4fe8a99c295a6bad605b.png#pic_center)

截图（v1.2.1，新版本 UI 已重新设计）

**当前版本：v2.1.0**

```
MythwareToolkit/
├── src/          ← 源码（9个 .cpp）
├── include/      ← 头文件（4个 .h）
├── res/          ← 资源（图标/图片/manifest/嵌入式exe）
├── scripts/      ← 编译 + 签名（build.bat / build_portable.bat / sign.bat / sign.ps1）
├── cert/         ← 证书 + 部署（deploy.bat / mythware.cer / RootCA.reg / 故障排查）
├── bin/          ← 编译输出（不入仓）
├── Makefile
├── README.md
└── CHANGELOG.md
```

---

## v2.1.0 新增

- **圆形悬浮窗**：始终置顶，左键切换主面板，**中键一键广播窗口化**，右键快捷菜单（防截屏），支持拖拽
- **崩溃自动诊断**：崩溃日志含完整寄存器 + 栈回溯，运行日志记录每一步操作
- **UI 重设计**：640×380 宽敞布局，左右分栏，按钮不再拥挤
- **日志系统**：运行日志 `MythwareToolkit_run.log` + 崩溃日志 `MythwareToolkit_crash.log`
- **代码重构**：1623 行 main.cpp 拆分为 9 个独立模块，UTF-8 编码
- **默认行为**：解鼠标锁、解键盘锁启动即生效
- **状态栏**：显示极域版本号
- **编译**：`build.bat` 一键编译 + `sign.bat` 一键签名，也支持 Makefile
- **图标转换工具**：`convert_icon.bat` 一键 PNG→ICO（多分辨率高清）

---

## 功能

### 极域控制

- 支持不依赖`taskkill`、`ntsd`等工具杀掉极域。极域未运行时可启动极域，降权到登录用户（路径来自注册表）
- 显示极域存活状态：未运行/正常运行/已挂起/无响应 + PID + 版本号
- 解除极域网络限制（黑/白名单或直接禁用，2016版测试通过，可验证至2021版）
- 解除极域U盘限制，两种方式（软解禁 / 硬解禁）
- 窗口化/全屏化极域广播（悬浮窗右键菜单或中键一键操作）
- 挂起（冻结）/恢复极域
- 解鼠标限制、键盘锁（启动默认开启）
- 防止截屏（Win7+），防止教师端看到本程序

### 学生机房管理助手控制

- 支持关闭 v6.8 ~ v12.99 版本的学生机房管理助手
- 计算 v9.x ~ v12.0 临时密码（动态密码计算器）
- 一键解禁系统程序：CMD、注册表编辑器、任务管理器、浏览器下载限制、小游戏等
- 重启资源管理器（explorer.exe）

### 通用功能

- 内置 MeltdownDFC、crdisk 两个解除硬盘保护的工具
- 快捷键：
  - <kbd>Alt</kbd>+双击<kbd>C</kbd> — 强制结束当前程序
  - <kbd>Alt</kbd>+<kbd>B</kbd> — 唤起主界面
  - <kbd>Alt</kbd>+<kbd>W</kbd> — 最小化当前窗口
- 支持超级置顶（UIAccess），覆盖任务管理器和放大镜
- 鼠标移至屏幕左上角/右上角弹窗操作
- 托盘图标常驻，最小化不占任务栏

---

## 使用教程

发行版提供两个版本，根据需求选择：

### 便携版（推荐大多数用户）

下载 `MythwareToolkit_Portable.exe`，**双击运行**即可。

- ✅ 免安装、免签名，U 盘即插即用
- ✅ 悬浮窗 + 完整功能
- ⚠️ 不能覆盖任务管理器（普通置顶）

### 超级置顶版（可覆盖任务管理器）

> 下载的文件包应包含：`MythwareToolkit.exe` + `deploy.bat` + `mythware.cer`

**1. 首先**，右键 `deploy.bat` → **以管理员身份运行**。它会自动：

- 安装证书到系统受信任根
- 复制 `MythwareToolkit.exe` 到 `C:\Program Files\MythwareToolkit\`
- 创建桌面快捷方式

**2. 之后**从桌面快捷方式启动即可。

> **为什么必须用 deploy.bat？** UIAccess 是 Windows 安全机制：exe 必须已签名、证书必须受信任、**且 exe 必须在 `C:\Program Files\` 下**。放桌面或别处会一直弹窗，即使装了证书也没用。`deploy.bat` 一步搞定这三个条件。

> 证书只需装一次，同一台电脑以后不用再装。

### 两个版本怎么选

| | 便携版 | 超级置顶版 |
|------|--------|-----------|
| 怎么用 | 双击运行 | 双击运行（弹窗则装证书） |
| 覆盖任务管理器 | ❌ | ✅ |
| 覆盖放大镜 | ❌ | ✅ |
| 需要安装 | 不需要 | 证书装一次 |
| 位置 | 放哪都行 | 任意位置 |
| 推荐场景 | 日常使用 | 教师端特别严格的环境 |

---

## 开发者：编译与部署

### UIAccess 完整版（超级置顶）

两步走，全部双击运行：

```batch
scripts\build.bat    →  编译 + 自动签名（自动提权）
cert\deploy.bat      →  部署到 C:\Program Files\
```

| 脚本 | 做什么 | 输出 |
|------|--------|------|
| `scripts\build.bat` | 编译 9 个源文件 → 自动签名 EXE | `bin\MythwareToolkit.exe`（已签名） |
| `cert\deploy.bat` | 复制到 Program Files + 桌面快捷方式 | `C:\Program Files\MythwareToolkit\` |

> `build.bat` 编译完成后会自动提权签名，一步到位。如需单独重新签名可运行 `scripts\sign.ps1`。

### 便携版（免签名免安装）

一步搞定：

```batch
scripts\build_portable.bat
```

输出 `bin\MythwareToolkit_Portable.exe`，U 盘即插即用，双击即可运行。

> 便携版牺牲超级置顶能力（不能覆盖任务管理器），但无需签名和安装。

### 两个版本的区别

| | UIAccess 版 | 便携版 |
|------|------------|--------|
| 构建 | `build.bat`（编译+签名一步完成） | `build_portable.bat` |
| uiAccess | `true`（超级置顶） | `false`（普通置顶） |
| 签名 | build.bat 自动签名 | 不需要 |
| 使用位置 | `C:\Program Files\`（deploy.bat 自动复制） | 任意位置 |
| 弹窗处理 | `cert\deploy.bat` 装证书 | 不会弹窗 |
| 悬浮窗 | 纯 GDI 圆形裁剪 | 同左 |

### 依赖

- [MinGW64](https://github.com/niXman/mingw-builds-binaries)（x86_64-XX.X.X-release-win32-seh-ucrt）
- Windows 10 或更高版本（64 位）

Makefile 也支持：`make` / `make portable`。

---

## 故障排查

### "从服务器返回了一个参照" 弹窗

UIAccess 程序必须**同时满足**两个条件：EXE 已签名 **且** 证书受信任。只装证书不签名无效！

**正确做法：** 运行 `scripts\build.bat`（编译后自动签名），或单独运行 `scripts\sign.bat` / `scripts\sign.ps1` 手动签名。

如果已签名但证书问题：
```batch
certutil -addstore -f -enterprise Root cert\mythware.cer   :: 手动装证书
cert\RootCA.reg                                              :: 或导入注册表
```

详见 `cert\从服务器返回一个参数解决方法.txt`。

### 崩溃 / 0xC0000005

v2.1 已修复学生机崩溃问题（移除对极域注入 DLL 的暴力卸载）。如仍遇崩溃，查看 `%TEMP%\MythwareToolkit_crash.log`（寄存器 + 栈回溯）和 `%TEMP%\MythwareToolkit_run.log`（运行日志）。

---

## 附录

<details>

### 防止教师端强制关机

删除极域目录下的 `Shutdown.exe` 即可。

### 命令行解除极域U盘限制

CMD：
```powershell
sc stop TDFileFilter
sc delete TDFileFilter
```

PowerShell（CMD被禁用时）：
```powershell
cd C:\Windows\System32\
.\sc.exe stop TDFileFilter
.\sc.exe delete TDFileFilter
```

### 学生机房管理助手的软件黑名单（v10.1）

进程名包含这些词就会蓝屏（加粗的匹配进程名+窗口名）：

vmware、VirtualBox、Virtual PC、**虚拟机**、**电子教室**、ProcView、IceSword、Procmast.exe、**toolkit_32-bits.exe**、rstray.exe、PFW.exe、FTCleaner.exe、Wsyscheck.exe、XueTr.exe、prom.exe、ProcessX.exe、pchunter、**Killer.exe**、procmgr.exe、ProcessHacker.exe、killcontrol、PowerTool32.exe、360taskmgr、YtWinAst、KVFWMain.exe、ECQ-PS.exe、SnipeSword、procexp、**MsgFlood.exe**、ProcessOVER、procdeal、**多桌面**、**任务管理**、**进程**、Prayaya、dexpot.exe、vdeskman.exe、mdesk.exe、**virtualdesk**、multideskt.exe、VirDsk.exe、IDesktop.exe、YtMDesk.exe、coon.exe、zmqh.exe、DexpotProPortable.exe、Desktops.exe、wisedesktop.exe、DESKTOP.exe、Vdesktop.exe、MagicDesktop.exe、multidesktop.exe、**weRs0cqa**（蓝屏时还会自动杀掉该名进程）、RegWX64.exe、QQPCNetFlow.exe、BDMANetLimiter.exe、netmon.exe、360netman.exe、HelloTeacher.exe、EHacker.exe、PowerTool64.exe、zydesk.exe、perfmon.exe、**吾爱破解**、**极域**、prcview.exe、processlasso.exe、netfuke.exe、**去除控制**、**课堂狂欢器**、**课堂工具**、fuckmythware、SpecialSet.exe、JiYuTrainer.exe、skieskiller、WindowsKernelExplorer.exe、msconfig.exe、iu杀毒、**窗口拓印**

此外任务管理器会触发独特的锁定蓝屏界面。

### 助手临时密码算法（v9.x ~ v12.0）

1. 10.0 前：首位为 8，后面为 `16 × (年 × 91 + 月 × 13 + 日 × 57)`
2. 10.0 ~ 11.0：上面结果 +11
3. 11.0 ~ 11.06 首个发布版：`年 × 789 + 月 × 123 + 日 × 456 + 111`
4. 11.06 第三版 ~ 12.0：`(月 × 159 + 日 × 357 + 计算机名末位 ASCII × 258)` 转 7 进制

使用本程序的"动态密码计算器"可直接计算。

### 在线生成机房助手密文（v7.2 ~ v9.98）

访问 [try.dot.net](https://try.dot.net/)，运行以下 C# 代码，将输出写入注册表 `HKEY_CURRENT_USER\Software:n`（REG_SZ），机房助手密码立即更改：

```csharp
using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

public class Program
{
    public static void Main()
    {
        string string_3 = "12345678"; // 改成你的密码
        string value = "C:\\WINDOWS";
        string s = value.Substring(0, 8);
        string s2 = value.Substring(1, 8);
        DESCryptoServiceProvider desc = new DESCryptoServiceProvider();
        desc.Key = Encoding.UTF8.GetBytes(s);
        desc.IV = Encoding.UTF8.GetBytes(s2);
        MemoryStream ms = new MemoryStream();
        CryptoStream cs = new CryptoStream(ms, desc.CreateEncryptor(), CryptoStreamMode.Write);
        StreamWriter sw = new StreamWriter(cs);
        sw.Write(string_3); sw.Flush(); cs.FlushFinalBlock(); ms.Flush();
        string enc = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < enc.Length; i++) sb.Append((char)(enc[i] - 10));
        MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
        byte[] hash = md5.ComputeHash(Encoding.Default.GetBytes(sb.ToString()));
        sb.Clear();
        for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
        Console.WriteLine(sb.ToString().Substring(10));
    }
}
// 期望输出：8a29cc29f5951530ac69f4（v9.99 以上为 8a29cc29f5951530ac69）
```

### 重要提醒

若出现"从服务器返回了一个参照"弹窗，说明 EXE 未签名或证书未安装。运行 `scripts\sign.bat` 一步解决。或手动导入 `cert\RootCA.reg`（原版证书）/ `cert\mythware.cer`（本版证书）。详见 `cert\从服务器返回一个参数解决方法.txt`。机房环境建议关闭 UAC。

</details>
