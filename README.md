# MythwareToolkit

> 基于 [BengbuGuards/MythwareToolkit](https://github.com/BengbuGuards/MythwareToolkit) 源码进行 AI+人工修改，在此感谢原作者！

> **[更新日志](CHANGELOG.md)** — 查看 v2.0.0 所有改动

极域工具包，支持多种控制极域以及学生机房管理助手的工具。StudentMain、Mythware、Jiyu

![截图](https://img-blog.csdnimg.cn/60d799d3637b4fe8a99c295a6bad605b.png#pic_center)

截图（v1.2.1，新版本 UI 已重新设计）

**当前版本：v2.0.0**

```
MythwareToolkit/
├── src/          ← 源码（9个 .cpp）
├── include/      ← 头文件（4个 .h）
├── res/          ← 资源（图标/图片/manifest/嵌入式exe）
├── scripts/      ← 编译脚本（build.bat / build_portable.bat / sign.ps1）
├── cert/         ← 证书 + 部署（deploy.bat / mythware.cer / RootCA.reg）
├── bin/          ← 编译输出（不入仓）
├── Makefile
├── README.md
└── CHANGELOG.md
```

---

## v2.0.0 新增

- **圆形悬浮窗**：始终置顶，左键切换主面板，**中键一键广播窗口化**，右键快捷菜单，支持拖拽
- **UI 重设计**：640×380 宽敞布局，左右分栏，按钮不再拥挤
- **日志自动落盘**：每次运行自动写入 `%TEMP%\MythwareToolkit.log`
- **代码重构**：1623 行 main.cpp 拆分为 9 个独立模块，UTF-8 编码
- **默认行为**：解鼠标锁、解键盘锁启动即生效
- **状态栏**：显示极域版本号
- **编译**：支持 CMake + Makefile + build.bat 三种方式

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

## 编译

### 方式一：build.bat（最简单）

```batch
scripts\build.bat          → bin\MythwareToolkit.exe       （UIAccess 完整版，需签名+安装）
scripts\build_portable.bat → bin\MythwareToolkit_Portable.exe （便携版，免签名免安装）
```

双击即可运行。自动检测 `D:\Dev\mingw64` / `C:\mingw64` / `C:\msys64\mingw64` / PATH 中的 MinGW64。

两个版本的区别：
- **build.bat** — `uiAccess="true"`，超级置顶（覆盖任务管理器），需签名后安装到 `C:\Program Files\`
- **build_portable.bat** — `uiAccess="false"`，免签名，U盘即插即用，牺牲超级置顶能力

### 方式二：Makefile

```bash
make          # UIAccess 版
make portable # 便携版
```

### 依赖

- [MinGW64](https://github.com/niXman/mingw-builds-binaries)（x86_64-XX.X.X-release-win32-seh-ucrt）
- GDI+（系统自带）

---

## 部署

### UIAccess 完整版

1. 运行 `scripts\build.bat` 编译
2. 以管理员 PowerShell 运行签名脚本：
   ```powershell
   powershell -File scripts\sign.ps1
   ```
3. 部署（复制到 Program Files + 安装证书 + 创建快捷方式）：
   ```batch
   cert\deploy.bat
   ```

### 便携版

直接编译 `scripts\build_portable.bat`，输出 `bin\MythwareToolkit_Portable.exe` 可在任意位置双击运行，无需签名和安装。

### 证书安装（解决"从服务器返回了一个参照"弹窗）

如果遇到弹窗报错，导入证书即可：

```batch
cert\deploy.bat    # 一键部署（推荐）
:: 或手动导入
certutil -addstore -f -enterprise Root cert\mythware.cer
:: 或导入注册表
cert\RootCA.reg
```

以上文件均在 `cert\` 目录下。

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

若出现"从服务器返回了一个参照"弹窗，导入 `cert\RootCA.reg`（原版证书）或 `cert\mythware.cer`（本版证书），或直接运行 `cert\deploy.bat`。机房环境建议关闭 UAC。

</details>
