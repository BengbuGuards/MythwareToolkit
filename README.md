# MythwareToolkit

极域工具包，支持多种控制极域以及学生机房管理助手的工具。StudentMain、Mythware、Jiyu

![截图](https://img-blog.csdnimg.cn/60d799d3637b4fe8a99c295a6bad605b.png#pic_center)

截图（1.2.1）

如果喜欢本项目，给个star可以吗？￣へ￣

欢迎访问[原理介绍博客](https://blog.csdn.net/weixin_42112038/article/details/125346545)，欢迎关注！

## 功能

注：以下*斜体标注*的内容表示即将到来的功能

**README适应版本：v1.2.2-patch**

### 极域控制

- 支持不依赖`taskkill`、`ntsd`等工具杀掉极域。极域未运行时可启动极域，降权到登录用户（路径来自注册表）
- 显示极域存活状态：未运行/正常运行/已挂起/无响应 + PID
- 解除极域网络限制功能（黑/白名单或是直接禁用，下面这些解禁功能一般都是仅对2016版有效，可验证至2021版）
- 解除极域U盘限制功能，有两种方式
- 窗口化/全屏化极域广播
- 挂起（冻结）/恢复极域
- 解鼠标限制，例如屏幕广播时的鼠标锁和机房管理助手蓝屏时的鼠标活动范围限制（教师端的远程控制依然有效）
- 支持解极域键盘锁，可以解锁<kbd>Alt</kbd>+<kbd>Ctrl</kbd>+<kbd>Delete</kbd>
- 防止截屏功能，可以防止教师端看到本程序（旧版本Windows看到黑框，新版本则是会看到后面的内容）

### 学生机房管理助手控制

- 支持关闭6.8-10.1版本的学生机房管理助手（其中某些版本可能不能正常工作，但是依然可以利用快捷键清除漏网之鱼）
- 将学生机房管理助手密码更改为12345678（7.1-9.9x版本有效，但是不推荐在助手运行期间更改，因为会蓝屏）。**最新版本的密码逻辑有变，所以建议不要更改。**
- 可以解除cmd（命令提示符）、注册表编辑器、任务管理器、注销、管理控制台、taskkill等程序，还可以解禁Chrome恐龙游戏和Edge冲浪游戏，以及Win7系统自带的一些游戏。
- 新版本机房助手会禁用Tab键，请在使用“解禁系统程序”功能后注销重登，才能解锁（一般此操作不会触发系统还原，但别忘了重新打开本软件）。
- 可以重启资源管理器（explorer.exe）

### 通用功能

- 内置MeltdownDFC、crdisk两个解除硬盘保护的软件
- 快捷键：
	- <kbd>Alt</kbd>+双击<kbd>C</kbd>强制结束当前程序（可用于对付机房助手）
	- <kbd>Alt</kbd>+<kbd>B</kbd>显示程序主界面（也可以从托盘小图标启动）
	- <kbd>Alt</kbd>+<kbd>W</kbd>最小化当前窗口
- 支持启动任务管理器，自动“置于顶层”。
- 支持超级置顶（UIAccess），可以覆盖任务管理器和放大镜。

#### 重要提醒！！！

若出现“从服务器返回了一个参照”的弹窗，请下载存储库中`RootCA.reg`文件导入即可。如果在您的设备中没有超级置顶，可以改改**组策略：计算机配置→Windows 设置→安全设置→本地策略→安全选项→用户帐户控制: 仅提升已签名和验证的可执行文件**，改成禁用

<details>
<summary>查看图片</summary>

![1](https://img-blog.csdnimg.cn/3bf026b7cf14411fa15c83fee47cf771.png)

![2](https://img-blog.csdnimg.cn/8065bc909c2148dd8039b67343cc2fc5.png)

</details>

- 当勾选“启用鼠标检测弹窗”选项后，鼠标移至屏幕左上角时，可以选择最小化当前的焦点窗口，与解键盘锁结合就可以实现脱离黑屏；移至右上角时，可以选择关闭当前焦点窗口，类似于<kbd>Alt</kbd>+<kbd>F4</kbd>效果。还有强制关闭窗口功能（即强制关闭：禁用关闭窗口、屏蔽<kbd>Alt</kbd>+<kbd>F4</kbd>的窗口，对UWP应用无效）

## 附录

<details>

### 防止教师端强制关机

只需删除极域目录下的Shutdown.exe即可。此后工具包将对这些远控操作做专门的预防

### 使用命令行或PowerShell手动解除极域U盘限制

CMD：

```powershell
sc stop TDFileFilter
sc delete TDFileFilter #可选
```

PowerShell：（适用于CMD被禁用情况）

```powershell
cd C:\Windows\System32\
.\sc.exe stop TDFileFilter
.\sc.exe delete TDFileFilter #可选
```

### 学生机房管理助手的软件黑名单（10.1版本）

进程名包含这些词就会蓝屏（加粗的名字不仅匹配进程名，还匹配窗口名）：

vmware、VirtualBox、Virtual PC、**虚拟机**、**电子教室**、ProcView、IceSword、Procmast.exe、**toolkit_32-bits.exe**（有点搞笑，只捉按规范命名的32位程序，随便一改都搞得定）、rstray.exe、PFW.exe、FTCleaner.exe、Wsyscheck.exe、XueTr.exe、prom.exe、ProcessX.exe、pchunter、**Killer.exe**、procmgr.exe、ProcessHacker.exe、killcontrol、PowerTool32.exe、360taskmgr、YtWinAst、KVFWMain.exe、ECQ-PS.exe、SnipeSword、procexp、**MsgFlood.exe**、ProcessOVER、procdeal、**多桌面**、**任务管理**、**进程**、Prayaya、dexpot.exe、vdeskman.exe、mdesk.exe、**virtualdesk**、multideskt.exe、VirDsk.exe、IDesktop.exe、YtMDesk.exe、coon.exe、zmqh.exe、DexpotProPortable.exe、Desktops.exe、wisedesktop.exe、DESKTOP.exe、Vdesktop.exe、MagicDesktop.exe、multidesktop.exe、**weRs0cqa**（这个有特别关照，在蓝屏窗口加载时还会自动杀掉带有这个名字的进程）、RegWX64.exe、QQPCNetFlow.exe、BDMANetLimiter.exe、netmon.exe、360netman.exe、HelloTeacher.exe、EHacker.exe、PowerTool64.exe、zydesk.exe、perfmon.exe、**吾爱破解**、**极域**、prcview.exe、processlasso.exe、netfuke.exe、**去除控制**、**课堂狂欢器**、**课堂工具**、fuckmythware、SpecialSet.exe、JiYuTrainer.exe、skieskiller、WindowsKernelExplorer.exe、msconfig.exe、iu杀毒、**窗口拓印**
。另外包括任务管理器，会有独特的锁定蓝屏界面。

### 在线根据明文生成学生机房管理助手密码（7.2版本以上，9.98以下）

访问[这个网站](https://try.dot.net/)，在代码运行窗口输入如下内容，便可生成密文，将密文写入注册表HKEY_CURRENT_USER\Software:n（REG_SZ），机房助手密码将会被立即更改：（也可以本地运行）

```csharp
// 代码来自学生机房管理助手9.0 set.exe，逆向、整理：小流汗黄豆
using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

public class Program
{
	public static void Main()
	{
		// 更改这里的内容
		string string_3 = "12345678";
		// Class6.smethod_0()
		string value = "C:\\WINDOWS";
		string s = value.Substring(0, 8);
		string s2 = value.Substring(1, 8);
		DESCryptoServiceProvider descryptoServiceProvider = new DESCryptoServiceProvider();
		descryptoServiceProvider.Key = Encoding.UTF8.GetBytes(s);
		descryptoServiceProvider.IV = Encoding.UTF8.GetBytes(s2);
		MemoryStream memoryStream = new MemoryStream();
		CryptoStream cryptoStream = new CryptoStream(memoryStream, descryptoServiceProvider.CreateEncryptor(), CryptoStreamMode.Write);
		StreamWriter streamWriter = new StreamWriter(cryptoStream);
		streamWriter.Write(string_3);
		streamWriter.Flush();
		cryptoStream.FlushFinalBlock();
		memoryStream.Flush();
		string string_4 = Convert.ToBase64String(memoryStream.GetBuffer(), 0, checked((int)memoryStream.Length));
		// Class6.smethod_3()
		StringBuilder stringBuilder = new StringBuilder();
		for(int i = 0; i < string_4.Length; i++)
			stringBuilder.Append((char)(string_4[i] - 10));
		string_3 = stringBuilder.ToString();
		// Class6.smethod_2()
		MD5CryptoServiceProvider md5CryptoServiceProvider = new MD5CryptoServiceProvider();
		byte[] array2 = md5CryptoServiceProvider.ComputeHash(Encoding.Default.GetBytes(string_3));
		stringBuilder.Clear();
		for (int i = 0; i < array2.Length; i++)
			stringBuilder.Append(array2[i].ToString("x2"));
		string str = stringBuilder.ToString().Substring(10);

		Console.WriteLine(str);
	}
}
// 期望输出：8a29cc29f5951530ac69f4，但是对于9.99以上版本为8a29cc29f5951530ac69需自己改
```

</details>

## 开发

鼓励大伙提出反馈和建议，也支持PR拉请求。

编译：使用最新版本的MinGW64编译器（<https://github.com/niXman/mingw-builds-binaries>），最好配合Red Panda C++等IDE开发和构建。

代码开源许可：若有引用他人代码，则引用部分遵循原作者许可；其他代码处于公共领域，请标注作者：小流汗黄豆。

另外：机房助手作者钟鸣，存在通过助手的木马广告非法获利（篡改浏览器主页至2345导航，一月获利以百元计）的行为。这可与其标榜的绿色无毒背道而驰了。
