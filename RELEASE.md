# MythwareToolkit v2.0

> 极域/机房助手控制工具包。悬浮窗 + 杀进程 + 解限制 + 密码计算 + 广播窗口化。

---

## 下载哪个？

| 你需要的 | 下载 |
|----------|------|
| 省心、双击即用 | **便携版** `MythwareToolkit_Portable.exe` |
| 窗口必须盖过任务管理器 | **超级置顶版** `MythwareToolkit_UIAccess.zip` |

---

## 便携版

**只有一个文件：** `MythwareToolkit_Portable.exe`

**使用：双击运行。** U 盘即插即用，放哪都能跑，无需任何配置。

> 浮���窗在屏幕右侧中间，左键开面板，中键一键广播窗口化。

---

## 超级置顶版

### 压缩包内容

```
MythwareToolkit_UIAccess.zip
├── MythwareToolkit.exe   ← 主程序（已签名）
├── deploy.bat            ← 证书安装脚本
└── mythware.cer          ← 签名证书
```

### 使用说明

**1.** 将压缩包解压到某个文件夹。

**2.** 右键 `deploy.bat` → **以管理员身份运行**。这一步会：

- 安装证书到系统受信任根 → 解决弹窗
- 复制 `MythwareToolkit.exe` 到 `C:\Program Files\MythwareToolkit\`
- 创建桌面快捷方式

**3.** 之后从桌面快捷方式启动，或直接打开 `C:\Program Files\MythwareToolkit\MythwareToolkit.exe`。

> **为什么必须放 Program Files？** UIAccess 是 Windows 安全机制，只允许签名过的 exe 从系统受保护目录（`C:\Program Files\` / `C:\Windows\`）运行。放桌面或 D 盘会一直弹"从服务器返回了一个参照"，就算证书装好了也没用。

---

## 常见问题

**Q：便携版和超级置顶版功能一样吗？**
完全一样。唯一区别：超级置顶版能覆盖任务管理器、放大镜等系统窗口。

**Q：装完证书还需要管理员权限吗？**
不需要。证书装一次就行，之后直接双击 EXE。

**Q：为什么弹"从服务器返回了一个参照"？**
三个可能：1) 证书没装 → 运行 `deploy.bat`；2) EXE 没放在 `C:\Program Files\` 下 → 复制过去；3) 两个都没做 → 直接运行 `deploy.bat` 一步搞定。
