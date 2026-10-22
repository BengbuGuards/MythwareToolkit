#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整性门禁：确保所有含非 ASCII 的字符串字面量最终都以 ACP 字节送达 Win32 A API。

背景：本项目以 -fexec-charset=UTF-8 编译（中文字面量是 UTF-8 字节），却调用
ANSI (A) 系列 Win32 API —— 这些 API 按进程 ACP 解码。曾想靠 manifest 的
activeCodePage 把 ACP 设成 UTF-8，但实测 Win7 与 Win11 26200 均无效（该设置
已移除），ACP 仍是 936，于是全部乱码。修法是让字面量在传参前经 UA()/AS() 转成 ACP 字节。

危险在于：漏包一处，编译器不会报错，只会在 Win7 上静默乱码（甚至让字符串
比较失效）。所以用本脚本兜底。

用法：python scripts/check_literals.py    （在仓库根目录执行）
退出码 0 = 通过，1 = 有漏包。
"""
import re
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

WRAPPERS = ("UA", "AS")

# ── 豁免区 ────────────────────────────────────────────────────────────────
# 这些位置的字面量确实是非 ASCII 且没有就地包装，但**故意的**，理由见注释。
# 按 (相对路径, 起始行, 结束行) 声明，区间为闭区间。
ALLOW = [
    # bypass.cpp 的静态表：pair 的 .second 是给人看的显示名，表本身只存 UTF-8，
    # 真正送进 API 前统一在遍历处转 —— 见 `UA(v.second)` / `AS(p.second)`。
    ("src/bypass.cpp", 32, 43, "静态表 .second 显示名，遍历处已 UA()/AS()"),
    ("src/bypass.cpp", 58, 61, "同上"),
    ("src/bypass.cpp", 76, 84, "同上"),
    ("src/bypass.cpp", 96, 102, "同上"),

    # psd.cpp：对话框模板的标题必须写成 UTF-16 塞进 DLGTEMPLATE，
    # 源码字面量是 UTF-8，所以这里显式用 CP_UTF8 转换 —— 转完即宽字符，
    # 不经过 ACP，用 UA()/AS() 反而是错的。
    ("src/psd.cpp", 89, 89, "MultiByteToWideChar(CP_UTF8) 显式转换，不经 ACP"),

    # mythware.cpp 的窗口标题常量表，同 bypass.cpp：存 UTF-8，在
    # EnumWindowsProc 里用 AS() 转好再拿去和 GetWindowTextA 的 ACP 字节比较。
    ("src/mythware.cpp", 4, 4, "窗口标题常量表，EnumWindowsProc 中已 AS()"),
]


def logical_lines(lines):
    """
    把相邻字面量拼接的多行合并成一条逻辑行，行号取起始行。
    否则 `UA("a"\\n "b")` 里第二行往后的字面量会被误判为漏包。
    """
    out, buf, start = [], None, 0
    for lineno, line in enumerate(lines, 1):
        if buf is None:
            buf, start = line, lineno
        else:
            buf += line
        # 去掉行尾注释再判断，免得 `UA("x")  // 注意"` 这种把下一行误并进来
        code = line.split("//")[0].rstrip()
        if code.endswith('"'):
            continue
        out.append((buf, start))
        buf = None
    if buf is not None:
        out.append((buf, start))
    return out


def literals_in(line):
    """产出 (字面量内容, 起始列)。跳过注释；不跨行处理转义。"""
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c == '/' and i + 1 < n and line[i + 1] == '/':
            return
        if c == '/' and i + 1 < n and line[i + 1] == '*':
            end = line.find('*/', i + 2)
            i = n if end < 0 else end + 2
            continue
        if c == '"':
            start = i
            i += 1
            buf = []
            while i < n:
                if line[i] == '\\':
                    buf.append(line[i:i + 2])
                    i += 2
                    continue
                if line[i] == '"':
                    break
                buf.append(line[i])
                i += 1
            yield ''.join(buf), start
            i += 1
            continue
        if c == "'":
            i += 1
            while i < n:
                if line[i] == '\\':
                    i += 2
                    continue
                if line[i] == "'":
                    break
                i += 1
            i += 1
            continue
        i += 1


def is_continuation(line, col):
    """相邻字面量拼接：`UA("a" "b")` 里的 "b" —— 前面的非空白字符是引号。"""
    j = col - 1
    while j >= 0 and line[j] in ' \t':
        j -= 1
    return j >= 0 and line[j] == '"'


def wrapped_backwards(line, col):
    """
    从字面量起点向前找**未闭合**的 UA(/AS( —— 覆盖三元、多实参这些
    `UA(x ? "a" : "b")` / `f(UA("a"), UA("b"))` 的写法。
    """
    depth = 0
    j = col - 1
    while j >= 0:
        ch = line[j]
        if ch == ')':
            depth += 1
        elif ch == '(':
            if depth == 0:
                head = line[max(0, j - 2):j]
                return head in WRAPPERS
            depth -= 1
        elif ch == ';' and depth == 0:
            return False
        elif ch == '"' and depth == 0:
            # 撞上上一个字面量的结束引号：说明是拼接，继续往前看它的起始引号
            j -= 1
            while j >= 0 and line[j] != '"':
                j -= 1
        j -= 1
    return False


def allowed(rel, lineno):
    return any(rel == a and lo <= lineno <= hi for a, lo, hi, _ in ALLOW)


def main():
    # 控制台可能是 936，直接 print 中文会炸；强制 UTF-8 并让不可编码字符降级
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    bad = []
    for path in sorted(SRC.glob("*.cpp")) + sorted(SRC.glob("*.h")):
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        for line, lineno in logical_lines(text.splitlines()):
            for lit, col in literals_in(line):
                if all(ord(ch) < 0x80 for ch in lit):
                    continue
                if allowed(rel, lineno):
                    continue
                if is_continuation(line, col):
                    continue
                if wrapped_backwards(line, col):
                    continue
                bad.append((rel, lineno, lit.strip()[:60]))

    if bad:
        print("漏包的非 ASCII 字面量（%d 处）：" % len(bad))
        for p, ln, s in bad:
            print("  %s:%d  %s" % (p, ln, s))
        return 1

    n_allow = sum(1 for _ in ALLOW)
    print("通过：未发现漏包的非 ASCII 字面量（另有 %d 段豁免区，见脚本内注释）。" % n_allow)
    return 0


if __name__ == "__main__":
    sys.exit(main())
