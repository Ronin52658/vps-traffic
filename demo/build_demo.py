#!/usr/bin/env python3
"""从正式版 index.html 生成演示站 demo.html（单文件，无需后端）
用法：python3 demo/build_demo.py  → 输出 demo/demo.html
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "..", "index.html"), encoding="utf-8").read()
mock = open(os.path.join(HERE, "mock.js"), encoding="utf-8").read()


def rep(old, new):
    global src
    if src.count(old) != 1:
        raise SystemExit(f"找不到唯一的替换点：{old[:50]!r}")
    src = src.replace(old, new)


rep("<title>VPS 流量</title>", "<title>VPS 流量面板演示</title>")

# 安全区域留白（发布页面要求）；深色模式由页面里的主题脚本处理，也会读取查看器的 data-theme
rep("*{box-sizing:border-box}", """*{box-sizing:border-box}
:root{box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}
html{scroll-padding-top:env(safe-area-inset-top,0px)}
.demo-note{font-size:13px;color:var(--muted);border-radius:14px;box-shadow:var(--inset-sm);padding:10px 14px;margin:0 0 18px}""")
rep("  padding:env(safe-area-inset-top,0px) env(safe-area-inset-right,0px) env(safe-area-inset-bottom,0px) env(safe-area-inset-left,0px);\n",
    "  padding:0 env(safe-area-inset-right,0px) 0 env(safe-area-inset-left,0px);\n")

# 提示文字
rep('<div id="mainView" class="wrap" hidden>',
    '<div id="mainView" class="wrap" hidden>\n  <p class="demo-note">这是演示站，数据为模拟并会实时增长。新增、修改、重置都只在本页生效，刷新后恢复原状。</p>')
rep('<p class="hint" style="margin-bottom:18px">请输入面板密码</p>',
    '<p class="hint" style="margin-bottom:18px">请输入面板密码（演示密码：demo）</p>')
rep("会用备份文件<b>完全替换</b>当前所有数据。",
    "演示站只检查文件格式，不会真的替换数据。正式版会用备份文件<b>完全替换</b>当前所有数据。")


# 国旗：演示站不能从 /flags 加载图片，把常用的几面内嵌成 data URI
import base64
FLAG_CODES = "HK JP US SG DE KR TW CN GB FR NL CA".split()
flag_data = {c: "data:image/png;base64," + base64.b64encode(open(os.path.join(HERE, "..", "flags", c.lower() + ".png"), "rb").read()).decode()
             for c in FLAG_CODES}
import json
rep("const flagSrc = cc => `/flags/${cc.toLowerCase()}.png`;",
    "const FLAG_DATA = " + json.dumps(flag_data) + ";\nconst flagSrc = cc => FLAG_DATA[cc] || \"data:,\";")

# 网站图标：演示站没有后端，SVG 图标内嵌成 data URI，其余图标链接去掉
svg = open(os.path.join(HERE, "..", "icons", "favicon.svg"), "rb").read()
rep('<link rel="icon" href="/favicon.svg" type="image/svg+xml">',
    '<link rel="icon" href="data:image/svg+xml;base64,' + base64.b64encode(svg).decode() + '" type="image/svg+xml">')
for line in ('<link rel="icon" href="/favicon.ico" sizes="48x48">\n', '<link rel="apple-touch-icon" href="/apple-touch-icon.png">\n',
             '<link rel="manifest" href="/manifest.webmanifest">\n'):
    rep(line, "")

# 注入模拟后端
rep("<script>\nconst $ =", f"<script>\n{mock}\n</script>\n<script>\nconst $ =")

out = os.path.join(HERE, "demo.html")
open(out, "w", encoding="utf-8").write(src)
print(f"已生成 {out}（{len(src.encode()) // 1024} KB）")
