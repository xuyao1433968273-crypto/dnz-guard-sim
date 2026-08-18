# -*- coding: utf-8 -*-
"""解析 teacher_192_reference.md 的调用关系，输出紧凑 JSON。"""
import re, json, sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

REF = r'D:\dnz_guard_sim\engine_ref\teacher_192_reference.md'
OUT = r'D:\dnz_guard_sim\engine_ref\callgraph_192.json'

txt = open(REF, encoding='utf-8').read()
secs = re.split(r'(?=^## \d{5}\. )', txt, flags=re.M)

data = []
for s in secs:
    m = re.match(r'## (\d{5})\. `(0x[0-9a-fA-F]+)` `([^`]*)`', s)
    if not m:
        continue
    ord_, addr, name = m.group(1), m.group(2), m.group(3)
    role_m = re.search(r'当前作用判断：([^。]+)', s)
    size_m = re.search(r'函数大小：(\d+)', s)
    role = role_m.group(1).strip() if role_m else ''
    size = int(size_m.group(1)) if size_m else 0

    callers, callees = [], []
    cm = re.search(r'谁叫它：(.*)', s)
    if cm:
        callers = [x.strip() for x in cm.group(1).split('、') if x.strip()]
    km = re.search(r'它叫谁：(.*)', s)
    if km:
        callees = [x.strip() for x in km.group(1).split('→') if x.strip()]

    # 关键魔数/调用行（用于给桩写真实内容）
    keylines = []
    for ln in s.splitlines():
        if '原码：' in ln:
            code = ln.split('原码：', 1)[1].strip()
            if any(k in code for k in ('HV_', 'g_Hv', 'g_Hook', 'sub_', '0x', '_Interlocked', 'memset', 'Mem_', '//')):
                keylines.append(code)

    data.append({
        'ord': int(ord_), 'addr': addr, 'name': name, 'role': role,
        'size': size, 'callers': callers[:8], 'callees': callees[:8],
        'key': keylines[:12],
    })

with open(OUT, 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=1)
print('写出', len(data), '条 ->', OUT)
