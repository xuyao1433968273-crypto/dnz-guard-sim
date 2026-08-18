# -*- coding: utf-8 -*-
"""从 LINE 逐行卷里切出 04-内存映射与隐藏 的 192 个函数章节，合并成参考文件。"""
import csv, os, sys, re

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

BASE = r'D:\CodexWork\ReverseLabV3\teacher_function_by_function_20260813\output'
CSV = os.path.join(BASE, 'all_functions_index_cn.csv')
LINE_DIR = os.path.join(BASE, 'line_by_line_cn')
OUT = r'D:\dnz_guard_sim\engine_ref\teacher_192_reference.md'

with open(CSV, encoding='utf-8-sig', errors='replace') as f:
    rows = list(csv.reader(f))

mem = [r for r in rows[1:] if len(r) > 4 and r[3] == '04-内存映射与隐藏']
print('192 函数:', len(mem))

# 排序：按 ordinal 数字
def ordinal(r):
    try:
        return int(r[0])
    except ValueError:
        return 999999
mem.sort(key=ordinal)

# 每个 ordinal -> 所在卷号: (ordinal-1)//100 + 1
def volume_path(ordinal):
    n = (ordinal - 1) // 100 + 1
    start = (n - 1) * 100 + 1
    fname = 'LINE_%03d_%05d.md' % (n, start)
    return os.path.join(LINE_DIR, fname)

# 预加载卷缓存（按卷号）
vol_cache = {}
def get_volume(ordinal):
    p = volume_path(ordinal)
    if p not in vol_cache:
        with open(p, encoding='utf-8', errors='replace') as f:
            vol_cache[p] = f.read()
    return vol_cache[p]

# 章节切分：每个函数以 '## %05d. `0x...` `name`' 开头
sec_re = re.compile(r'^## (\d{5})\. `(0x[0-9a-fA-F]+)` `([^`]*)`', re.M)

missing = []
out = []
out.append('# 老师 04-内存映射与隐藏 192 函数逐行分析合集\n')
out.append('来源: all_functions_index_cn.csv + line_by_line_cn/LINE_*.md\n')
out.append('(自动提取，用于完整建模参考)\n\n')

for r in mem:
    ordinal, addr, name = int(r[0]), r[1], r[2]
    vol = get_volume(ordinal)
    # 找该序号的章节
    matches = list(sec_re.finditer(vol))
    sec = None
    for i, m in enumerate(matches):
        if int(m.group(1)) == ordinal:
            start = m.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(vol)
            sec = vol[start:end]
            break
    if sec is None:
        missing.append((ordinal, addr, name))
        continue
    out.append(sec)
    out.append('\n---\n')

with open(OUT, 'w', encoding='utf-8') as f:
    f.write(''.join(out))

print('已写出:', OUT)
print('缺失章节:', len(missing))
for x in missing[:30]:
    print('  ', x)
