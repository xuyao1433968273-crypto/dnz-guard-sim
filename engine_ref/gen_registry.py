# -*- coding: utf-8 -*-
"""生成 dnz_registry.c：192 个函数的登记表（链接期验证全覆盖）。"""
import json, sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

DATA = r'D:\dnz_guard_sim\engine_ref\callgraph_192.json'
OUT = r'D:\dnz_guard_sim\engine\dnz_registry.c'

data = json.load(open(DATA, encoding='utf-8'))

lines = []
lines.append('/* dnz_registry.c —— 老师「04-内存映射与隐藏」192 函数登记表')
lines.append(' * 全部 192 个函数按 IDA 序号/地址登记；链接期即可验证每个符号都存在。 */')
lines.append('#include "dnz_types.h"')
lines.append('#include "dnz_ept.h"')
lines.append('#include "dnz_hook.h"')
lines.append('#include "dnz_realvmx.h"')
lines.append('#include "dnz_violation.h"')
lines.append('#include "dnz_dispatch.h"')
lines.append('#include "dnz_hooks.h"')
lines.append('#include "dnz_stubs.h"')
lines.append('#include "dnz_registry.h"')
lines.append('#include "dnz_aliases.h"')
lines.append('')
lines.append('dnz_reg_entry g_dnz_registry[] = {')
for fn in data:
    name = fn['name']
    lines.append(f'    {{ {fn["ord"]}, "{fn["addr"]}", "{name}", "{fn["role"]}", (dnz_any_fn){name} }},')
lines.append('};')
lines.append('')
lines.append('const unsigned g_dnz_registry_count = sizeof(g_dnz_registry) / sizeof(g_dnz_registry[0]);')
lines.append('')

open(OUT, 'w', encoding='utf-8').write('\n'.join(lines))
print('登记表生成:', OUT, '共', len(data), '条')
