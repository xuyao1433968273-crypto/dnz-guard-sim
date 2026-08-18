#pragma once
#include "dnz_types.h"

/* 192 函数登记表条目（dnz_registry.c 由 gen_registry.py 生成） */
typedef uint64_t (*dnz_any_fn)(void);

typedef struct {
    unsigned    ord;
    const char *addr;
    const char *name;
    const char *role;
    dnz_any_fn  fn;
} dnz_reg_entry;

extern dnz_reg_entry  g_dnz_registry[];
extern const unsigned g_dnz_registry_count;
