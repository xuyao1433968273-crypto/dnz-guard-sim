/*++
 * dnz_teacher.h — 老师 8 个子函数（sub_140168A70 / sub_140176310 / sub_140179540 /
 * sub_140179790 / sub_14017BAF0 / sub_140187B90 / sub_140187E60 / sub_1401881D0）
 * 逐行还原所需的全局状态与接口。
 *
 * 所有全局变量按老师 IDA 原样建模：
 *   g_Hook_NtosOffsetsCtx + 1592/1840/1896/1900/1928/1984/2000/2130
 *   g_Hook_OffsetTable + 16/20/32/36/116/124/132/136/160/168/176/252/268/272/
 *     476/504/552/556/560/640/644/788/792/796/800/804/1072/1076/1080
 *     （在 DNZ_HOOK_CONTEXT.OffsetTable，UINT32 数组，字节偏移 /4 = 槽）
 *   g_Sys_ConfigFlags + 218/219/220/221/228/232/236/240/377/378/629/630/640/660/849
 *   unk_14DD8A1A0 / MEMORY[0x14E3AF258..264] / MEMORY[0x14DD921E0/EC]（自瞄状态）
 *   qword_14DB95C98（进程名 FNV 哈希表）/ qword_14828F380（事件队列）/
 *   qword_14828F388（事件状态表）/ qword_14828F308（PID 状态表）/
 *   qword_14DD8A2F8 / qword_14DD8A378（实体表 0/1）/
 *   qword_14828F2F0（指针翻译缓存）
 *
 * 唯一偏差（文档化）：
 *   - 老师的 Mem_HeapAlloc / 桶扩容（sub_1400669F0 等）在 root 模式 MAX_IRQL 下
 *     不可用，这里用静态节点池 + 固定 64 桶代替；节点布局（+0 prev / +8 next /
 *     +16 key / +24 data）与 FNV-1a 哈希原样保留。
 *   - g_Wddm_DisableOverlay 置 1：走直接页表走查路径（= 我们的 Hv_* 原语），
 *     老师那套 GS-base overlay 加速（sub_1400FD010 / HV_Rdgsbase）不移植。
 *   - sub_14016B540 的 Esp_ApplyGuestProloguePatch 未移植（返回原地址）。
 * --*/

#pragma once
#include <ntddk.h>
#include "dnz_heap.h"

/* ================= FNV-1a 常量（老师原样） ================= */

#define DNZ_FNV_BASIS  0xCBF29CE484222325ULL
#define DNZ_FNV_PRIME  0x100000001B3ULL

/* ================= 老师哈希链表（桶数组 + 哨兵，节点布局原样） =================
 * 桶项 = 16 字节：+0 = 链尾，+8 = 链头（空桶两者都是哨兵）。
 * 查找从链头出发沿 Next 走，直到回到链尾。 */

#define DNZ_TLIST_BUCKETS 64

typedef struct _DNZ_TLIST {
    volatile LONG Lock;          /* 自旋锁（对应 qword_14DB95CB8/CA0/CC0/CF8 等） */
    UINT64         Sentinel;     /* 哨兵节点地址（指向 SentinelBuf） */
    UINT64         SentinelBuf[2]; /* 哨兵 +0 prev / +8 next */
    UINT64         Count;        /* 节点数 */
    UINT64         Mask;         /* 桶掩码（63） */
    UINT64         LoadFactor;   /* 加载因子 float 位模式（0x3F800000 = 1.0f） */
    UINT64         BucketNext[DNZ_TLIST_BUCKETS];  /* 桶项 +0（链尾） */
    UINT64         BucketPrev[DNZ_TLIST_BUCKETS];  /* 桶项 +8（链头） */
} DNZ_TLIST, *PDNZ_TLIST;

/* ================= 自瞄状态（sub_140168A70 用） ================= */

typedef struct _DNZ_AIM_STATE {
    float   Target[3];      /* unk_14DD8A1A0：目标坐标（x,y,z） */
    float   Vector[3];      /* MEMORY[0x14E3AF258..260]：归一化方向 */
    UINT32  VectorFlag;     /* MEMORY[0x14E3AF264]：方向已初始化标志 */
    UINT32  Spin[2];        /* MEMORY[0x14DD921E0/EC]：旋转状态（0..4） */
    volatile LONG Counter0; /* dword_140270230 */
    volatile LONG Counter1; /* dword_14027022C */
    volatile LONG Counter2; /* dword_140270234（当前武器编号） */
    UINT64  ReadPtr;        /* qword_1402707A8：当前准星读取位置 */
    UINT64  BasePtr;        /* qword_1402707C8：自瞄基址 */
    UINT8   FlagB4;         /* byte_14026E0B4 */
    UINT8   FlagB5;         /* byte_14026E0B5 */
} DNZ_AIM_STATE;

/* ================= 老师子函数全部全局状态 ================= */

typedef struct _DNZ_TEACHER_STATE {
    /* g_Sys_ConfigFlags：字节标志（+218/+219/+220/+221/+228/+232/+236/+240/
     * +377/+378/+629/+630/+640/+660/+849） */
    UINT8 ConfigFlags[1024];

    /* g_Hook_NtosOffsetsCtx 的扩展槽 */
    UINT64 NtosBase;      /* +1592：游戏/模块基址 */
    UINT64 Ntos1840;      /* +1840 */
    UINT32 Ntos1896;      /* +1896 */
    UINT32 Ntos1900;      /* +1900 */
    UINT64 Ntos1928;      /* +1928 */
    UINT32 Ntos1984;      /* +1984：当前登记的武器/进程编号 */
    UINT32 Ntos2000;      /* +2000：sub_1401687E0 找到的指令偏移缓存 */
    UINT8  Ntos2130;      /* +2130：sub_1401755B0 的翻译缓存开关 */

    /* 近期读到的 guest 值 */
    UINT64 LastRead0;     /* qword_14DB95CE8 */
    UINT64 LastRead1;     /* qword_14DB95CF0 */
    UINT64 LastRead2;     /* qword_14DB95D00 */
    UINT8  Flag3D4;       /* byte_14828F3D4 */
    UINT8  Flag3D5;       /* byte_14828F3D5 */

    /* 计数器（老师 dword_14026xxx / dword_140270xxx） */
    volatile LONG CntC02C;   /* dword_14026C02C */
    volatile LONG CntC030;   /* dword_14026C030 */
    volatile LONG CntC034;   /* dword_14026C034 */
    volatile LONG CntC040;   /* dword_14026C040 */
    volatile LONG CntC044;   /* dword_14026C044 */
    volatile LONG CntBF68;   /* dword_14026BF68 */
    volatile LONG CntBF6C;   /* dword_14026BF6C */
    volatile LONG CntBF70;   /* dword_14026BF70 */
    volatile LONG CntBF74;   /* dword_14026BF74 */
    volatile LONG CntV0228;  /* dword_140270228 */
    volatile LONG LogCount;  /* qword_14DB95CD0：日志计数 */
    UINT32 LogEnable;        /* qword_14DD8A2C0 */

    /* 自旋锁（老师 qword_14DB95xxx） */
    volatile LONG LockList;    /* qword_14DB95CB0：ListHook/日志 */
    volatile LONG LockPid;     /* qword_14DB95CB8：PID 状态表 */
    volatile LONG LockEntity;  /* qword_14DB95CA0：实体表 1 */
    volatile LONG LockDetail;  /* qword_14DB95CC0：DetailHook/ListHook 流程 */
    volatile LONG LockEvent;   /* qword_14DB95CF8：事件队列/状态表 */

    /* 自瞄状态 */
    DNZ_AIM_STATE Aim;

    /* 进程名 FNV 哈希表（qword_14DB95C98）：节点 = 0x20 字节，
     * +0 prev / +8 next / +16 DWORD pid / +24 QWORD 名字哈希 */
    DNZ_TLIST  NameList;

    /* 事件队列（qword_14828F380）：节点 = 0x28 字节，
     * +0 prev / +8 next / +16 QWORD key / +24 QWORD data0 / +32 DWORD data1 */
    DNZ_TLIST  EventQueue;

    /* 事件状态表（qword_14828F388）：节点布局同事件队列 */
    DNZ_TLIST  EventState;

    /* PID 状态表（qword_14828F308）：节点 = 0x20 字节，
     * +0 prev / +8 next / +16 DWORD pid / +24 QWORD data */
    DNZ_TLIST  PidState;

    /* 指针翻译缓存（qword_14828F2C8 桶 / qword_14828F2E0 掩码 / qword_14828F2B8 哨兵，
     * sub_1401755B0 / sub_140175230 用）：节点 = 0x28 字节，
     * +0 prev / +8 next / +16 QWORD key / +24 QWORD data0 / +32 QWORD data1 */
    DNZ_TLIST  XlateCache;
    volatile LONGLONG XlateCounter;  /* qword_14DB95C90：翻译缓存引用计数/独占锁（0=空闲，-1=独占，>0=引用） */

    /* 实体表 1（qword_14DD8A378）：节点 = 0x70 字节，
     * +0 prev / +8 next / +16 QWORD key / +24 data[80] */
    DNZ_TLIST  Entity1;

    /* 实体表 0（qword_14DD8A2F8）：节点 = 24 + 21616 字节（1080 字节 × 20 槽） */
    DNZ_TLIST  Entity0;

    /* sub_140176080 的进程名字符串静态缓冲（0x14DD92210，4096 字节） */
    UINT8      NameBuf[4096];

    /* sub_140175D20 的 UTF-16/字节静态缓冲（0x14E3B0F50）+ 解密开关
     * （MEMORY[0x1482916A8]；g_Hook_OffsetTable+272 非 0 时启用） */
    UINT8      Utf16Buf[512];
    UINT16     Utf16Key;

    /* 注：老师的 g_Wddm_DisableOverlay 是 ESP 外接屏/overlay 渲染子系统
     * （Esp_CollectGuestDxState 等，属于"透视/外接屏"功能模块）的开关，
     * 不在本模块（认人+翻镜子+偏移表分派）范围内——见 README 偏差说明。 */
} DNZ_TEACHER_STATE, *PDNZ_TEACHER_STATE;

extern DNZ_TEACHER_STATE g_TState;

/* ================= 8 个子函数（a2 = guest 寄存器帧 = CONTEXT，a2[N] = CONTEXT 偏移 N*8） ================= */

/* sub_140168A70：自瞄（+2024）—— 归一化方向 + 写回 guest 准星 */
UINT64
DnzSub_140168A70(
    _In_ UINT64* A2
    );

/* sub_140176310：进程名 FNV 哈希查找/缓存（+2032 分支内部） */
UINT64
DnzSub_140176310(
    _In_ UINT64 A1
    );

/* sub_140179540：实体表 1 更新（+2048） */
UINT64
DnzSub_140179540(
    _In_ UINT64* A2
    );

/* sub_140179790：实体表 1 更新 + 击杀信息（+2056） */
UINT64
DnzSub_140179790(
    _In_ UINT64* A2
    );

/* sub_14017BAF0：DetailHook 处理（+2072） */
UINT64
DnzSub_14017BAF0(
    _In_ UINT64* A2
    );

/* sub_140187B90：条件跳转模拟（+1960，按 EFlags.ZF 前移 22 或 2 字节） */
UINT64
DnzSub_140187B90(
    _In_ UINT64* A2
    );

/* sub_140187E60：登记事件 + 武器编号检查（+1968） */
VOID
DnzSub_140187E60(
    _In_ UINT64* A2
    );

/* sub_1401881D0：事件状态表查找 + 击杀计数写入（+1976） */
UINT64
DnzSub_1401881D0(
    _In_ UINT64* A2
    );

/* 初始化全部老师状态（DnzHookInit 里调） */
VOID
DnzTeacherInit(
    VOID
    );

/* ================= 供分派（dnz_hook.c）调用的导出 helper ================= */

/* Hook_LookupByPid（ACE_LookupListHookByPid）：ListHook 链表 find + 拷 24 字节 + 删节点 */
UINT8
DnzHookLookupRemoveByPid(
    _In_ UINT32 Pid,
    _Out_ PUINT64 Out24
    );

/* Hook_LogListEntry（老师原样：计数 + 探测性 guest 读，不产生输出） */
VOID
DnzHookLogListEntry(
    _In_ const char* Name,
    _In_ UINT32 Pid,
    _In_ UINT64 A3
    );

/* sub_140180D20：实体表 0 find-or-insert（Out[0] = 节点，Out[1] = 新插入标志） */
VOID
DnzSub_140180D20(
    _Out_ PUINT64 Out,
    _In_  UINT64 Key
    );

/* sub_1401944D0：配置检查（FNV 哈希黑名单 switch，原样还原） */
UINT8
DnzSub_1401944D0(
    _In_ UINT64 A1
    );

/* sub_140175230：翻译缓存 find-or-insert（qword_14DB95C90 计数保护；命中更新
 * +24/+32 data，未命中走独占锁插入。a2 = 16 字节 data：+0 data0 / +8 dword data1） */
UINT64
DnzSub_140175230(
    _In_ UINT64 Key,
    _In_ const UINT64* Data16
    );

/* sub_14017B160：EPROCESS 摘要填充（a1 = guest EPROCESS，a2 = 344 字节输出） */
VOID
DnzSub_14017B160(
    _In_ UINT64 A1,
    _In_ UINT64 A2
    );

/* ACE_ReadProcessListFromGuest：读 guest 进程列表（a1 = 列表头，a2 = 输出缓冲：
 * 头 16 字节 + 1080 字节 × 20 条目） */
VOID
Hv_ReadProcessListFromGuest(
    _In_ UINT64 A1,
    _In_ UINT64 A2
    );
