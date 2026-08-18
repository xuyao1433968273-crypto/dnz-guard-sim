===== 0x1400669f0
name: sub_1400669F0
--- PSEUDOCODE ---
__int64 __fastcall sub_1400669F0(_QWORD *a1, unsigned __int64 a2)
{
  unsigned __int64 v3; // rcx
  unsigned __int64 v4; // rbx
  unsigned __int64 v5; // rcx
  __int64 v6; // rdi
  __int64 result; // rax
  _QWORD *v8; // rcx
  _QWORD *i; // rdx
  __int64 **v10; // r11
  __int64 *v11; // r10
  __int64 v12; // r8
  __int64 v13; // r10
  _QWORD *v14; // r9
  _QWORD *v15; // r8
  __int64 *v16; // r9
  _QWORD *v17; // r10
  __int64 *v18; // r9
  _QWORD *v19; // r8
  __int64 v20; // r10
  _QWORD *v21; // r9
  _QWORD *v22; // r8

  _BitScanReverse64(&v3, 0xFFFFFFFFFFFFFFFuLL);
  if ( a2 > 1LL << v3 )
  {
    nullsub_3();
    JUMPOUT(0x140066BDELL);
  }
  v4 = a1[1];
  _BitScanReverse64(&v5, (a2 - 1) | 1);
  v6 = 1LL << ((unsigned __int8)v5 + 1);
  sub_140066620((__int64)(a1 + 3), 2 * v6, v4);
  a1[7] = v6;
  result = v6 - 1;
  a1[6] = v6 - 1;
  v8 = *(_QWORD **)a1[1];
  for ( i = v8; i != (_QWORD *)v4; v8 = i )
  {
    i = (_QWORD *)*i;
    result = *((unsigned __int8 *)v8 + 23);
    v10 = (__int64 **)(a1[3]
                     + 16
                     * (a1[6]
                      & (0x100000001B3LL
                       * (result
                        ^ (0x100000001B3LL
                         * (*((unsigned __int8 *)v8 + 22)
                          ^ (0x100000001B3LL
                           * (*((unsigned __int8 *)v8 + 21)
                            ^ (0x100000001B3LL
                             * (*((unsigned __int8 *)v8 + 20)
                              ^ (0x100000001B3LL
                               * (*((unsigned __int8 *)v8 + 19)
                                ^ (0x100000001B3LL
                                 * (*((unsigned __int8 *)v8 + 18)
                                  ^ (0x100000001B3LL
                                   * (*((unsigned __int8 *)v8 + 17)
                                    ^ (0x100000001B3LL * (*((unsigned __int8 *)v8 + 16) ^ 0xCBF29CE484222325uLL))))))))))))))))));
    v11 = *v10;
    if ( *v10 == (__int64 *)v4 )
    {
      *v10 = v8;
      v10[1] = v8;
    }
    else
    {
      result = (__int64)v10[1];
      v12 = v8[2];
      if ( v12 == *(_QWORD *)(result + 16) )
      {
        v13 = *(_QWORD *)result;
        if ( *(_QWORD **)result != v8 )
        {
          v14 = (_QWORD *)v8[1];
          *v14 = i;
          v15 = (_QWORD *)i[1];
          *v15 = v13;
          result = *(_QWORD *)(v13 + 8);
          *(_QWORD *)result = v8;
          *(_QWORD *)(v13 + 8) = v15;
          i[1] = v14;
          v8[1] = result;
        }
        v10[1] = v8;
      }
      else if ( v11 == (__int64 *)result )
      {
LABEL_12:
        v17 = (_QWORD *)v8[1];
        *v17 = i;
        v18 = (__int64 *)i[1];
        *v18 = result;
        v19 = *(_QWORD **)(result + 8);
        *v19 = v8;
        *(_QWORD *)(result + 8) = v18;
        i[1] = v17;
        v8[1] = v19;
        *v10 = v8;
      }
      else
      {
        while ( 1 )
        {
          v16 = *(__int64 **)(result + 8);
          result = (__int64)v16;
          if ( v12 == v16[2] )
            break;
          if ( v11 == v16 )
            goto LABEL_12;
        }
        v20 = *v16;
        v21 = (_QWORD *)v8[1];
        *v21 = i;
        v22 = (_QWORD *)i[1];
        *v22 = v20;
        result = *(_QWORD *)(v20 + 8);
        *(_QWORD *)result = v8;
        *(_QWORD *)(v20 + 8) = v22;
        i[1] = v21;
        v8[1] = result;
      }
    }
  }
  return result;
}


===== 0x1400fd010
name: sub_1400FD010
--- PSEUDOCODE ---
// attributes: thunk
__int64 sub_1400FD010()
{
  return sub_14E7F9315();
}


===== 0x1400ff650
name: sub_1400FF650
--- PSEUDOCODE ---
__int64 __fastcall sub_1400FF650(__int64 a1, unsigned __int64 a2)
{
  __int64 v2; // rbx
  __int64 retaddr; // [rsp+28h] [rbp+0h]

  v2 = *(_QWORD *)a2;
  --*(_QWORD *)(a1 + 8);
  **(_QWORD **)(a2 + 8) = v2;
  *(_QWORD *)(v2 + 8) = *(_QWORD *)(a2 + 8);
  if ( (a2 < (unsigned __int64)&qword_14D2952A0 || a2 >= (unsigned __int64)qword_14DB952A0)
    && (a2 < (unsigned __int64)qword_14027F000 || a2 >= (unsigned __int64)&qword_14827F000) )
  {
    Mem_HeapFreeTracked(a2, retaddr);
    return v2;
  }
  else
  {
    Mem_HeapFreeLocal(a2);
    return v2;
  }
}


===== 0x14011cac0
name: sub_14011CAC0
--- PSEUDOCODE ---
unsigned __int64 __fastcall sub_14011CAC0(__int64 a1, __int64 a2, __int64 a3, unsigned __int64 a4)
{
  unsigned __int64 v4; // rsi
  __int64 v9; // rdx
  char v10; // cl
  __int64 v11; // rax
  unsigned __int64 v12; // rdi
  __int64 v14; // [rsp+30h] [rbp-48h] BYREF
  __int64 v15; // [rsp+38h] [rbp-40h]
  __int64 v16; // [rsp+40h] [rbp-38h]
  __int64 v17; // [rsp+48h] [rbp-30h]
  unsigned __int64 v18; // [rsp+88h] [rbp+10h] BYREF

  v4 = 0;
  if ( a4 != 0 )
  {
    while ( 1 )
    {
      v18 = 0;
      v9 = sub_14011C430(a1, v4 + a2, &v18, a4, &v14);
      if ( (unsigned __int64)(v9 - 1) > 0x7FFFFFFFFFLL )
        return v4;
      v10 = v15;
      v11 = 0x7F8000000000LL;
      if ( (v15 & 0x80u) == 0LL )
      {
        v10 = v16;
        if ( (v16 & 0x80u) == 0LL )
        {
          if ( (v17 & 0x10) != 0 )
          {
            v11 = 0x7E8000000000LL;
          }
          else if ( (v17 & 8) != 0 )
          {
            v11 = 0x7F0000000000LL;
          }
          goto LABEL_15;
        }
        if ( (v16 & 0x10) == 0 )
        {
LABEL_9:
          if ( (v10 & 8) != 0 )
            v11 = 0x7F0000000000LL;
          goto LABEL_15;
        }
        v11 = 0x7E8000000000LL;
      }
      else
      {
        if ( (v15 & 0x10) == 0 )
          goto LABEL_9;
        v11 = 0x7E8000000000LL;
      }
LABEL_15:
      if ( v11 + v9 != 0 )
      {
        v12 = v18;
        if ( a4 - v4 < v18 )
          v12 = a4 - v4;
        Util_Memcpy((char *)(v11 + v9), (char *)(v4 + a3), v12);
        v4 += v12;
        if ( v4 < a4 )
          continue;
      }
      return v4;
    }
  }
  return v4;
}


===== 0x14014fee0
name: sub_14014FEE0
--- PSEUDOCODE ---
__int64 __fastcall sub_14014FEE0(__int64 a1, int a2, _BYTE *a3, int a4)
{
  unsigned int v8; // r10d
  int v9; // r11d
  int v10; // r9d
  __int64 v11; // r8
  int v12; // ecx
  int v13; // edx
  unsigned int v14; // edx
  int v15; // eax
  int v17; // r9d
  __int64 v18; // r11
  int v19; // ecx
  int v20; // edx
  unsigned int v21; // edx
  unsigned int v22; // ecx
  _BYTE *v23; // r8
  __int64 v24; // rbx
  unsigned int v25; // esi
  char v26; // r10
  unsigned int v27; // eax
  __int64 v28; // rdi
  char v29; // al
  unsigned int v30; // ecx
  unsigned int v31; // esi

  if ( a1 == 0 || a2 < 0 )
  {
    if ( a3 != nullptr && a4 > 0 )
      *a3 = 0;
    return 0;
  }
  v8 = 0;
  v9 = 1;
  v10 = 0;
  if ( a2 > 0 )
  {
    v11 = 0;
    do
    {
      v12 = *(unsigned __int16 *)(a1 + 2 * v11);
      if ( (_WORD)v12 == 0 )
        break;
      ++v10;
      if ( (unsigned __int16)v12 < 0xD800u || (unsigned __int16)v12 > 0xDBFFu )
      {
        if ( (unsigned __int16)(v12 + 9216) <= 0x3FFu )
          return 0;
        v14 = *(unsigned __int16 *)(a1 + 2 * v11++);
      }
      else
      {
        if ( v10 >= a2 )
          return 0;
        v13 = *(unsigned __int16 *)(a1 + 2 * v11 + 2);
        if ( (unsigned __int16)(v13 + 9216) > 0x3FFu )
          return 0;
        v14 = (v12 << 10) + v13 - 56613888;
        ++v10;
        v11 += 2;
      }
      if ( v14 > 0x7F )
      {
        if ( v14 > 0x7FF )
        {
          if ( v14 > 0xFFFF )
          {
            if ( v14 > 0x10FFFF )
              return 0;
            v15 = 4;
          }
          else
          {
            v15 = 3;
          }
        }
        else
        {
          v15 = 2;
        }
      }
      else
      {
        v15 = 1;
      }
      if ( v9 > 0x7FFFFFFF - v15 )
        return 0;
      v9 += v15;
    }
    while ( v10 < a2 );
  }
  if ( a3 == nullptr )
    return (unsigned int)v9;
  if ( a4 < v9 )
  {
    if ( a4 > 0 )
      *a3 = 0;
    return 0;
  }
  v17 = 0;
  if ( a2 > 0 )
  {
    v18 = 0;
    do
    {
      v19 = *(unsigned __int16 *)(a1 + 2 * v18);
      if ( (_WORD)v19 == 0 )
        break;
      ++v17;
      if ( (unsigned __int16)v19 < 0xD800u || (unsigned __int16)v19 > 0xDBFFu )
      {
        if ( (unsigned __int16)(v19 + 9216) <= 0x3FFu )
          return 0;
        v21 = *(unsigned __int16 *)(a1 + 2 * v18++);
      }
      else
      {
        if ( v17 >= a2 )
          return 0;
        v20 = *(unsigned __int16 *)(a1 + 2 * v18 + 2);
        if ( (unsigned __int16)(v20 + 9216) > 0x3FFu )
          return 0;
        v21 = (v19 << 10) + v20 - 56613888;
        ++v17;
        v18 += 2;
      }
      v22 = v8 + 1;
      v23 = &a3[v8];
      if ( v21 > 0x7F )
      {
        v24 = (int)v22;
        v25 = v8 + 2;
        v26 = v21 & 0x3F | 0x80;
        v27 = v21 >> 6;
        if ( v21 > 0x7FF )
        {
          v28 = (int)v25;
          v29 = v27 & 0x3F | 0x80;
          v30 = v21 >> 12;
          v31 = v25 + 1;
          if ( v21 > 0xFFFF )
          {
            *v23 = (v21 >> 18) & 7 | 0xF0;
            a3[v24] = v30 & 0x3F | 0x80;
            a3[v28] = v29;
            a3[v31] = v26;
            v8 = v31 + 1;
          }
          else
          {
            *v23 = v30 & 0xF | 0xE0;
            a3[v24] = v29;
            a3[v28] = v26;
            v8 = v31;
          }
        }
        else
        {
          *v23 = v27 & 0x1F | 0xC0;
          a3[v22] = v26;
          v8 = v22 + 1;
        }
      }
      else
      {
        *v23 = v21;
        ++v8;
      }
    }
    while ( v17 < a2 );
  }
  a3[v8] = 0;
  return v8;
}


===== 0x14016b540
name: sub_14016B540
--- PSEUDOCODE ---
__int64 __fastcall sub_14016B540(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v4; // [rsp+48h] [rbp-50h]
  __int64 v5; // [rsp+50h] [rbp-48h]
  unsigned __int64 v6; // [rsp+58h] [rbp-40h]
  _QWORD *v7; // [rsp+60h] [rbp-38h]
  _QWORD *v8; // [rsp+68h] [rbp-30h]

  if ( *(_BYTE *)(g_Sys_ConfigFlags + 216) != 0 )
    return sub_1401196F0(a1, a1, a2, a3, 0, 0, 0, 0, 0, v4);
  else
    return Esp_ApplyGuestProloguePatch(a1, *(_QWORD *)qword_1402707B8, a1, a2, a3, 0, 0, 0, 0, 0, v5, v6, v7, v8);
}


===== 0x140175d20
name: sub_140175D20
--- PSEUDOCODE ---
__int64 __fastcall sub_140175D20(__int64 a1, _BYTE *a2, _WORD *a3)
{
  unsigned __int16 v6; // ax
  unsigned int v7; // ebx
  int *v8; // r14
  unsigned __int64 v9; // rsi
  unsigned __int64 v10; // rdi
  unsigned int v11; // ebp
  __int64 v12; // rcx
  bool v13; // zf
  __int64 v14; // rcx
  __int16 v15; // dx
  unsigned int v16; // ecx
  __int64 v17; // rax
  __int64 v18; // rcx
  __int64 v19; // rcx
  char v20; // cl
  __int64 v21; // rax
  int v23; // [rsp+30h] [rbp-C8h] BYREF
  int v24; // [rsp+34h] [rbp-C4h]
  int v25; // [rsp+38h] [rbp-C0h]
  int v26; // [rsp+40h] [rbp-B8h]
  __int64 v27; // [rsp+48h] [rbp-B0h]
  unsigned __int64 v28; // [rsp+50h] [rbp-A8h]
  __int64 v29; // [rsp+58h] [rbp-A0h]
  int v30; // [rsp+80h] [rbp-78h] BYREF
  int v31; // [rsp+84h] [rbp-74h]
  int v32; // [rsp+88h] [rbp-70h]
  int v33; // [rsp+90h] [rbp-68h]
  unsigned __int64 v34; // [rsp+98h] [rbp-60h]
  unsigned __int64 v35; // [rsp+A0h] [rbp-58h]
  __int64 v36; // [rsp+A8h] [rbp-50h]

  v6 = sub_1401769B0(g_Hook_GuestCr3OrCtx, a1);
  v7 = 0;
  if ( v6 == 0 )
    goto LABEL_41;
  v8 = (int *)g_Hook_GuestCr3OrCtx;
  v9 = a1 + 2;
  v10 = (unsigned __int64)v6 >> 6;
  v11 = v6 >> 6;
  if ( (v6 & 1) != 0 )
  {
    if ( v9 > 0x10000 )
    {
      if ( g_Wddm_DisableOverlay != 0 )
      {
        if ( *(_DWORD *)(g_Hook_GuestCr3OrCtx + 4) != *(_DWORD *)g_Hook_GuestCr3OrCtx )
          goto LABEL_41;
        v14 = *(_QWORD *)(g_Hook_GuestCr3OrCtx + 8);
        if ( v14 == 0 )
          goto LABEL_41;
        v12 = HV_CopyFromGuestVa(v14, v9, 0x14E3B0F50LL, 2 * v10) == 2 * v10;
      }
      else if ( 2 * v10 != 0 && v9 < 0x7FFFFFFFFFFFLL )
      {
        if ( HV_Rdgsbase() != 0 )
        {
          v25 = *v8;
          v29 = 0x14E3B0F50LL;
          v23 = 4;
          v28 = v9;
          v27 = 2 * v10;
          v26 = 0;
          sub_1400FD010(&v23);
          v13 = v24 == 0;
          v8[16] = v24;
          v12 = v13;
        }
        else
        {
          v12 = (unsigned int)sub_1401D6A50((_DWORD)v8, v9, 1312493392, 2 * (int)v10, 0);
        }
      }
      else
      {
        v12 = 0;
      }
      if ( (_DWORD)v12 != 0 )
      {
        if ( *(_DWORD *)(g_Hook_OffsetTable + 272) != 0 )
        {
          if ( MEMORY[0x14E3B0F50] != 0 )
          {
            v15 = MEMORY[0x1482916A8];
            v16 = 0;
            do
            {
              v17 = v16;
              v16 += 2;
              *(_WORD *)(2 * v17 + 0x14E3B0F50LL) ^= v15;
            }
            while ( v16 < v11 );
            *(_WORD *)(2 * v10 + 0x14E3B0F50LL) = 0;
            *a2 = 1;
            *a3 = v10;
            return 0x14E3B0F50LL;
          }
        }
        else
        {
          sub_1401757E0(v12, (unsigned int)v10);
        }
        *(_WORD *)(2 * v10 + 0x14E3B0F50LL) = 0;
        *a2 = 1;
        *a3 = v10;
        return 0x14E3B0F50LL;
      }
    }
LABEL_41:
    MEMORY[0x14E3B0F50] = 0;
    return 0x14E3B0F50LL;
  }
  if ( v9 <= 0x10000 )
    goto LABEL_41;
  if ( g_Wddm_DisableOverlay != 0 )
  {
    if ( *(_DWORD *)(g_Hook_GuestCr3OrCtx + 4) != *(_DWORD *)g_Hook_GuestCr3OrCtx )
      goto LABEL_41;
    v19 = *(_QWORD *)(g_Hook_GuestCr3OrCtx + 8);
    if ( v19 == 0 )
      goto LABEL_41;
    v18 = HV_CopyFromGuestVa(v19, v9, 0x14E3B0F50LL, v10) == v10;
  }
  else if ( v10 != 0 && v9 < 0x7FFFFFFFFFFFLL )
  {
    if ( HV_Rdgsbase() != 0 )
    {
      v32 = *v8;
      v36 = 0x14E3B0F50LL;
      v30 = 4;
      v35 = v9;
      v34 = v10;
      v33 = 0;
      sub_1400FD010(&v30);
      v13 = v31 == 0;
      v8[16] = v31;
      v18 = v13;
    }
    else
    {
      v18 = (unsigned int)sub_1401D6A50((_DWORD)v8, v9, 1312493392, v10, 0);
    }
  }
  else
  {
    v18 = 0;
  }
  if ( (_DWORD)v18 == 0 )
    goto LABEL_41;
  if ( *(_DWORD *)(g_Hook_OffsetTable + 272) != 0 )
  {
    if ( MEMORY[0x14E3B0F50] != 0 )
    {
      v20 = MEMORY[0x1482916A8];
      do
      {
        v21 = v7++;
        *(_BYTE *)(v21 + 0x14E3B0F50LL) ^= v20;
      }
      while ( v7 < v11 );
    }
  }
  else
  {
    sub_140175AA0(v18, (unsigned int)v10);
  }
  *(_BYTE *)(v10 + 0x14E3B0F50LL) = 0;
  *a2 = 0;
  *a3 = v10;
  return 0x14E3B0F50LL;
}


===== 0x1401764f0
name: sub_1401764F0
--- PSEUDOCODE ---
__int64 __fastcall sub_1401764F0(__int64 a1, __int64 a2, unsigned __int8 *a3, _OWORD *a4)
{
  float *v4; // rsi
  _QWORD *v8; // rbp
  unsigned __int64 v9; // r15
  __int64 v10; // rcx
  _QWORD *v11; // rax
  __int64 result; // rax
  char *v13; // rax
  __int64 v14; // rdx
  _QWORD *v15; // rbx
  unsigned __int64 v16; // rdi
  __int64 v17; // rcx
  float v18; // xmm0_4
  float v19; // xmm2_4
  float v20; // xmm0_4
  unsigned __int64 v21; // rcx
  unsigned __int64 v22; // rax
  unsigned __int64 v23; // rcx
  __int64 v24; // rdx
  _QWORD *v25; // rax
  _QWORD *v26; // rdx
  __int64 v27; // rcx
  _QWORD *v28; // rdx
  __int64 v29; // rcx
  __int64 v30; // rax
  _QWORD *v31; // r8
  __int64 retaddr; // [rsp+58h] [rbp+0h]

  v4 = (float *)qword_14828F2F0;
  v8 = *(_QWORD **)(qword_14828F2F0 + 8);
  v9 = 0x100000001B3LL
     * (a3[7]
      ^ (0x100000001B3LL
       * (a3[6]
        ^ (0x100000001B3LL
         * (a3[5]
          ^ (0x100000001B3LL
           * (a3[4]
            ^ (0x100000001B3LL
             * (a3[3]
              ^ (0x100000001B3LL
               * (a3[2] ^ (0x100000001B3LL * (a3[1] ^ (0x100000001B3LL * (*a3 ^ 0xCBF29CE484222325uLL)))))))))))))));
  v10 = *(_QWORD *)(qword_14828F2F0 + 24);
  v11 = *(_QWORD **)(v10 + 16 * (v9 & *(_QWORD *)(qword_14828F2F0 + 48)) + 8);
  if ( v11 != v8 )
  {
    if ( *(_QWORD *)a3 == v11[2] )
    {
LABEL_5:
      *(_QWORD *)a2 = v11;
      *(_BYTE *)(a2 + 8) = 0;
      return a2;
    }
    while ( v11 != *(_QWORD **)(v10 + 16 * (v9 & *(_QWORD *)(qword_14828F2F0 + 48))) )
    {
      v11 = (_QWORD *)v11[1];
      if ( *(_QWORD *)a3 == v11[2] )
        goto LABEL_5;
    }
    v8 = v11;
  }
  if ( *(_QWORD *)(qword_14828F2F0 + 16) == 0x666666666666666LL )
  {
    nullsub_3();
    JUMPOUT(0x14017680ALL);
  }
  v13 = (char *)Mem_HeapAlloc(0x28u);
  v15 = v13;
  if ( v13 == nullptr )
  {
    HV_Dispatch(0x3678656u, 40, retaddr, retaddr - 0x140000000LL, 0);
    __debugbreak();
  }
  *(_OWORD *)v13 = 0;
  *((_OWORD *)v13 + 1) = 0;
  *((_QWORD *)v13 + 4) = 0;
  *((_QWORD *)v13 + 2) = *(_QWORD *)a3;
  *(_OWORD *)(v13 + 24) = *a4;
  v16 = *((_QWORD *)v4 + 7);
  v17 = *((_QWORD *)v4 + 2) + 1LL;
  if ( v17 < 0 )
  {
    v17 &= 1u;
    v18 = (float)(int)(v17 | ((unsigned __int64)(*((_QWORD *)v4 + 2) + 1LL) >> 1))
        + (float)(int)(v17 | ((unsigned __int64)(*((_QWORD *)v4 + 2) + 1LL) >> 1));
  }
  else
  {
    v18 = (float)(int)v17;
  }
  if ( (v16 & 0x8000000000000000uLL) != 0LL )
  {
    v17 = *((_QWORD *)v4 + 7) & 1LL | (v16 >> 1);
    v19 = (float)(int)v17 + (float)(int)v17;
  }
  else
  {
    v19 = (float)(int)v16;
  }
  if ( (float)(v18 / v19) > *v4 )
  {
    v20 = sub_1401E9C60(v17, v14);
    v21 = 0;
    if ( v20 >= 9.223372e18 )
    {
      v20 = v20 - 9.223372e18;
      if ( v20 < 9.223372e18 )
        v21 = 0x8000000000000000uLL;
    }
    v22 = v21 + (unsigned int)(int)v20;
    v23 = 8;
    if ( v22 > 8 )
      v23 = v22;
    if ( v16 < v23 )
    {
      if ( v16 >= 0x200 || (v16 *= 8LL, v16 < v23) )
        v16 = v23;
    }
    sub_1400669F0(v4, v16);
    v24 = *((_QWORD *)v4 + 3);
    v8 = *((_QWORD **)v4 + 1);
    v25 = *(_QWORD **)(v24 + 16 * (v9 & *((_QWORD *)v4 + 6)) + 8);
    if ( v25 != v8 )
    {
      v26 = *(_QWORD **)(v24 + 16 * (v9 & *((_QWORD *)v4 + 6)));
      v27 = v15[2];
      if ( v27 == v25[2] )
      {
LABEL_29:
        v8 = (_QWORD *)*v25;
      }
      else
      {
        while ( v25 != v26 )
        {
          v25 = (_QWORD *)v25[1];
          if ( v27 == v25[2] )
            goto LABEL_29;
        }
        v8 = v25;
      }
    }
  }
  v28 = (_QWORD *)v8[1];
  ++*((_QWORD *)v4 + 2);
  *v15 = v8;
  v15[1] = v28;
  *v28 = v15;
  v8[1] = v15;
  v29 = *((_QWORD *)v4 + 3);
  v30 = 2 * (v9 & *((_QWORD *)v4 + 6));
  v31 = *(_QWORD **)(v29 + 16 * (v9 & *((_QWORD *)v4 + 6)));
  if ( v31 == *((_QWORD **)v4 + 1) )
  {
    *(_QWORD *)(v29 + 16 * (v9 & *((_QWORD *)v4 + 6))) = v15;
LABEL_36:
    *(_QWORD *)(v29 + 8 * v30 + 8) = v15;
    goto LABEL_37;
  }
  if ( v31 == v8 )
  {
    *(_QWORD *)(v29 + 16 * (v9 & *((_QWORD *)v4 + 6))) = v15;
    *(_QWORD *)a2 = v15;
    *(_BYTE *)(a2 + 8) = 1;
    return a2;
  }
  if ( *(_QWORD **)(v29 + 16 * (v9 & *((_QWORD *)v4 + 6)) + 8) == v28 )
    goto LABEL_36;
LABEL_37:
  *(_QWORD *)a2 = v15;
  result = a2;
  *(_BYTE *)(a2 + 8) = 1;
  return result;
}


===== 0x140176810
name: sub_140176810
--- PSEUDOCODE ---
__int64 __fastcall sub_140176810(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 v5; // rdi
  __int64 v6; // r14
  unsigned __int64 v7; // rsi
  __int64 v8; // rax
  unsigned __int64 v9; // rbx
  int v10; // [rsp+24h] [rbp-74h]
  unsigned __int64 v11; // [rsp+A8h] [rbp+10h] BYREF
  __int64 v12; // [rsp+B0h] [rbp+18h] BYREF

  if ( a2 > 0x10000 )
  {
    if ( g_Wddm_DisableOverlay == 0 )
    {
      if ( HV_Rdgsbase() == 0 )
        return sub_140176810(a1, a2);
      v5 = 0;
      if ( a2 < 0x7FFFFFFFFFFFLL )
      {
        v11 = 0;
        sub_1400FD010();
        v5 = v11;
        *(_DWORD *)(a1 + 64) = v10;
      }
      return v5;
    }
    if ( *(_DWORD *)(a1 + 4) == *(_DWORD *)a1 )
    {
      v6 = *(_QWORD *)(a1 + 8);
      if ( v6 != 0 )
      {
        v7 = 0;
        v12 = 0;
        do
        {
          v11 = 0;
          v8 = HV_TranslateGuestVa_Present(v6, v7 + a2, &v11);
          if ( (unsigned __int64)(v8 - 1) > 0x7FFFFFFFFFLL )
            break;
          v9 = v11;
          if ( 8 - v7 < v11 )
            v9 = 8 - v7;
          Util_Memcpy((char *)&v12 + v7, (char *)(v8 + 0x7F8000000000LL), v9);
          v7 += v9;
        }
        while ( v7 < 8 );
        return v12;
      }
    }
  }
  return 0;
}


===== 0x140176b60
name: sub_140176B60
--- PSEUDOCODE ---
__int64 __fastcall sub_140176B60(__int64 a1, __int64 a2, unsigned __int8 *a3, _QWORD *a4)
{
  __int64 v4; // rdi
  __int64 *v8; // rsi
  unsigned __int64 v9; // r15
  __int64 v10; // rcx
  __int64 *v11; // rax
  __int64 result; // rax
  _OWORD *v13; // rax
  _OWORD *v14; // rbx
  __int64 v15; // rcx
  float v16; // xmm0_4
  __int64 v17; // rcx
  float v18; // xmm1_4
  __int64 v19; // rax
  __int64 v20; // rdx
  __int64 *v21; // rax
  __int64 *v22; // rdx
  int v23; // ecx
  _QWORD *v24; // rdx
  __int64 v25; // rcx
  __int64 v26; // rax
  __int64 *v27; // r8
  __int64 retaddr; // [rsp+58h] [rbp+0h]

  v4 = qword_14DB95C98;
  v8 = *(__int64 **)(qword_14DB95C98 + 8);
  v9 = 0x100000001B3LL
     * (a3[3]
      ^ (0x100000001B3LL * (a3[2] ^ (0x100000001B3LL * (a3[1] ^ (0x100000001B3LL * (*a3 ^ 0xCBF29CE484222325uLL)))))));
  v10 = *(_QWORD *)(qword_14DB95C98 + 24);
  v11 = *(__int64 **)(v10 + 16 * (v9 & *(_QWORD *)(qword_14DB95C98 + 48)) + 8);
  if ( v11 != v8 )
  {
    if ( *(_DWORD *)a3 == *((_DWORD *)v11 + 4) )
    {
LABEL_5:
      *(_QWORD *)a2 = v11;
      *(_BYTE *)(a2 + 8) = 0;
      return a2;
    }
    while ( v11 != *(__int64 **)(v10 + 16 * (v9 & *(_QWORD *)(qword_14DB95C98 + 48))) )
    {
      v11 = (__int64 *)v11[1];
      if ( *(_DWORD *)a3 == *((_DWORD *)v11 + 4) )
        goto LABEL_5;
    }
    v8 = v11;
  }
  if ( *(_QWORD *)(qword_14DB95C98 + 16) == 0x7FFFFFFFFFFFFFFLL )
  {
    nullsub_3();
    JUMPOUT(0x140176DC9LL);
  }
  v13 = Mem_HeapAlloc(0x20u);
  v14 = v13;
  if ( v13 == nullptr )
  {
    HV_Dispatch(0x3678656u, 32, retaddr, retaddr - 0x140000000LL, 0);
    __debugbreak();
  }
  *v13 = 0;
  v13[1] = 0;
  *((_DWORD *)v13 + 4) = *(_DWORD *)a3;
  *((_QWORD *)v13 + 3) = *a4;
  v15 = *(_QWORD *)(v4 + 16) + 1LL;
  if ( v15 < 0 )
    v16 = (float)(v15 & 1 | (unsigned int)((unsigned __int64)v15 >> 1))
        + (float)(v15 & 1 | (unsigned int)((unsigned __int64)v15 >> 1));
  else
    v16 = (float)(int)v15;
  v17 = *(_QWORD *)(v4 + 56);
  if ( v17 < 0 )
  {
    v19 = *(_QWORD *)(v4 + 56) & 1LL | (*(_QWORD *)(v4 + 56) >> 1);
    v18 = (float)(int)v19 + (float)(int)v19;
  }
  else
  {
    v18 = (float)(int)v17;
  }
  if ( (float)(v16 / v18) > *(float *)v4 )
  {
    sub_1401772E0(v4);
    v20 = *(_QWORD *)(v4 + 24);
    v8 = *(__int64 **)(v4 + 8);
    v21 = *(__int64 **)(v20 + 16 * (v9 & *(_QWORD *)(v4 + 48)) + 8);
    if ( v21 != v8 )
    {
      v22 = *(__int64 **)(v20 + 16 * (v9 & *(_QWORD *)(v4 + 48)));
      v23 = *((_DWORD *)v14 + 4);
      if ( v23 == *((_DWORD *)v21 + 4) )
      {
LABEL_20:
        v8 = (__int64 *)*v21;
      }
      else
      {
        while ( v21 != v22 )
        {
          v21 = (__int64 *)v21[1];
          if ( v23 == *((_DWORD *)v21 + 4) )
            goto LABEL_20;
        }
        v8 = v21;
      }
    }
  }
  v24 = (_QWORD *)v8[1];
  ++*(_QWORD *)(v4 + 16);
  *(_QWORD *)v14 = v8;
  *((_QWORD *)v14 + 1) = v24;
  *v24 = v14;
  v8[1] = (__int64)v14;
  v25 = *(_QWORD *)(v4 + 24);
  v26 = 2 * (v9 & *(_QWORD *)(v4 + 48));
  v27 = *(__int64 **)(v25 + 16 * (v9 & *(_QWORD *)(v4 + 48)));
  if ( v27 == *(__int64 **)(v4 + 8) )
  {
    *(_QWORD *)(v25 + 16 * (v9 & *(_QWORD *)(v4 + 48))) = v14;
LABEL_27:
    *(_QWORD *)(v25 + 8 * v26 + 8) = v14;
    goto LABEL_28;
  }
  if ( v27 == v8 )
  {
    *(_QWORD *)(v25 + 16 * (v9 & *(_QWORD *)(v4 + 48))) = v14;
    *(_QWORD *)a2 = v14;
    *(_BYTE *)(a2 + 8) = 1;
    return a2;
  }
  if ( *(_QWORD **)(v25 + 16 * (v9 & *(_QWORD *)(v4 + 48)) + 8) == v24 )
    goto LABEL_27;
LABEL_28:
  *(_QWORD *)a2 = v14;
  result = a2;
  *(_BYTE *)(a2 + 8) = 1;
  return result;
}


===== 0x1401772e0
name: sub_1401772E0
--- PSEUDOCODE ---
__int64 __fastcall sub_1401772E0(__int64 a1)
{
  __int64 v1; // rdx
  bool v3; // sf
  __int64 v4; // rdx
  unsigned __int64 v5; // rbx
  float v6; // xmm0_4
  unsigned __int64 v7; // rcx
  unsigned __int64 v8; // rax
  unsigned __int64 v9; // rcx

  v1 = *(_QWORD *)(a1 + 16);
  v3 = v1 + 1 < 0;
  v4 = v1 + 1;
  v5 = *(_QWORD *)(a1 + 56);
  if ( v3 )
    v4 &= 1u;
  v6 = sub_1401E9C60(a1, v4);
  v7 = 0;
  if ( v6 >= 9.223372e18 )
  {
    v6 = v6 - 9.223372e18;
    if ( v6 < 9.223372e18 )
      v7 = 0x8000000000000000uLL;
  }
  v8 = v7 + (unsigned int)(int)v6;
  v9 = 8;
  if ( v8 > 8 )
    v9 = v8;
  if ( v5 < v9 )
  {
    if ( v5 >= 0x200 || (v5 *= 8LL, v5 < v9) )
      v5 = v9;
  }
  return sub_140177620(a1, v5);
}


===== 0x140179340
name: sub_140179340
--- PSEUDOCODE ---
__int64 __fastcall sub_140179340(__int64 a1, __int64 a2)
{
  __int64 v4; // rsi
  int GuestU32; // eax
  __int64 v6; // rcx
  int v7; // eax
  __int64 v8; // rcx
  int GuestU64; // eax
  __int64 v10; // rcx
  int v11; // eax
  __int64 v12; // rcx
  int v13; // eax
  __int64 v14; // rcx
  __int64 v15; // rax
  __int64 v16; // rcx
  __int64 v17; // rax
  __int64 v18; // rcx
  int v19; // eax
  __int64 v20; // rcx
  int v21; // eax
  __int64 v22; // rcx
  int v23; // eax
  __int64 v24; // rcx
  int v25; // eax
  __int64 v26; // rcx
  int v27; // eax
  __int64 v28; // rcx
  int v29; // eax
  __int64 v30; // rcx
  int v31; // eax
  __int64 v32; // rcx
  __int64 v33; // rax
  __int64 v34; // rcx
  __int64 result; // rax
  int v36; // eax
  __int64 v37; // rcx
  int v38; // eax
  __int64 v39; // rcx

  if ( (unsigned int)Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, a1 + 76) == 200
    && (unsigned __int64)((v4 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, a1 + 64)) - 0xFFFF) <= 0x7FFFFFFF0000LL )
  {
    GuestU32 = Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, v4 + 16);
    v6 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 20) = GuestU32;
    v7 = Hv_ReadGuestU32(v6, v4 + 20);
    v8 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 16) = v7;
    GuestU64 = Hv_ReadGuestU64(v8, v4 + 24);
    v10 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 28) = GuestU64;
    v11 = Hv_ReadGuestU32(v10, v4 + 32);
    v12 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 56) = v11;
    v13 = Hv_ReadGuestU32(v12, v4 + 36);
    v14 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 60) = v13;
    v15 = sub_140176810(v14, v4 + 48);
    v16 = g_Hook_GuestCr3OrCtx;
    *(_QWORD *)(a2 + 48) = v15;
    v17 = sub_140176810(v16, v4 + 56);
    v18 = g_Hook_GuestCr3OrCtx;
    *(_QWORD *)(a2 + 32) = v17;
    v19 = Hv_ReadGuestU32(v18, v4 + 68);
    v20 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 24) = v19;
    v21 = Hv_ReadGuestU32(v20, v4 + 80);
    v22 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 80) = v21;
    v23 = Hv_ReadGuestU32(v22, v4 + 84);
    v24 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 72) = v23;
    v25 = Hv_ReadGuestU32(v24, v4 + 88);
    v26 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 64) = v25;
    v27 = Hv_ReadGuestU32(v26, v4 + 92);
    v28 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 84) = v27;
    v29 = Hv_ReadGuestU32(v28, v4 + 96);
    v30 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 76) = v29;
    v31 = Hv_ReadGuestU32(v30, v4 + 100);
    v32 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 68) = v31;
    v33 = sub_140176810(v32, v4 + 120);
    v34 = g_Hook_GuestCr3OrCtx;
    *(_QWORD *)(a2 + 40) = v33;
    result = sub_140176810(v34, v4 + 128);
    *(_DWORD *)(a2 + 12) = result;
    *(_BYTE *)a2 = 1;
  }
  else
  {
    v36 = Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, a1 + 24);
    v37 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 20) = v36;
    v38 = Hv_ReadGuestU32(v37, a1 + 32);
    v39 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 16) = v38;
    result = Hv_ReadGuestU64(v39, a1 + 48);
    *(_DWORD *)(a2 + 28) = result;
    *(_BYTE *)a2 = 1;
  }
  return result;
}


===== 0x14017b030
name: sub_14017B030
--- PSEUDOCODE ---
void __fastcall sub_14017B030(_BYTE *a1, unsigned __int64 a2, unsigned __int64 a3)
{
  unsigned __int64 v3; // rbx
  unsigned __int64 GuestU64; // rsi
  unsigned __int64 v7; // rax
  int v8; // edx
  __int64 v9; // rcx

  if ( a1 != nullptr )
  {
    *a1 = 0;
    v3 = a3;
    if ( a3 - 0xFFFF <= 0x7FFFFFFF0000LL )
    {
      GuestU64 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, a3 + 16);
      v7 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v3 + 24);
      if ( GuestU64 - 1 <= 0xFFF )
      {
        if ( v7 > 0xF )
          v3 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v3);
        if ( v3 - 0xFFFF <= 0x7FFFFFFF0000LL )
        {
          if ( GuestU64 >= a2 )
            GuestU64 = a2 - 1;
          if ( v3 > 0x10000 )
          {
            if ( g_Wddm_DisableOverlay == 0 )
            {
              v8 = sub_1401D6AB0(g_Hook_GuestCr3OrCtx, v3, (_DWORD)a1, GuestU64, 0);
              goto LABEL_15;
            }
            if ( *(_DWORD *)(g_Hook_GuestCr3OrCtx + 4) == *(_DWORD *)g_Hook_GuestCr3OrCtx )
            {
              v9 = *(_QWORD *)(g_Hook_GuestCr3OrCtx + 8);
              if ( v9 != 0 )
              {
                v8 = HV_CopyFromGuestVa(v9, v3, (__int64)a1, GuestU64) == GuestU64;
LABEL_15:
                if ( v8 != 0 )
                {
                  a1[GuestU64] = 0;
                  return;
                }
              }
            }
          }
          *a1 = 0;
        }
      }
    }
  }
}


===== 0x140180a80
name: sub_140180A80
--- PSEUDOCODE ---
__int64 *__fastcall sub_140180A80(__int64 a1, __int64 *a2, unsigned __int8 *a3)
{
  unsigned __int64 v5; // rcx
  __int64 v6; // rax
  __int64 v7; // r8
  __int64 *v8; // rdx
  __int64 v9; // rax
  __int64 v10; // rdx

  v5 = a3[6]
     ^ (0x100000001B3LL
      * (a3[5]
       ^ (0x100000001B3LL
        * (a3[4]
         ^ (0x100000001B3LL
          * (a3[3]
           ^ (0x100000001B3LL * (a3[2] ^ (0x100000001B3LL * (a3[1] ^ (0x100000001B3LL * (*a3 ^ 0xCBF29CE484222325uLL))))))))))));
  v6 = a3[7];
  v7 = qword_14DD8A378;
  v8 = (__int64 *)(qword_14DD8A388 + 16 * (qword_14DD8A3A0 & (0x100000001B3LL * (v6 ^ (0x100000001B3LL * v5)))));
  v9 = v8[1];
  if ( v9 == qword_14DD8A378 )
  {
LABEL_8:
    v9 = 0;
    goto LABEL_9;
  }
  v10 = *v8;
  if ( *(_QWORD *)a3 != *(_QWORD *)(v9 + 16) )
  {
    while ( v9 != v10 )
    {
      v9 = *(_QWORD *)(v9 + 8);
      if ( *(_QWORD *)a3 == *(_QWORD *)(v9 + 16) )
      {
        if ( v9 != 0 )
          v7 = v9;
        *a2 = v7;
        return a2;
      }
    }
    goto LABEL_8;
  }
LABEL_9:
  if ( v9 != 0 )
    v7 = v9;
  *a2 = v7;
  return a2;
}


===== 0x140183b50
name: sub_140183B50
--- PSEUDOCODE ---
unsigned __int64 __fastcall sub_140183B50(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 v2; // rcx
  __int64 v3; // rdi
  unsigned __int64 v4; // rcx
  __int64 v5; // rbx
  unsigned __int64 result; // rax
  __int64 v7; // r9
  __int64 *v8; // rcx
  __int64 *v9; // rdx
  __int64 **v10; // r11
  __int64 *v11; // r10
  __int64 v12; // r8
  __int64 v13; // r10
  __int64 **v14; // r9
  _QWORD *v15; // r8
  __int64 *v16; // r9
  __int64 **v17; // r10
  unsigned __int64 *v18; // r9
  __int64 **v19; // r8
  __int64 v20; // r10
  __int64 **v21; // r9
  _QWORD *v22; // r8

  _BitScanReverse64(&v2, 0xFFFFFFFFFFFFFFFuLL);
  if ( a2 > 1LL << v2 )
  {
    nullsub_3();
    JUMPOUT(0x140183D3CLL);
  }
  v3 = qword_14DD8A2F8;
  _BitScanReverse64(&v4, (a2 - 1) | 1);
  v5 = 1LL << ((unsigned __int8)v4 + 1);
  result = sub_140066620((__int64)&qword_14DD8A308, 2 * v5, qword_14DD8A2F8);
  v7 = v5 - 1;
  qword_14DD8A320 = v5 - 1;
  qword_14DD8A328 = v5;
  v8 = *(__int64 **)qword_14DD8A2F8;
  v9 = *(__int64 **)qword_14DD8A2F8;
  if ( *(_QWORD *)qword_14DD8A2F8 != v3 )
  {
    while ( 1 )
    {
      v9 = (__int64 *)*v9;
      result = *((unsigned __int8 *)v8 + 23);
      v10 = (__int64 **)(qword_14DD8A308
                       + 16
                       * (v7
                        & (0x100000001B3LL
                         * (result
                          ^ (0x100000001B3LL
                           * (*((unsigned __int8 *)v8 + 22)
                            ^ (0x100000001B3LL
                             * (*((unsigned __int8 *)v8 + 21)
                              ^ (0x100000001B3LL
                               * (*((unsigned __int8 *)v8 + 20)
                                ^ (0x100000001B3LL
                                 * (*((unsigned __int8 *)v8 + 19)
                                  ^ (0x100000001B3LL
                                   * (*((unsigned __int8 *)v8 + 18)
                                    ^ (0x100000001B3LL
                                     * (*((unsigned __int8 *)v8 + 17)
                                      ^ (0x100000001B3LL * (*((unsigned __int8 *)v8 + 16) ^ 0xCBF29CE484222325uLL))))))))))))))))));
      v11 = *v10;
      if ( *v10 == (__int64 *)v3 )
      {
        *v10 = v8;
        v10[1] = v8;
      }
      else
      {
        result = (unsigned __int64)v10[1];
        v12 = v8[2];
        if ( v12 == *(_QWORD *)(result + 16) )
        {
          v13 = *(_QWORD *)result;
          if ( *(__int64 **)result != v8 )
          {
            v14 = (__int64 **)v8[1];
            *v14 = v9;
            v15 = (_QWORD *)v9[1];
            *v15 = v13;
            result = *(_QWORD *)(v13 + 8);
            *(_QWORD *)result = v8;
            *(_QWORD *)(v13 + 8) = v15;
            v9[1] = (__int64)v14;
            v8[1] = result;
          }
          v10[1] = v8;
        }
        else if ( v11 == (__int64 *)result )
        {
LABEL_12:
          v17 = (__int64 **)v8[1];
          *v17 = v9;
          v18 = (unsigned __int64 *)v9[1];
          *v18 = result;
          v19 = *(__int64 ***)(result + 8);
          *v19 = v8;
          *(_QWORD *)(result + 8) = v18;
          v9[1] = (__int64)v17;
          v8[1] = (__int64)v19;
          *v10 = v8;
        }
        else
        {
          while ( 1 )
          {
            v16 = *(__int64 **)(result + 8);
            result = (unsigned __int64)v16;
            if ( v12 == v16[2] )
              break;
            if ( v11 == v16 )
              goto LABEL_12;
          }
          v20 = *v16;
          v21 = (__int64 **)v8[1];
          *v21 = v9;
          v22 = (_QWORD *)v9[1];
          *v22 = v20;
          result = *(_QWORD *)(v20 + 8);
          *(_QWORD *)result = v8;
          *(_QWORD *)(v20 + 8) = v22;
          v9[1] = (__int64)v21;
          v8[1] = result;
        }
      }
      v8 = v9;
      if ( v9 == (__int64 *)v3 )
        break;
      v7 = qword_14DD8A320;
    }
  }
  return result;
}


===== 0x1401840f0
name: sub_1401840F0
--- PSEUDOCODE ---
unsigned __int64 __fastcall sub_1401840F0(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 v2; // rcx
  __int64 v3; // rdi
  unsigned __int64 v4; // rcx
  __int64 v5; // rbx
  unsigned __int64 result; // rax
  __int64 v7; // r9
  __int64 *v8; // rcx
  __int64 *v9; // rdx
  __int64 **v10; // r11
  __int64 *v11; // r10
  __int64 v12; // r8
  __int64 v13; // r10
  __int64 **v14; // r9
  _QWORD *v15; // r8
  __int64 *v16; // r9
  __int64 **v17; // r10
  unsigned __int64 *v18; // r9
  __int64 **v19; // r8
  __int64 v20; // r10
  __int64 **v21; // r9
  _QWORD *v22; // r8

  _BitScanReverse64(&v2, 0xFFFFFFFFFFFFFFFuLL);
  if ( a2 > 1LL << v2 )
  {
    nullsub_3();
    JUMPOUT(0x1401842DCLL);
  }
  v3 = qword_14DD8A378;
  _BitScanReverse64(&v4, (a2 - 1) | 1);
  v5 = 1LL << ((unsigned __int8)v4 + 1);
  result = sub_140066620((__int64)&qword_14DD8A388, 2 * v5, qword_14DD8A378);
  v7 = v5 - 1;
  qword_14DD8A3A0 = v5 - 1;
  qword_14DD8A3A8 = v5;
  v8 = *(__int64 **)qword_14DD8A378;
  v9 = *(__int64 **)qword_14DD8A378;
  if ( *(_QWORD *)qword_14DD8A378 != v3 )
  {
    while ( 1 )
    {
      v9 = (__int64 *)*v9;
      result = *((unsigned __int8 *)v8 + 23);
      v10 = (__int64 **)(qword_14DD8A388
                       + 16
                       * (v7
                        & (0x100000001B3LL
                         * (result
                          ^ (0x100000001B3LL
                           * (*((unsigned __int8 *)v8 + 22)
                            ^ (0x100000001B3LL
                             * (*((unsigned __int8 *)v8 + 21)
                              ^ (0x100000001B3LL
                               * (*((unsigned __int8 *)v8 + 20)
                                ^ (0x100000001B3LL
                                 * (*((unsigned __int8 *)v8 + 19)
                                  ^ (0x100000001B3LL
                                   * (*((unsigned __int8 *)v8 + 18)
                                    ^ (0x100000001B3LL
                                     * (*((unsigned __int8 *)v8 + 17)
                                      ^ (0x100000001B3LL * (*((unsigned __int8 *)v8 + 16) ^ 0xCBF29CE484222325uLL))))))))))))))))));
      v11 = *v10;
      if ( *v10 == (__int64 *)v3 )
      {
        *v10 = v8;
        v10[1] = v8;
      }
      else
      {
        result = (unsigned __int64)v10[1];
        v12 = v8[2];
        if ( v12 == *(_QWORD *)(result + 16) )
        {
          v13 = *(_QWORD *)result;
          if ( *(__int64 **)result != v8 )
          {
            v14 = (__int64 **)v8[1];
            *v14 = v9;
            v15 = (_QWORD *)v9[1];
            *v15 = v13;
            result = *(_QWORD *)(v13 + 8);
            *(_QWORD *)result = v8;
            *(_QWORD *)(v13 + 8) = v15;
            v9[1] = (__int64)v14;
            v8[1] = result;
          }
          v10[1] = v8;
        }
        else if ( v11 == (__int64 *)result )
        {
LABEL_12:
          v17 = (__int64 **)v8[1];
          *v17 = v9;
          v18 = (unsigned __int64 *)v9[1];
          *v18 = result;
          v19 = *(__int64 ***)(result + 8);
          *v19 = v8;
          *(_QWORD *)(result + 8) = v18;
          v9[1] = (__int64)v17;
          v8[1] = (__int64)v19;
          *v10 = v8;
        }
        else
        {
          while ( 1 )
          {
            v16 = *(__int64 **)(result + 8);
            result = (unsigned __int64)v16;
            if ( v12 == v16[2] )
              break;
            if ( v11 == v16 )
              goto LABEL_12;
          }
          v20 = *v16;
          v21 = (__int64 **)v8[1];
          *v21 = v9;
          v22 = (_QWORD *)v9[1];
          *v22 = v20;
          result = *(_QWORD *)(v20 + 8);
          *(_QWORD *)result = v8;
          *(_QWORD *)(v20 + 8) = v22;
          v9[1] = (__int64)v21;
          v8[1] = result;
        }
      }
      v8 = v9;
      if ( v9 == (__int64 *)v3 )
        break;
      v7 = qword_14DD8A3A0;
    }
  }
  return result;
}


===== 0x1401843b0
name: sub_1401843B0
--- PSEUDOCODE ---
unsigned __int64 sub_1401843B0()
{
  void *v0; // rax
  void *v1; // rbx
  unsigned __int64 result; // rax
  __int64 retaddr; // [rsp+38h] [rbp+0h]

  v0 = Mem_HeapAlloc(0x54AFu);
  v1 = v0;
  if ( v0 == nullptr )
  {
    HV_Dispatch(0x3678656u, 21679, retaddr, retaddr - 0x140000000LL, 0);
    JUMPOUT(0x140184420LL);
  }
  Util_Memset((__int64)v0, 0, 21679);
  result = ((unsigned __int64)v1 + 39) & 0xFFFFFFFFFFFFFFE0uLL;
  *(_QWORD *)(result - 8) = v1;
  return result;
}


===== 0x1401d6a50
name: sub_1401D6A50
--- PSEUDOCODE ---
__int64 __fastcall sub_1401D6A50(
        __int64 a1,
        unsigned __int64 a2,
        __int64 a3,
        unsigned __int64 a4,
        unsigned __int64 *a5)
{
  __int64 v7; // rcx
  unsigned __int64 v8; // rcx

  if ( a2 <= 0x10000 )
    return 0;
  if ( g_Wddm_DisableOverlay == 0 )
    return sub_1401D6AB0(a1, a2, a3, a4, (__int64)a5);
  if ( *(_DWORD *)(a1 + 4) != *(_DWORD *)a1 )
    return 0;
  v7 = *(_QWORD *)(a1 + 8);
  if ( v7 == 0 )
    return 0;
  v8 = HV_CopyFromGuestVa(v7, a2, a3, a4);
  if ( a5 != nullptr )
    *a5 = v8;
  return v8 == a4;
}


===== 0x1401e9c60
name: sub_1401E9C60
--- PSEUDOCODE ---
// attributes: thunk
float __fastcall sub_1401E9C60(float result)
{
  return sub_140138BE0(result);
}


