===== sub_140168A70 start=0x140168a70 end=0x140169076 size=1542 proto=__int64 __fastcall(_QWORD *)
comment: 
repeatable_comment: 
callers: [{"ea": "0x1401906e0", "name": "Hook_NtApi_VmExitHandler"}]
callees: [{"ea": "0x14015d100", "name": "Hv_WriteGuestU64"}, {"ea": "0x14015d5c0", "name": "Hv_ReadGuestU64"}, {"ea": "0x14015d900", "name": "Hv_ReadGuestBytes"}, {"ea": "0x140166d10", "name": "sub_140166D10"}, {"ea": "0x1401687e0", "name": "sub_1401687E0"}, {"ea": "0x140168a70", "name": "sub_140168A70"}, {"ea": "0x14016b1c0", "name": "sub_14016B1C0"}, {"ea": "0x14016b300", "name": "sub_14016B300"}, {"ea": "0x14016b410", "name": "sub_14016B410"}]
strings: []
--- PSEUDOCODE ---
__int64 __fastcall sub_140168A70(_QWORD *a1)
{
  __int64 result; // rax
  __int64 GuestU64; // r12
  unsigned __int64 v4; // rdx
  int v5; // esi
  unsigned int v6; // r15d
  bool v7; // cl
  bool v8; // r13
  __int64 v9; // r8
  float v10; // xmm2_4
  __int64 v11; // rcx
  __int64 v12; // rdx
  __int64 v13; // rbx
  __int64 v14; // rdi
  __int64 v15; // r8
  unsigned __int64 v16; // xmm6_8
  __int64 v17; // rax
  __int64 v18; // rax
  int v19; // r8d
  unsigned int v20; // ecx
  __int64 v21; // r8
  float v22; // xmm2_4
  __int64 v23; // rcx
  __int64 v24; // rdx
  __int64 v25; // rbx
  __int64 v26; // rdi
  __int64 v27; // r8
  unsigned __int64 v28; // xmm6_8
  float v29; // [rsp+20h] [rbp-19h] BYREF
  float v30; // [rsp+24h] [rbp-15h]
  float v31; // [rsp+28h] [rbp-11h]
  __int64 v32; // [rsp+30h] [rbp-9h] BYREF
  float v33; // [rsp+38h] [rbp-1h]
  float v34; // [rsp+40h] [rbp+7h] BYREF
  float v35; // [rsp+44h] [rbp+Bh]
  float v36; // [rsp+48h] [rbp+Fh]
  unsigned __int64 v37; // [rsp+50h] [rbp+17h] BYREF
  int v38; // [rsp+58h] [rbp+1Fh]
  bool v39; // [rsp+A0h] [rbp+67h]

  result = Hv_WriteGuestU64((int *)g_Hook_GuestCr3OrCtx, a1[19] + 16LL, a1[17]);
  a1[31] += 5LL;
  if ( *(float *)&unk_14DD8A1A0 != 0.0 || *((float *)&unk_14DD8A1A0 + 1) != 0.0 || *(float *)&MEMORY[0x14DD8A1A8] != 0.0 )
  {
    result = sub_140166D10(g_Hook_GuestCr3OrCtx, &v37, a1[17]);
    if ( v37 != 0 && v38 > 0 )
    {
      if ( (MEMORY[0x14E3AF264] & 1) == 0 )
      {
        MEMORY[0x14E3AF258] = 0;
        MEMORY[0x14E3AF264] |= 1u;
        MEMORY[0x14E3AF260] = 0;
      }
      GuestU64 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, a1[19]);
      v4 = GuestU64 - *(_QWORD *)(g_Hook_NtosOffsetsCtx + 1592);
      byte_14026E0B4 = v4 >= 0x18000000;
      v5 = 0;
      if ( v4 < 0x18000000 )
      {
        Hv_ReadGuestBytes(g_Hook_GuestCr3OrCtx, (__int64)&v34, qword_1402707A8);
        v21 = g_Hook_OffsetTable;
        v22 = 1.0
            / fsqrt(
                (float)((float)((float)(*((float *)&unk_14DD8A1A0 + 1) - v35)
                              * (float)(*((float *)&unk_14DD8A1A0 + 1) - v35))
                      + (float)((float)(*(float *)&unk_14DD8A1A0 - v34) * (float)(*(float *)&unk_14DD8A1A0 - v34)))
              + (float)((float)(*(float *)&MEMORY[0x14DD8A1A8] - v36) * (float)(*(float *)&MEMORY[0x14DD8A1A8] - v36)));
        MEMORY[0x14E3AF258] = v22 * (float)(*(float *)&unk_14DD8A1A0 - v34);
        MEMORY[0x14E3AF25C] = v22 * (float)(*((float *)&unk_14DD8A1A0 + 1) - v35);
        MEMORY[0x14E3AF260] = v22 * (float)(*(float *)&MEMORY[0x14DD8A1A8] - v36);
        v23 = *(unsigned int *)(g_Hook_OffsetTable + 796);
        v24 = a1[16];
        v25 = v24 + v23 + *(unsigned int *)(g_Hook_OffsetTable + 788);
        v26 = v24 + v23 + *(unsigned int *)(g_Hook_OffsetTable + 792);
        LOBYTE(v21) = 1;
        sub_14016B1C0(g_Hook_GuestCr3OrCtx, v25 + *(unsigned int *)(g_Hook_OffsetTable + 800), v21);
        LOBYTE(v27) = 1;
        sub_14016B1C0(g_Hook_GuestCr3OrCtx, v26 + *(unsigned int *)(g_Hook_OffsetTable + 800), v27);
        v28 = _mm_unpacklo_ps((__m128)0x3F800000u, (__m128)0x3F800000u).m128_u64[0];
        sub_14016B300(g_Hook_GuestCr3OrCtx, v25 + *(unsigned int *)(g_Hook_OffsetTable + 804), v28);
        result = sub_14016B300(g_Hook_GuestCr3OrCtx, v26 + *(unsigned int *)(g_Hook_OffsetTable + 804), v28);
        goto LABEL_25;
      }
      _InterlockedCompareExchange(&dword_14026BF68, 0, 1);
      v6 = 0;
      v7 = v38 == 1;
      v39 = v38 == 1;
      if ( v38 == 1 )
      {
        v6 = dword_140270230;
        result = (unsigned int)++dword_140270230;
        if ( v6 >= 5 )
          return result;
        v8 = v6 == 0;
        if ( v6 != 0 )
        {
LABEL_15:
          if ( v7 )
          {
            result = sub_1401687E0(GuestU64);
            if ( (_DWORD)result == 0 )
              return result;
            if ( v8 )
            {
              v17 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, a1[19] + (unsigned int)result);
              _InterlockedCompareExchange(&dword_14026BF6C, 0, 1);
              v18 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v17 + *(unsigned int *)(g_Hook_OffsetTable + 136));
              _InterlockedCompareExchange(&dword_14026BF74, 0, 1);
              v19 = (0x5851F42D4C957F2DLL * v18 + 0x14057B7EF767814FLL) % 5uLL;
              MEMORY[0x14DD921E0] = v19;
              result = 5 * ((v19 + 1) / 5u);
              v20 = (v19 + 1) % 5u;
              MEMORY[0x14DD921EC] = v20;
            }
            else
            {
              v19 = MEMORY[0x14DD921E0];
              v20 = MEMORY[0x14DD921EC];
            }
            if ( v6 == v20 )
            {
              Hv_ReadGuestBytes(g_Hook_GuestCr3OrCtx, (__int64)&v32, v37);
              v29 = (float)(*(float *)&v32 - MEMORY[0x14E3AF258]) + *(float *)&v32;
              v30 = (float)(*((float *)&v32 + 1) - MEMORY[0x14E3AF25C]) + *((float *)&v32 + 1);
              v31 = (float)(v33 - MEMORY[0x14E3AF260]) + v33;
              result = sub_14016B410(g_Hook_GuestCr3OrCtx, v37, &v29);
LABEL_27:
              a1[19] += 8LL;
              a1[31] = GuestU64;
              return result;
            }
            if ( v6 != v19 )
              return result;
          }
LABEL_25:
          ++dword_14027022C;
          if ( v38 > 0 )
          {
            do
            {
              v33 = MEMORY[0x14E3AF260];
              v32 = MEMORY[0x14E3AF258];
              result = sub_14016B410(g_Hook_GuestCr3OrCtx, v37 + 12LL * v5++, &v32);
            }
            while ( v5 < v38 );
          }
          goto LABEL_27;
        }
      }
      else
      {
        v8 = true;
      }
      Hv_ReadGuestBytes(g_Hook_GuestCr3OrCtx, (__int64)&v29, qword_1402707A8);
      v9 = g_Hook_OffsetTable;
      v10 = 1.0
          / fsqrt(
              (float)((float)((float)(*((float *)&unk_14DD8A1A0 + 1) - v30)
                            * (float)(*((float *)&unk_14DD8A1A0 + 1) - v30))
                    + (float)((float)(*(float *)&unk_14DD8A1A0 - v29) * (float)(*(float *)&unk_14DD8A1A0 - v29)))
            + (float)((float)(*(float *)&MEMORY[0x14DD8A1A8] - v31) * (float)(*(float *)&MEMORY[0x14DD8A1A8] - v31)));
      MEMORY[0x14E3AF258] = v10 * (float)(*(float *)&unk_14DD8A1A0 - v29);
      MEMORY[0x14E3AF25C] = v10 * (float)(*((float *)&unk_14DD8A1A0 + 1) - v30);
      MEMORY[0x14E3AF260] = v10 * (float)(*(float *)&MEMORY[0x14DD8A1A8] - v31);
      v11 = *(unsigned int *)(g_Hook_OffsetTable + 796);
      v12 = a1[16];
      v13 = v12 + v11 + *(unsigned int *)(g_Hook_OffsetTable + 788);
      v14 = v12 + v11 + *(unsigned int *)(g_Hook_OffsetTable + 792);
      LOBYTE(v9) = 1;
      sub_14016B1C0(g_Hook_GuestCr3OrCtx, v13 + *(unsigned int *)(g_Hook_OffsetTable + 800), v9);
      LOBYTE(v15) = 1;
      sub_14016B1C0(g_Hook_GuestCr3OrCtx, v14 + *(unsigned int *)(g_Hook_OffsetTable + 800), v15);
      v16 = _mm_unpacklo_ps((__m128)0x3F800000u, (__m128)0x3F800000u).m128_u64[0];
      sub_14016B300(g_Hook_GuestCr3OrCtx, v13 + *(unsigned int *)(g_Hook_OffsetTable + 804), v16);
      result = sub_14016B300(g_Hook_GuestCr3OrCtx, v14 + *(unsigned int *)(g_Hook_OffsetTable + 804), v16);
      v7 = v39;
      goto LABEL_15;
    }
  }
  return result;
}

--- DISASM (first 300 lines) ---


===== sub_140176310 start=0x140176310 end=0x1401764ea size=474 proto=__int64 __fastcall(__int64)
comment: 
repeatable_comment: 
callers: [{"ea": "0x14015b960", "name": "sub_14015B960"}, {"ea": "0x140163720", "name": "sub_140163720"}, {"ea": "0x14016dd70", "name": "sub_14016DD70"}, {"ea": "0x140172e50", "name": "sub_140172E50"}, {"ea": "0x140186d90", "name": "sub_140186D90"}, {"ea": "0x1401891d0", "name": "Hook_InstallAll"}, {"ea": "0x1401906e0", "name": "Hook_NtApi_VmExitHandler"}]
callees: [{"ea": "0x140133e10", "name": "Mem_HeapAlloc"}, {"ea": "0x1401536b0", "name": "HV_Dispatch"}, {"ea": "0x14015cf60", "name": "Hv_ReadGuestU32"}, {"ea": "0x1401625b0", "name": "sub_1401625B0"}, {"ea": "0x140176080", "name": "sub_140176080"}, {"ea": "0x140176310", "name": "sub_140176310"}, {"ea": "0x140176b60", "name": "sub_140176B60"}, {"ea": "0x1401e9d70", "name": "sub_1401E9D70"}]
strings: [{"ea": "0x1401f1a20", "text": "NULL0"}, {"ea": "0x1401f1a30", "text": "_C_"}]
--- PSEUDOCODE ---
__int64 __fastcall sub_140176310(__int64 a1)
{
  _OWORD *v2; // rax
  unsigned int GuestU32; // eax
  unsigned int v4; // r8d
  __int64 v6; // rbx
  __int64 v7; // rcx
  __int64 v8; // rdx
  __int64 *v9; // r9
  __int64 v10; // rax
  const char *v11; // rdi
  __int64 v12; // rax
  unsigned __int8 i; // al
  unsigned __int64 v14; // rbx
  char v15[24]; // [rsp+30h] [rbp-18h] BYREF
  __int64 retaddr; // [rsp+48h] [rbp+0h]
  unsigned int v17; // [rsp+58h] [rbp+10h] BYREF
  __int64 v18; // [rsp+60h] [rbp+18h] BYREF

  if ( qword_14DB95C98 == 0 )
  {
    v2 = Mem_HeapAlloc(0x40u);
    if ( v2 == nullptr )
    {
      HV_Dispatch(0x3678656u, 64, retaddr, retaddr - 0x140000000LL, 0);
      JUMPOUT(0x1401764E9LL);
    }
    *v2 = 0;
    v2[1] = 0;
    v2[2] = 0;
    v2[3] = 0;
    qword_14DB95C98 = sub_1401625B0(v2);
  }
  GuestU32 = Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, a1 + *(unsigned int *)(g_Hook_OffsetTable + 268));
  v4 = GuestU32;
  v17 = GuestU32;
  if ( GuestU32 == 0 )
    return 0;
  v6 = 0xCBF29CE484222325uLL;
  v7 = qword_14DB95C98;
  v8 = *(_QWORD *)(qword_14DB95C98 + 8);
  v9 = (__int64 *)(*(_QWORD *)(qword_14DB95C98 + 24)
                 + 16
                 * (*(_QWORD *)(qword_14DB95C98 + 48)
                  & (0x100000001B3LL
                   * (((unsigned __int64)GuestU32 >> 24)
                    ^ (0x100000001B3LL
                     * (BYTE2(GuestU32)
                      ^ (0x100000001B3LL
                       * (BYTE1(GuestU32) ^ (0x100000001B3LL * ((unsigned __int8)GuestU32 ^ 0xCBF29CE484222325uLL))))))))));
  v10 = v9[1];
  if ( v10 == v8 )
    goto LABEL_11;
  v7 = *v9;
  if ( v4 != *(_DWORD *)(v10 + 16) )
  {
    while ( v10 != v7 )
    {
      v10 = *(_QWORD *)(v10 + 8);
      if ( v4 == *(_DWORD *)(v10 + 16) )
        goto LABEL_12;
    }
LABEL_11:
    v10 = 0;
  }
LABEL_12:
  if ( v10 == 0 )
    v10 = *(_QWORD *)(qword_14DB95C98 + 8);
  if ( v10 != v8 )
    return *(_QWORD *)(v10 + 24);
  if ( v4 != 0 )
  {
    v11 = (const char *)sub_140176080(v4);
    v12 = sub_1401E9D70(v11, qword_1401F1A30);
    if ( v12 != 0 )
      *(_BYTE *)(v12 + 2) = 0;
  }
  else
  {
    v11 = "NULL0";
  }
  for ( i = *v11; *v11 != 0; v6 = 0x100000001B3LL * v14 )
  {
    ++v11;
    v14 = i ^ (unsigned __int64)v6;
    i = *v11;
  }
  v18 = v6;
  sub_140176B60(v7, v15, &v17, &v18);
  return v18;
}

--- DISASM (first 300 lines) ---


===== sub_140179540 start=0x140179540 end=0x14017978b size=587 proto=__int64 __fastcall(__int64 *)
comment: 
repeatable_comment: 
callers: [{"ea": "0x1401906e0", "name": "Hook_NtApi_VmExitHandler"}]
callees: [{"ea": "0x14015cf60", "name": "Hv_ReadGuestU32"}, {"ea": "0x14015d100", "name": "Hv_WriteGuestU64"}, {"ea": "0x14015d5c0", "name": "Hv_ReadGuestU64"}, {"ea": "0x140178fb0", "name": "sub_140178FB0"}, {"ea": "0x140179340", "name": "sub_140179340"}, {"ea": "0x140179540", "name": "sub_140179540"}, {"ea": "0x140180a80", "name": "sub_140180A80"}, {"ea": "0x140181890", "name": "sub_140181890"}]
strings: []
--- PSEUDOCODE ---
__int64 __fastcall sub_140179540(__int64 *a1)
{
  __int64 GuestU64; // rax
  unsigned int GuestU32; // eax
  __int64 v4; // rcx
  __int64 v5; // rsi
  __int128 v6; // xmm1
  __int128 v7; // xmm0
  __int128 v8; // xmm1
  __int128 v9; // xmm0
  __int64 v10; // rcx
  __int64 *v11; // rax
  __int128 v12; // xmm1
  __int64 v13; // rcx
  __int128 v14; // xmm0
  __int128 v15; // xmm1
  __int128 v16; // xmm0
  __int64 result; // rax
  __int128 v18; // [rsp+20h] [rbp-89h] BYREF
  __int128 v19; // [rsp+30h] [rbp-79h]
  __int128 v20; // [rsp+40h] [rbp-69h]
  __int128 v21; // [rsp+50h] [rbp-59h]
  __int128 v22; // [rsp+60h] [rbp-49h]
  __int64 v23; // [rsp+70h] [rbp-39h]
  _BYTE v24[96]; // [rsp+80h] [rbp-29h] BYREF
  __int64 v25; // [rsp+E0h] [rbp+37h]
  __int64 v26; // [rsp+110h] [rbp+67h] BYREF
  __int64 v27; // [rsp+118h] [rbp+6Fh] BYREF

  GuestU64 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, a1[20] - *(unsigned int *)(g_Hook_OffsetTable + 252));
  if ( (unsigned __int64)(GuestU64 - 0xFFFF) <= 0x7FFFFFFF0000LL )
    GuestU32 = Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, GuestU64 + 44);
  else
    GuestU32 = 0;
  v26 = 0;
  if ( (unsigned __int8)sub_140178FB0(GuestU32, &v26) != 0 )
  {
    while ( _InterlockedCompareExchange64(&qword_14DB95CB8, 1, 0) == 1 )
      _mm_pause();
    v5 = v26;
    v18 = 0;
    v25 = 0;
    v19 = 0;
    v20 = 0;
    v21 = 0;
    v22 = 0;
    v23 = 0;
    if ( v26 != 0 )
    {
      while ( _InterlockedCompareExchange64(&qword_14DB95CA0, 1, 0) == 1 )
        _mm_pause();
      sub_140180A80(v4, &v27, &v26);
      if ( v27 != qword_14DD8A378 )
      {
        v6 = *(_OWORD *)(v27 + 40);
        v18 = *(_OWORD *)(v27 + 24);
        v7 = *(_OWORD *)(v27 + 56);
        v19 = v6;
        v8 = *(_OWORD *)(v27 + 72);
        v20 = v7;
        v9 = *(_OWORD *)(v27 + 88);
        v21 = v8;
        *(_QWORD *)&v8 = *(_QWORD *)(v27 + 104);
        v22 = v9;
        v23 = v8;
      }
      _InterlockedExchange64(&qword_14DB95CA0, 0);
    }
    sub_140179340(a1[16], (__int64)&v18);
    if ( (_BYTE)v18 != 0 )
    {
      v26 = v5;
      if ( v5 != 0 )
      {
        while ( _InterlockedCompareExchange64(&qword_14DB95CA0, 1, 0) == 1 )
          _mm_pause();
        v11 = (__int64 *)sub_140181890(v10, v24, &v26);
        v12 = v19;
        v13 = *v11;
        *(_OWORD *)(v13 + 24) = v18;
        v14 = v20;
        *(_OWORD *)(v13 + 40) = v12;
        v15 = v21;
        *(_OWORD *)(v13 + 56) = v14;
        v16 = v22;
        *(_OWORD *)(v13 + 72) = v15;
        *(_QWORD *)&v15 = v23;
        *(_OWORD *)(v13 + 88) = v16;
        *(_QWORD *)(v13 + 104) = v15;
        _InterlockedExchange64(&qword_14DB95CA0, 0);
      }
    }
    _InterlockedExchange64(&qword_14DB95CB8, 0);
  }
  a1[19] -= 8;
  result = Hv_WriteGuestU64((int *)g_Hook_GuestCr3OrCtx, a1[19], a1[18]);
  a1[31] += 2;
  return result;
}

--- DISASM (first 300 lines) ---


===== sub_140179790 start=0x140179790 end=0x140179a88 size=760 proto=__int64 __fastcall(_QWORD *)
comment: 
repeatable_comment: 
callers: [{"ea": "0x1401906e0", "name": "Hook_NtApi_VmExitHandler"}]
callees: [{"ea": "0x14015cf60", "name": "Hv_ReadGuestU32"}, {"ea": "0x14015d100", "name": "Hv_WriteGuestU64"}, {"ea": "0x14015d5c0", "name": "Hv_ReadGuestU64"}, {"ea": "0x140178fb0", "name": "sub_140178FB0"}, {"ea": "0x140179790", "name": "sub_140179790"}, {"ea": "0x140180a80", "name": "sub_140180A80"}, {"ea": "0x140181890", "name": "sub_140181890"}]
strings: []
--- PSEUDOCODE ---
__int64 __fastcall sub_140179790(_QWORD *a1)
{
  __int64 GuestU64; // rax
  unsigned int GuestU32; // eax
  __int64 v4; // rax
  __int64 v5; // rsi
  __int64 v6; // rbp
  __int64 v7; // rcx
  __int64 v8; // rcx
  __int64 result; // rax
  __int128 v10; // [rsp+20h] [rbp-138h]
  __int128 v11; // [rsp+30h] [rbp-128h]
  __int128 v12; // [rsp+40h] [rbp-118h]
  __int128 v13; // [rsp+50h] [rbp-108h]
  _BYTE v14[16]; // [rsp+60h] [rbp-F8h] BYREF
  __int128 v15; // [rsp+70h] [rbp-E8h]
  __int64 v16; // [rsp+120h] [rbp-38h]
  __int64 v17; // [rsp+160h] [rbp+8h] BYREF
  __int64 v18; // [rsp+168h] [rbp+10h] BYREF
  __int64 v19; // [rsp+170h] [rbp+18h] BYREF

  GuestU64 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, a1[20] - *(unsigned int *)(g_Hook_OffsetTable + 252));
  if ( (unsigned __int64)(GuestU64 - 0xFFFF) <= 0x7FFFFFFF0000LL )
    GuestU32 = Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, GuestU64 + 44);
  else
    GuestU32 = 0;
  v17 = 0;
  if ( (unsigned __int8)sub_140178FB0(GuestU32, &v17) != 0 )
  {
    while ( _InterlockedCompareExchange64(&qword_14DB95CB8, 1, 0) == 1 )
      _mm_pause();
    v4 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, a1[16] + 32LL);
    if ( (unsigned __int64)(v4 - 0xFFFF) <= 0x7FFFFFFF0000LL )
    {
      v5 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v4 + 8);
      if ( (unsigned __int64)(v5 - 0xFFFF) <= 0x7FFFFFFF0000LL )
      {
        v6 = v17;
        v18 = v17;
        v16 = 0;
        v17 = 0;
        v15 = 0;
        v10 = 0;
        v11 = 0;
        v12 = 0;
        v13 = 0;
        if ( v18 != 0 )
        {
          while ( _InterlockedCompareExchange64(&qword_14DB95CA0, 1, 0) == 1 )
            _mm_pause();
          sub_140180A80(v5 - 0xFFFF, &v19, &v18);
          if ( v19 != qword_14DD8A378 )
          {
            v15 = *(_OWORD *)(v19 + 24);
            v10 = *(_OWORD *)(v19 + 40);
            v11 = *(_OWORD *)(v19 + 56);
            v12 = *(_OWORD *)(v19 + 72);
            v13 = *(_OWORD *)(v19 + 88);
            v17 = *(_QWORD *)(v19 + 104);
          }
          _InterlockedExchange64(&qword_14DB95CA0, 0);
        }
        DWORD1(v15) = Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, v5 + 128);
        DWORD2(v15) = Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, v5 + 248);
        v18 = v6;
        if ( v6 != 0 )
        {
          while ( _InterlockedCompareExchange64(&qword_14DB95CA0, 1, 0) == 1 )
            _mm_pause();
          v8 = *(_QWORD *)sub_140181890(v7, v14, &v18);
          *(_OWORD *)(v8 + 24) = v15;
          *(_OWORD *)(v8 + 40) = v10;
          *(_OWORD *)(v8 + 56) = v11;
          *(_OWORD *)(v8 + 72) = v12;
          *(_OWORD *)(v8 + 88) = v13;
          *(_QWORD *)(v8 + 104) = v17;
          _InterlockedExchange64(&qword_14DB95CA0, 0);
        }
      }
    }
    _InterlockedExchange64(&qword_14DB95CB8, 0);
  }
  a1[19] -= 8LL;
  result = Hv_WriteGuestU64((int *)g_Hook_GuestCr3OrCtx, a1[19], a1[18]);
  a1[31] += 2LL;
  return result;
}

--- DISASM (first 300 lines) ---


===== sub_14017BAF0 start=0x14017baf0 end=0x14017bdaf size=703 proto=__int64 __fastcall(_QWORD *)
comment: 
repeatable_comment: 
callers: [{"ea": "0x1401906e0", "name": "Hook_NtApi_VmExitHandler"}]
callees: [{"ea": "0x14015cdc0", "name": "Hv_ReadGuestU8"}, {"ea": "0x14015cf60", "name": "Hv_ReadGuestU32"}, {"ea": "0x14015d100", "name": "Hv_WriteGuestU64"}, {"ea": "0x14015d5c0", "name": "Hv_ReadGuestU64"}, {"ea": "0x14017abc0", "name": "Hook_LookupByPid"}, {"ea": "0x14017aea0", "name": "Hook_LogListEntry"}, {"ea": "0x14017b600", "name": "sub_14017B600"}, {"ea": "0x14017baf0", "name": "sub_14017BAF0"}, {"ea": "0x140180d20", "name": "sub_140180D20"}]
strings: [{"ea": "0x1401f1ec0", "text": "DetailHook"}]
--- PSEUDOCODE ---
__int64 __fastcall sub_14017BAF0(_QWORD *a1)
{
  __int64 GuestU64; // rax
  __int64 v3; // r8
  __int64 v4; // r9
  int GuestU32; // ebx
  __int64 v6; // rax
  __int64 v7; // rdx
  int v8; // eax
  __int64 v9; // rdi
  __int64 v10; // rsi
  __int64 v11; // rcx
  int v12; // eax
  __int64 v13; // rcx
  unsigned __int8 GuestU8; // al
  __int64 v15; // rcx
  int v16; // ebx
  unsigned __int64 v17; // rdx
  __int64 v18; // rax
  int v19; // edi
  unsigned __int64 v20; // rbp
  unsigned __int64 v21; // r12
  __int64 v22; // rax
  __int64 v23; // rdx
  __int64 result; // rax
  _BYTE v25[16]; // [rsp+20h] [rbp-58h] BYREF
  __int128 v26; // [rsp+30h] [rbp-48h] BYREF
  __int64 v27; // [rsp+40h] [rbp-38h]

  GuestU64 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, a1[20] - *(unsigned int *)(g_Hook_OffsetTable + 252));
  if ( (unsigned __int64)(GuestU64 - 0xFFFF) > 0x7FFFFFFF0000LL )
    GuestU32 = 0;
  else
    GuestU32 = Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, GuestU64 + 44);
  v26 = 0;
  v27 = 0;
  if ( Hook_LookupByPid(GuestU32, (__int64)&v26, v3, v4) == 0 || (_DWORD)v26 != 1 )
  {
    Hook_LogListEntry((__int64)"DetailHook", GuestU32, (__int64)a1);
    goto LABEL_30;
  }
  while ( _InterlockedCompareExchange64(&qword_14DB95CC0, 1, 0) == 1 )
    _mm_pause();
  v6 = sub_140180D20(1, v25, (char *)&v26 + 8);
  v7 = *(_QWORD *)v6 + 24LL;
  if ( (int)v27 >= 0 )
  {
    v8 = *(_DWORD *)(*(_QWORD *)v6 + 36LL);
    if ( v8 >= 0 )
    {
      if ( v8 > 20 )
        v8 = 20;
    }
    else
    {
      v8 = 0;
    }
    if ( (int)v27 < v8 )
    {
      v9 = a1[16];
      v10 = v7 + 1080LL * (int)v27 + 344;
      if ( v10 != 0
        && (unsigned __int64)(v9 - 0xFFFF) <= 0x7FFFFFFF0000LL
        && (unsigned int)Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, v9 + 40) == 0 )
      {
        v11 = g_Hook_GuestCr3OrCtx;
        *(_BYTE *)v10 = 1;
        v12 = Hv_ReadGuestU32(v11, v9 + 44);
        v13 = g_Hook_GuestCr3OrCtx;
        *(_DWORD *)(v10 + 4) = v12;
        GuestU8 = Hv_ReadGuestU8(v13, v9 + 48);
        v15 = g_Hook_GuestCr3OrCtx;
        *(_DWORD *)(v10 + 8) = GuestU8;
        *(_DWORD *)(v10 + 12) = 0;
        v16 = Hv_ReadGuestU32(v15, v9 + 24);
        v17 = v9 + 32;
        if ( v16 >= 0 )
        {
          if ( v16 <= 4 )
          {
            v18 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v17);
            v19 = 0;
            if ( v16 <= 0 )
              goto LABEL_28;
          }
          else
          {
            v16 = 4;
            v18 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v17);
            v19 = 0;
          }
          v20 = v18 + 8;
          v21 = v18 - 0xFFFF;
          do
          {
            if ( v21 <= 0x7FFFFFFF0000LL )
            {
              v22 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v20);
              if ( (unsigned __int64)(v22 - 0xFFFF) <= 0x7FFFFFFF0000LL )
              {
                sub_14017B600(v22, v10 + 184LL * *(int *)(v10 + 12) + 16);
                v23 = *(int *)(v10 + 12);
                if ( *(_BYTE *)(184 * v23 + v10 + 16) != 0 )
                  *(_DWORD *)(v10 + 12) = v23 + 1;
              }
            }
            ++v19;
            v20 += 8LL;
          }
          while ( v19 < v16 );
          goto LABEL_28;
        }
        Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v17);
      }
    }
  }
LABEL_28:
  _InterlockedExchange64(&qword_14DB95CC0, 0);
LABEL_30:
  a1[19] -= 8LL;
  result = Hv_WriteGuestU64((int *)g_Hook_GuestCr3OrCtx, a1[19], a1[18]);
  a1[31] += 2LL;
  return result;
}

--- DISASM (first 300 lines) ---


===== sub_140187B90 start=0x140187b90 end=0x140187e55 size=709 proto=__int64 __fastcall(__int64)
comment: 
repeatable_comment: 
callers: [{"ea": "0x1401906e0", "name": "Hook_NtApi_VmExitHandler"}]
callees: [{"ea": "0x14015cf60", "name": "Hv_ReadGuestU32"}, {"ea": "0x14015d2d0", "name": "sub_14015D2D0"}, {"ea": "0x14015d5c0", "name": "Hv_ReadGuestU64"}, {"ea": "0x1401755b0", "name": "sub_1401755B0"}, {"ea": "0x140187b90", "name": "sub_140187B90"}, {"ea": "0x14018cc80", "name": "sub_14018CC80"}]
strings: []
--- PSEUDOCODE ---
__int64 __fastcall sub_140187B90(__int64 a1)
{
  unsigned __int64 v2; // rdx
  __int64 GuestU64; // rax
  __int64 v4; // rbp
  __int64 v5; // rbx
  bool v6; // di
  __int64 v7; // r14
  __int64 v8; // rcx
  int v9; // ebx
  int v10; // ebx
  __int64 v11; // rax
  __int64 v12; // rax
  double v13; // xmm0_8
  unsigned __int64 v14; // rdx
  __int64 v15; // r8
  bool v16; // zf
  __int64 result; // rax
  __int64 v18; // [rsp+50h] [rbp+8h] BYREF

  v2 = *(_QWORD *)(a1 + 128) + *(unsigned int *)(g_Hook_OffsetTable + 504);
  qword_14DB95CE8 = *(_QWORD *)(a1 + 128);
  GuestU64 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v2);
  qword_14DB95CF0 = GuestU64;
  byte_14828F3D5 = 0;
  v4 = GuestU64;
  if ( (unsigned __int64)(GuestU64 - 0xFFFF) > 0x7FFFFFFF0000LL )
  {
    v6 = true;
    goto LABEL_22;
  }
  v18 = GuestU64;
  v5 = *(_QWORD *)(g_Hook_NtosOffsetsCtx + 1840);
  v6 = GuestU64 == v5;
  v7 = sub_1401755B0(GuestU64 + *(unsigned int *)(g_Hook_OffsetTable + 476));
  v8 = v7 - 0xFFFF;
  if ( (unsigned __int64)(v7 - 0xFFFF) > 0x7FFFFFFF0000LL )
  {
    v8 = 1;
    byte_14828F3D5 = 1;
    if ( *(_BYTE *)(g_Sys_ConfigFlags + 221) != 0 )
    {
      v6 = true;
      goto LABEL_15;
    }
  }
  else
  {
    LOBYTE(v8) = 0;
    byte_14828F3D5 = 0;
  }
  if ( v4 != v5 )
  {
    if ( (_BYTE)v8 != 0
      || (*(_BYTE *)(g_Sys_ConfigFlags + 377) == 0
       || (v9 = *(_DWORD *)(g_Hook_NtosOffsetsCtx + 1896),
           (unsigned int)Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, v7 + *(unsigned int *)(g_Hook_OffsetTable + 640)) != v9))
      && (*(_BYTE *)(g_Sys_ConfigFlags + 378) == 0
       || (v10 = *(_DWORD *)(g_Hook_NtosOffsetsCtx + 1900),
           (unsigned int)Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, v7 + *(unsigned int *)(g_Hook_OffsetTable + 644)) != v10)) )
    {
      v11 = sub_1401755B0(v4 + *(unsigned int *)(g_Hook_OffsetTable + 552));
      if ( (unsigned __int64)(v11 - 0xFFFF) > 0x7FFFFFFF0000LL )
        goto LABEL_22;
      v12 = sub_1401755B0(v11 + *(unsigned int *)(g_Hook_OffsetTable + 556));
      if ( (unsigned __int64)(v12 - 0xFFFF) > 0x7FFFFFFF0000LL )
        goto LABEL_22;
      v13 = sub_14015D2D0(g_Hook_GuestCr3OrCtx, v12 + *(unsigned int *)(g_Hook_OffsetTable + 560));
      if ( *(_BYTE *)(g_Sys_ConfigFlags + 220) == 0 || *(float *)&v13 > 0.0 )
        goto LABEL_22;
    }
    v6 = true;
  }
LABEL_15:
  while ( _InterlockedCompareExchange64(&qword_14DB95CF8, 1, 0) == 1 )
    _mm_pause();
  sub_14018CC80(v8, &v18);
  _InterlockedExchange64(&qword_14DB95CF8, 0);
LABEL_22:
  v14 = *(_QWORD *)(a1 + 152);
  byte_14828F3D4 = v6;
  v15 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v14);
  if ( (unsigned __int64)(v15 - *(_QWORD *)(g_Hook_NtosOffsetsCtx + 1592)) >= 0x18000000 )
    _InterlockedCompareExchange(&dword_14026C044, 0, 1);
  v16 = (*(_DWORD *)(a1 + 68) & 0x40) == 0;
  qword_14DB95D00 = v15;
  result = 22;
  if ( !v16 )
    result = 2;
  *(_QWORD *)(a1 + 248) += result;
  return result;
}

--- DISASM (first 300 lines) ---


===== sub_140187E60 start=0x140187e60 end=0x1401881c6 size=870 proto=void __fastcall(_QWORD *)
comment: 
repeatable_comment: 
callers: [{"ea": "0x1401906e0", "name": "Hook_NtApi_VmExitHandler"}]
callees: [{"ea": "0x14003e1e0", "name": "HV_FlushOrSyncAfterRegister"}, {"ea": "0x140127b80", "name": "HV_HandlePendingEvent"}, {"ea": "0x14015d100", "name": "Hv_WriteGuestU64"}, {"ea": "0x14015d480", "name": "Hv_WriteGuestPtr"}, {"ea": "0x14015d5c0", "name": "Hv_ReadGuestU64"}, {"ea": "0x14015d900", "name": "Hv_ReadGuestBytes"}, {"ea": "0x140176110", "name": "sub_140176110"}, {"ea": "0x140176fd0", "name": "sub_140176FD0"}, {"ea": "0x140187e60", "name": "sub_140187E60"}, {"ea": "0x14018c6b0", "name": "sub_14018C6B0"}, {"ea": "0x1401e98d0", "name": "sub_1401E98D0"}]
strings: [{"ea": "0x1401f2a40", "text": "INVALID"}]
--- PSEUDOCODE ---
void __fastcall sub_140187E60(_QWORD *a1)
{
  unsigned __int64 v2; // rdx
  __int64 v3; // rcx
  __int64 GuestU64; // r8
  char v5; // r12
  char v6; // r14
  bool v7; // si
  int v8; // edx
  int v9; // ebx
  const char *v10; // rdi
  __int64 v11; // rcx
  unsigned __int64 v12; // rax
  __int64 v13; // rcx
  float v14; // xmm2_4
  __int64 v15; // xmm6_8
  int v16; // ebx
  __int64 v17; // rcx
  __int64 v18; // [rsp+30h] [rbp-58h] BYREF
  int v19; // [rsp+38h] [rbp-50h]
  _BYTE v20[16]; // [rsp+40h] [rbp-48h] BYREF
  __int64 v21; // [rsp+90h] [rbp+8h] BYREF

  Hv_WriteGuestU64((int *)g_Hook_GuestCr3OrCtx, a1[19] + 32LL, a1[24]);
  v2 = a1[19];
  v3 = g_Hook_GuestCr3OrCtx;
  a1[31] += 5LL;
  GuestU64 = Hv_ReadGuestU64(v3, v2);
  if ( (unsigned __int64)(GuestU64 - *(_QWORD *)(g_Hook_NtosOffsetsCtx + 1592)) >= 0x18000000 )
    _InterlockedCompareExchange(&dword_14026C040, 0, 1);
  v5 = *(_BYTE *)(g_Sys_ConfigFlags + 219);
  if ( *(_BYTE *)(g_Sys_ConfigFlags + 218) != 0 && *(_BYTE *)(g_Sys_ConfigFlags + 660) != 0 )
  {
    v6 = 1;
  }
  else
  {
    v6 = 0;
    if ( v5 == 0 )
      return;
  }
  if ( (unsigned __int64)(GuestU64 - qword_14DB95D00) <= 0x2000 && byte_14828F3D4 == 0 )
  {
    sub_14018C6B0(g_Hook_GuestCr3OrCtx, &v21, a1[16] + 88LL);
    v7 = false;
    v8 = *(_DWORD *)(g_Hook_NtosOffsetsCtx + 1984);
    if ( v8 != 0 )
    {
      v7 = (_DWORD)v21 == v8;
      if ( (_DWORD)v21 != v8 && v5 != 0 && (_DWORD)v21 != -1 )
        sub_140176110(v21);
    }
    else
    {
      v9 = v21;
      if ( (_DWORD)v21 == -1 )
        v10 = "INVALID";
      else
        v10 = (const char *)sub_140176110((unsigned int)v21);
      if ( *(_BYTE *)(g_Sys_ConfigFlags + 240) != 0 && (unsigned int)sub_1401E98D0(v10, g_Sys_ConfigFlags + 240) == 0 )
      {
        *(_DWORD *)(g_Hook_NtosOffsetsCtx + 1984) = v9;
        while ( _InterlockedCompareExchange64(&qword_14DB95CF8, 1, 0) == 1 )
          _mm_pause();
        HV_HandlePendingEvent(&qword_14828F380);
        v7 = true;
        _InterlockedExchange64(&qword_14DB95CF8, 0);
      }
    }
    if ( v6 != 0 && v7 )
    {
      v11 = *(_QWORD *)(g_Hook_NtosOffsetsCtx + 1928);
      if ( v11 == 0x436D8150BLL
        || (v12 = v11 - 0x4E44B2883LL, (unsigned __int64)(v11 - 0x4E44B2883LL) <= 9)
        && (v13 = 577, _bittest64(&v13, v12)) )
      {
        v14 = *(float *)(g_Sys_ConfigFlags + 236);
      }
      else if ( byte_14828F3D5 != 0 )
      {
        v14 = *(float *)(g_Sys_ConfigFlags + 232);
      }
      else
      {
        v14 = *(float *)(g_Sys_ConfigFlags + 228);
      }
      Hv_WriteGuestPtr((int *)g_Hook_GuestCr3OrCtx, a1[23], v14);
      Hv_ReadGuestBytes(g_Hook_GuestCr3OrCtx, (__int64)&v18, a1[17] + 16LL);
      while ( _InterlockedCompareExchange64(&qword_14DB95CF8, 1, 0) == 1 )
        _mm_pause();
      v15 = v18;
      v16 = v19;
      v17 = *(_QWORD *)sub_140176FD0(&qword_14828F380, v20, &qword_14DB95CF0);
      *(_QWORD *)(v17 + 24) = v15;
      *(_DWORD *)(v17 + 32) = v16;
      _InterlockedExchange64(&qword_14DB95CF8, 0);
    }
    if ( v5 != 0 )
      HV_FlushOrSyncAfterRegister();
  }
}

--- DISASM (first 300 lines) ---


===== sub_1401881D0 start=0x1401881d0 end=0x14018847a size=682 proto=__int64 __fastcall(_QWORD *)
comment: 
repeatable_comment: 
callers: [{"ea": "0x1401906e0", "name": "Hook_NtApi_VmExitHandler"}]
callees: [{"ea": "0x14015cdc0", "name": "Hv_ReadGuestU8"}, {"ea": "0x14015cf60", "name": "Hv_ReadGuestU32"}, {"ea": "0x14015d5c0", "name": "Hv_ReadGuestU64"}, {"ea": "0x14016b410", "name": "sub_14016B410"}, {"ea": "0x140184d90", "name": "sub_140184D90"}, {"ea": "0x1401881d0", "name": "sub_1401881D0"}, {"ea": "0x14018c6b0", "name": "sub_14018C6B0"}]
strings: [{"ea": "0x14828f398", "text": "`r1L"}, {"ea": "0x14828f3b0", "text": "\u0007"}]
--- PSEUDOCODE ---
__int64 __fastcall sub_1401881D0(_QWORD *a1)
{
  __int64 v2; // rsi
  __int64 v3; // rdi
  unsigned int GuestU32; // ebp
  __int64 v5; // rdx
  __int64 GuestU64; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v9; // rcx
  __int64 v10; // xmm6_8
  int v11; // ebp
  __int64 result; // rax
  __int64 v13; // [rsp+20h] [rbp-38h] BYREF
  int v14; // [rsp+28h] [rbp-30h]
  __int64 v15; // [rsp+60h] [rbp+8h] BYREF

  if ( *(_BYTE *)(g_Sys_ConfigFlags + 218) == 0
    || *(_BYTE *)(g_Sys_ConfigFlags + 660) == 0
    || *(_DWORD *)(g_Hook_NtosOffsetsCtx + 1984) == 0 )
  {
    goto LABEL_25;
  }
  v2 = a1[19];
  v3 = *(unsigned int *)(g_Hook_OffsetTable + 160);
  GuestU32 = Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, v2 + v3 + 112);
  if ( GuestU32 != 0 )
  {
    GuestU64 = Hv_ReadGuestU64(
                 g_Hook_GuestCr3OrCtx,
                 *(_QWORD *)(g_Hook_NtosOffsetsCtx + 1592) + *(unsigned int *)(g_Hook_OffsetTable + 20));
    if ( (unsigned __int64)(GuestU64 - 0xFFFF) > 0x7FFFFFFF0000LL )
    {
      v5 = 0;
    }
    else
    {
      v7 = sub_140184D90(GuestU64 - 0xFFFF, GuestU64, GuestU32);
      v5 = 0;
      if ( (unsigned __int64)(v7 - 0xFFFF) <= 0x7FFFFFFF0000LL )
        v5 = v7;
    }
  }
  else
  {
    v5 = 0;
  }
  v15 = v5;
  v13 = 0;
  v14 = 0;
  while ( _InterlockedCompareExchange64(&qword_14DB95CF8, 1, 0) == 1 )
    _mm_pause();
  v8 = *(_QWORD *)(qword_14828F398
                 + 16
                 * (qword_14828F3B0
                  & (0x100000001B3LL
                   * (HIBYTE(v15)
                    ^ (0x100000001B3LL
                     * (BYTE6(v15)
                      ^ (0x100000001B3LL
                       * (BYTE5(v15)
                        ^ (0x100000001B3LL
                         * (BYTE4(v15)
                          ^ (0x100000001B3LL
                           * (BYTE3(v15)
                            ^ (0x100000001B3LL
                             * (BYTE2(v15)
                              ^ (0x100000001B3LL
                               * (BYTE1(v15) ^ (0x100000001B3LL * ((unsigned __int8)v5 ^ 0xCBF29CE484222325uLL)))))))))))))))))
                 + 8);
  if ( v8 == qword_14828F388 )
    goto LABEL_18;
  if ( v5 != *(_QWORD *)(v8 + 16) )
  {
    while ( v8 != *(_QWORD *)(qword_14828F398
                            + 16
                            * (qword_14828F3B0
                             & (0x100000001B3LL
                              * (HIBYTE(v15)
                               ^ (0x100000001B3LL
                                * (BYTE6(v15)
                                 ^ (0x100000001B3LL
                                  * (BYTE5(v15)
                                   ^ (0x100000001B3LL
                                    * (BYTE4(v15)
                                     ^ (0x100000001B3LL
                                      * (BYTE3(v15)
                                       ^ (0x100000001B3LL
                                        * (BYTE2(v15)
                                         ^ (0x100000001B3LL
                                          * (BYTE1(v15)
                                           ^ (0x100000001B3LL * ((unsigned __int8)v5 ^ 0xCBF29CE484222325uLL)))))))))))))))))) )
    {
      v8 = *(_QWORD *)(v8 + 8);
      if ( v5 == *(_QWORD *)(v8 + 16) )
        goto LABEL_19;
    }
LABEL_18:
    v8 = 0;
  }
LABEL_19:
  v9 = qword_14828F388;
  if ( v8 != 0 )
    v9 = v8;
  if ( v9 == qword_14828F388 )
  {
    _InterlockedExchange64(&qword_14DB95CF8, 0);
  }
  else
  {
    v10 = *(_QWORD *)(v9 + 24);
    v11 = *(_DWORD *)(v9 + 32);
    _InterlockedExchange64(&qword_14DB95CF8, 0);
    sub_14018C6B0(g_Hook_GuestCr3OrCtx, &v15, v2 + v3 + 128);
    if ( (_DWORD)v15 == *(_DWORD *)(g_Hook_NtosOffsetsCtx + 1984) )
    {
      v13 = v10;
      v14 = v11;
      sub_14016B410(g_Hook_GuestCr3OrCtx, v2 + v3 + 36, &v13);
    }
  }
LABEL_25:
  LOBYTE(result) = Hv_ReadGuestU8(g_Hook_GuestCr3OrCtx, *(unsigned int *)(g_Hook_OffsetTable + 160) + 1LL + a1[19]);
  a1[31] += 8LL;
  result = (unsigned __int8)result;
  a1[15] = (unsigned __int8)result;
  return result;
}

--- DISASM (first 300 lines) ---


