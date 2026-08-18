// ACE exit handler: match guest RIP to hooked ntos offsets; ListHook path
char __fastcall ACE_NtApiHook_ExitHandler(__int64 a1, _QWORD *a2)
{
  __int64 v4; // rdx
  __int64 v5; // r9
  __int64 v6; // rax
  __int64 v7; // rdx
  __int64 v8; // rbx
  __int64 v9; // rax
  __int64 v11; // rbx
  __int64 v12; // rax
  int v13; // ebp
  int v14; // ecx
  __int64 v15; // rdx
  __int64 v16; // rax
  __int64 v17; // rdx
  __int64 v18; // rax
  _BYTE *v19; // r8
  __int64 v20; // rdx
  __int64 v21; // rdx
  __int64 v22; // rax
  unsigned int v23; // esi
  __int64 v24; // rcx
  _QWORD *v25; // rax
  _BYTE v26[16]; // [rsp+20h] [rbp-38h] BYREF
  __int128 v27; // [rsp+30h] [rbp-28h] BYREF
  __int64 v28; // [rsp+40h] [rbp-18h]

  if ( HV_Rdgsbase() )
    v4 = *(_QWORD *)((char *)KeGetCurrentThread() + (unsigned int)g_Off_EPROCESS_UniqueProcessId);
  else
    v4 = HV_GetCurrentProcessId_Host();
  v5 = g_Hook_GuestCr3OrCtx;
  if ( v4 != *(_DWORD *)g_Hook_GuestCr3OrCtx )
    return 0;
  v6 = g_Hook_NtosOffsetsCtx;
  v7 = *(_QWORD *)(a1 + 16);
  if ( v7 == *(_QWORD *)(g_Hook_NtosOffsetsCtx + 1936) )
  {
    v8 = a2[22];
    Hv_ReadGuestBytes(g_Hook_GuestCr3OrCtx, v26, a2[20] + 48LL);
    sub_140175230(v8, v26);
    v9 = a2[20] - 32LL;
    a2[31] += 4LL;
    a2[16] = v9;
    return 1;
  }
  if ( v7 == *(_QWORD *)(g_Hook_NtosOffsetsCtx + 1944) )
  {
    v11 = a2[16];
    Hv_ReadGuestBytes(g_Hook_GuestCr3OrCtx, v26, a2[17] + 16LL);
    sub_140175230(v11, v26);
    a2[19] -= 48LL;
    a2[31] += 4LL;
    return 1;
  }
  if ( v7 != *(_QWORD *)(g_Hook_NtosOffsetsCtx + 2032) )
  {
    if ( v7 == *(_QWORD *)(g_Hook_NtosOffsetsCtx + 2040) )
    {
      v17 = a2[19];
      if ( byte_14026E0B5 )
      {
        v18 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v17);
        a2[19] += 8LL;
        a2[31] = v18;
        _InterlockedCompareExchange(&dword_14026C030, 0, 1);
      }
      else
      {
        Hv_WriteGuestU64(g_Hook_GuestCr3OrCtx, v17 + 16, a2[17]);
        a2[31] += 5LL;
      }
      return 1;
    }
    if ( v7 == *(_QWORD *)(g_Hook_NtosOffsetsCtx + 1952) )
    {
      v19 = (_BYTE *)g_Sys_ConfigFlags;
      a2[31] += 5LL;
      a2[16] = 12;
      if ( v19[629] && (v19[630] || v19[849]) && (!v19[640] || (unsigned __int8)sub_1401944D0(*(_QWORD *)(v6 + 1928))) )
        Hv_WriteGuestPtr(v5, a2[19] + *(unsigned int *)(g_Hook_OffsetTable + 168));
      return 1;
    }
    if ( v7 == *(_QWORD *)(g_Hook_NtosOffsetsCtx + 1960) )
    {
      sub_140187B90(a2);
      return 1;
    }
    if ( v7 == *(_QWORD *)(g_Hook_NtosOffsetsCtx + 1968) )
    {
      sub_140187E60(a2);
      return 1;
    }
    if ( v7 == *(_QWORD *)(g_Hook_NtosOffsetsCtx + 1976) )
    {
      sub_1401881D0(a2);
      return 1;
    }
    if ( v7 == *(_QWORD *)(g_Hook_NtosOffsetsCtx + 2008) )
    {
      v20 = *(unsigned int *)(g_Hook_OffsetTable + 116);
LABEL_39:
      v21 = a2[19] + v20;
      ++dword_140270228;
      a2[31] += 8LL;
      dword_140270230 = 0;
      a2[17] = v21;
      qword_1402707A8 = v21;
      return 1;
    }
    if ( v7 == *(_QWORD *)(g_Hook_NtosOffsetsCtx + 2016) )
    {
      v20 = *(unsigned int *)(g_Hook_OffsetTable + 124);
      goto LABEL_39;
    }
    if ( v7 == *(_QWORD *)(g_Hook_NtosOffsetsCtx + 2024) )
    {
      sub_140168A70(a2);
      return 1;
    }
    if ( v7 == *(_QWORD *)(g_Hook_NtosOffsetsCtx + 2048) )
    {
      sub_140179540(a2);
      return 1;
    }
    if ( v7 == *(_QWORD *)(g_Hook_NtosOffsetsCtx + 2056) )
    {
      sub_140179790(a2);
      return 1;
    }
    if ( v7 == *(_QWORD *)(g_Hook_NtosOffsetsCtx + 2064) )
    {
      v22 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, a2[20] - *(unsigned int *)(g_Hook_OffsetTable + 252));
      if ( (unsigned __int64)(v22 - 0xFFFF) <= 0x7FFFFFFF0000LL )
        v23 = Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, v22 + 44);
      else
        v23 = 0;
      v27 = 0;
      v28 = 0;
      if ( !(unsigned __int8)Hook_LookupByPid(v23, &v27) || (_DWORD)v27 )
      {
        Hook_LogListEntry("ListHook", v23, a2);
      }
      else
      {
        while ( _InterlockedCompareExchange64(&qword_14DB95CC0, 1, 0) == 1 )
          _mm_pause();
        v25 = (_QWORD *)sub_140180D20(v24, v26, (char *)&v27 + 8);
        Hv_ReadProcessListFromGuest(a2[16], *v25 + 24LL);
        _InterlockedExchange64(&qword_14DB95CC0, 0);
      }
      a2[19] -= 8LL;
      Hv_WriteGuestU64(g_Hook_GuestCr3OrCtx, a2[19], a2[18]);
      a2[31] += 2LL;
      return 1;
    }
    if ( v7 == *(_QWORD *)(g_Hook_NtosOffsetsCtx + 2072) )
    {
      sub_14017BAF0(a2);
      return 1;
    }
    return 0;
  }
  if ( dword_140270234 )
  {
    v12 = sub_140176310(a2[23]);
    if ( v12 == 0x553A7EE1DD1AE97CLL || v12 == 0x73BAE6D464A1B55CLL )
    {
      v13 = Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, a2[24] + *(unsigned int *)(g_Hook_OffsetTable + 1076));
      v14 = Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, a2[24] + *(unsigned int *)(g_Hook_OffsetTable + 1080));
      _InterlockedCompareExchange(&dword_14026C02C, 0, 1);
      if ( v14 == dword_140270234 )
      {
        sub_14015D2D0(g_Hook_GuestCr3OrCtx, qword_1402707C8 + *(unsigned int *)(g_Hook_OffsetTable + 1072));
        Hv_WriteGuestPtr(g_Hook_GuestCr3OrCtx, qword_1402707C8 + *(unsigned int *)(g_Hook_OffsetTable + 1072));
        v15 = a2[19];
        byte_14026E0B5 = 1;
        v16 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v15);
        a2[19] += 8LL;
        a2[31] = v16;
        _InterlockedCompareExchange(&dword_14026C034, 0, 1);
        return 1;
      }
      if ( v13 == dword_140270234 )
      {
        Hv_WriteGuestPtr(g_Hook_GuestCr3OrCtx, qword_1402707C8 + *(unsigned int *)(g_Hook_OffsetTable + 1072));
        byte_14026E0B5 = 0;
      }
    }
  }
  Hv_WriteGuestU64(g_Hook_GuestCr3OrCtx, a2[19] + 32LL, a2[24]);
  a2[31] += 5LL;
  return 1;
}
