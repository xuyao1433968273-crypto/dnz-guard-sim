===== HV_FlushOrSyncAfterRegister size=21 proto=void()
callers: [{"ea": "0x140061b40", "name": "sub_140061B40"}, {"ea": "0x140061df0", "name": "sub_140061DF0"}, {"ea": "0x1400620a0", "name": "sub_1400620A0"}, {"ea": "0x140073410", "name": "sub_140073410"}, {"ea": "0x140075f60", "name": "Rule_ApplyServerConfig"}, {"ea": "0x140077f20", "name": "sub_140077F20"}, {"ea": "0x140079aa0", "name": "sub_140079AA0"}, {"ea": "0x140079c90", "name": "sub_140079C90"}, {"ea": "0x140088010", "name": "sub_140088010"}, {"ea": "0x1400887b0", "name": "sub_1400887B0"}, {"ea": "0x140088af0", "name": "sub_140088AF0"}, {"ea": "0x14008aaf0", "name": "sub_14008AAF0"}, {"ea": "0x140099500", "name": "sub_140099500"}, {"ea": "0x140107a60", "name": "Net_HttpsBearSslSession"}, {"ea": "0x140108730", "name": "sub_140108730"}, {"ea": "0x140108ed0", "name": "Net_HttpRequest"}, {"ea": "0x140111900", "name": "sub_140111900"}, {"ea": "0x140112ce0", "name": "sub_140112CE0"}, {"ea": "0x1401176e0", "name": "sub_1401176E0"}, {"ea": "0x140118970", "name": "HV_RegisterExitHandler"}, {"ea": "0x14011cfa0", "name": "sub_14011CFA0"}, {"ea": "0x14011fc20", "name": "sub_14011FC20"}, {"ea": "0x140126c20", "name": "HV_HandleVmExit_Primary"}, {"ea": "0x14012d6e0", "name": "sub_14012D6E0"}, {"ea": "0x140152ae0", "name": "sub_140152AE0"}, {"ea": "0x14017aea0", "name": "Hook_LogListEntry"}, {"ea": "0x14017bfa0", "name": "sub_14017BFA0"}, {"ea": "0x140187e60", "name": "sub_140187E60"}, {"ea": "0x140194810", "name": "sub_140194810"}, {"ea": "0x1401da0b0", "name": "HV_RemoveEptHook_Wrapper"}, {"ea": "0x14e80fd83", "name": "sub_14E80FD83"}]
callees: []
--- PSEUDOCODE ---
void HV_FlushOrSyncAfterRegister()
{
  ;
}


===== HV_HandlePendingEvent size=115 proto=__int64 __fastcall(_QWORD *)
callers: [{"ea": "0x140125f40", "name": "HV_ClearPendingExceptionState"}, {"ea": "0x140126020", "name": "HV_TryFastExitPath"}, {"ea": "0x1401755b0", "name": "sub_1401755B0"}, {"ea": "0x140187e60", "name": "sub_140187E60"}, {"ea": "0x14e811e71", "name": "sub_14E811E71"}]
callees: [{"ea": "0x140065c80", "name": "sub_140065C80"}, {"ea": "0x1400661d0", "name": "sub_1400661D0"}, {"ea": "0x140066580", "name": "sub_140066580"}, {"ea": "0x140127b80", "name": "HV_HandlePendingEvent"}]
--- PSEUDOCODE ---
__int64 __fastcall HV_HandlePendingEvent(_QWORD *a1)
{
  unsigned __int64 v2; // rcx
  _QWORD *v3; // rdx
  __int64 result; // rax
  __int64 v5; // rdx
  __int64 v6; // rcx
  __int64 v7; // [rsp+30h] [rbp+8h] BYREF

  v2 = a1[2];
  if ( v2 )
  {
    v3 = (_QWORD *)a1[1];
    if ( a1[7] >> 3 <= v2 )
    {
      sub_140066580(v2, v3);
      *(_QWORD *)a1[1] = a1[1];
      *(_QWORD *)(a1[1] + 8LL) = a1[1];
      a1[2] = 0;
      v5 = a1[4];
      v6 = a1[3];
      v7 = a1[1];
      return sub_140065C80(v6, v5, &v7);
    }
    else
    {
      return sub_1400661D0(a1, *v3, a1[1]);
    }
  }
  return result;
}


===== Hook_LogListEntry size=395 proto=void __fastcall(__int64, int, __int64)
callers: [{"ea": "0x14017baf0", "name": "sub_14017BAF0"}, {"ea": "0x1401906e0", "name": "Hook_NtApi_VmExitHandler"}]
callees: [{"ea": "0x14003e1e0", "name": "HV_FlushOrSyncAfterRegister"}, {"ea": "0x14015cf60", "name": "Hv_ReadGuestU32"}, {"ea": "0x14015d5c0", "name": "Hv_ReadGuestU64"}, {"ea": "0x14017aea0", "name": "Hook_LogListEntry"}]
--- PSEUDOCODE ---
void __fastcall ACE_LogListHook(__int64 a1, int a2, __int64 a3)
{
  __int64 v4; // r9
  __int64 v5; // rbx

  while ( _InterlockedCompareExchange64(&qword_14DB95CB0, 1, 0) == 1 )
    _mm_pause();
  _InterlockedExchange64(&qword_14DB95CB0, 0);
  if ( (_DWORD)qword_14DD8A2C0 || (a2 & 0xF0000000) == 0xA0000000 )
  {
    v4 = _InterlockedIncrement64(&qword_14DB95CD0);
    if ( v4 <= 16 || v4 == 50 * (v4 / 50) )
    {
      if ( a3 && (v5 = *(_QWORD *)(a3 + 128), (unsigned __int64)(v5 - 0xFFFF) <= 0x7FFFFFFF0000LL) )
      {
        Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, v5 + 40);
      }
      else if ( !a3 )
      {
LABEL_12:
        HV_FlushOrSyncAfterRegister();
        return;
      }
      Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, *(_QWORD *)(a3 + 160) - *(unsigned int *)(g_Hook_OffsetTable + 252));
      goto LABEL_12;
    }
  }
}


===== Hook_LookupByPid size=435 proto=char __fastcall(int, __int64, __int64, __int64)
callers: [{"ea": "0x14017baf0", "name": "sub_14017BAF0"}, {"ea": "0x1401906e0", "name": "Hook_NtApi_VmExitHandler"}]
callees: [{"ea": "0x1400ff650", "name": "sub_1400FF650"}, {"ea": "0x14017abc0", "name": "Hook_LookupByPid"}]
--- PSEUDOCODE ---
// FNV-1a hash lookup of ListHook by PID; remove node if found
char __fastcall ACE_LookupListHookByPid(int a1, __int64 a2, __int64 a3, __int64 a4)
{
  __int64 *v6; // rcx
  __int64 v7; // rax
  __int64 v8; // rcx
  __int64 v9; // rdx
  __int64 *v10; // r8
  __int64 v11; // rax
  __int64 v12; // rax

  if ( !a1 || !a2 )
    return 0;
  LOBYTE(a4) = 0;
  while ( _InterlockedCompareExchange64(&qword_14DB95CB0, 1, 0) == 1 )
    _mm_pause();
  v6 = (__int64 *)(g_Hook_ListBuckets
                 + 16
                 * (g_Hook_ListMask
                  & (0x100000001B3LL
                   * (HIBYTE(a1)
                    ^ (0x100000001B3LL
                     * (BYTE2(a1)
                      ^ (0x100000001B3LL
                       * (BYTE1(a1) ^ (0x100000001B3LL * ((unsigned __int8)a1 ^ 0xCBF29CE484222325uLL))))))))));
  v7 = v6[1];
  if ( v7 == g_Hook_ListSentinel )
    goto LABEL_10;
  v8 = *v6;
  if ( a1 != *(_DWORD *)(v7 + 16) )
  {
    while ( v7 != v8 )
    {
      v7 = *(_QWORD *)(v7 + 8);
      if ( a1 == *(_DWORD *)(v7 + 16) )
        goto LABEL_11;
    }
LABEL_10:
    v7 = 0;
  }
LABEL_11:
  v9 = g_Hook_ListSentinel;
  if ( v7 )
    v9 = v7;
  if ( v9 != g_Hook_ListSentinel )
  {
    *(_OWORD *)a2 = *(_OWORD *)(v9 + 24);
    *(_QWORD *)(a2 + 16) = *(_QWORD *)(v9 + 40);
    v10 = (__int64 *)(g_Hook_ListBuckets
                    + 16
                    * (g_Hook_ListMask
                     & (0x100000001B3LL
                      * (*(unsigned __int8 *)(v9 + 19)
                       ^ (0x100000001B3LL
                        * (*(unsigned __int8 *)(v9 + 18)
                         ^ (0x100000001B3LL
                          * (*(unsigned __int8 *)(v9 + 17)
                           ^ (0x100000001B3LL * (*(unsigned __int8 *)(v9 + 16) ^ 0xCBF29CE484222325uLL))))))))));
    v11 = *v10;
    if ( v10[1] == v9 )
    {
      if ( v11 == v9 )
      {
        v12 = g_Hook_ListSentinel;
        *v10 = g_Hook_ListSentinel;
      }
      else
      {
        v12 = *(_QWORD *)(v9 + 8);
      }
      v10[1] = v12;
    }
    else if ( v11 == v9 )
    {
      *v10 = *(_QWORD *)v9;
    }
    sub_1400FF650(&g_Hook_ListSentinel, v9, v10, a4);
    LOBYTE(a4) = 1;
  }
  _InterlockedExchange64(&qword_14DB95CB0, 0);
  return a4;
}


===== sub_14015D2D0 size=422 proto=double __fastcall(__int64, unsigned __int64)
callers: [{"ea": "0x14015b960", "name": "sub_14015B960"}, {"ea": "0x14015bce0", "name": "sub_14015BCE0"}, {"ea": "0x14015c2c0", "name": "sub_14015C2C0"}, {"ea": "0x14015c420", "name": "sub_14015C420"}, {"ea": "0x14015c5a0", "name": "sub_14015C5A0"}, {"ea": "0x14015c740", "name": "sub_14015C740"}, {"ea": "0x14015d2d0", "name": "sub_14015D2D0"}, {"ea": "0x140164f60", "name": "sub_140164F60"}, {"ea": "0x140166690", "name": "sub_140166690"}, {"ea": "0x1401686a0", "name": "sub_1401686A0"}, {"ea": "0x14016a7b0", "name": "sub_14016A7B0"}, {"ea": "0x14016dd70", "name": "sub_14016DD70"}, {"ea": "0x1401703f0", "name": "sub_1401703F0"}, {"ea": "0x1401739e0", "name": "sub_1401739E0"}, {"ea": "0x140187b90", "name": "sub_140187B90"}, {"ea": "0x140188480", "name": "sub_140188480"}, {"ea": "0x1401891d0", "name": "Hook_InstallAll"}, {"ea": "0x1401906e0", "name": "Hook_NtApi_VmExitHandler"}]
callees: [{"ea": "0x1400fd010", "name": "sub_1400FD010"}, {"ea": "0x14011c2a0", "name": "HV_TranslateGuestVa_Present"}, {"ea": "0x14011fb10", "name": "HV_Rdgsbase"}, {"ea": "0x14015d2d0", "name": "sub_14015D2D0"}, {"ea": "0x1401ea340", "name": "Util_Memcpy"}]
--- PSEUDOCODE ---
double __fastcall sub_14015D2D0(__int64 a1, unsigned __int64 a2)
{
  double result; // xmm0_8
  __int64 v5; // r14
  unsigned __int64 v6; // rdi
  __int64 v7; // rax
  unsigned __int64 v8; // rbx
  int v9; // [rsp+24h] [rbp-74h]
  unsigned int v10; // [rsp+A8h] [rbp+10h] BYREF
  unsigned __int64 v11; // [rsp+B0h] [rbp+18h] BYREF

  if ( a2 <= 0x10000 )
    return 0.0;
  if ( g_Wddm_DisableOverlay == 0 )
  {
    if ( HV_Rdgsbase() == 0 )
      return sub_14015D2D0(a1, a2);
    if ( a2 < 0x7FFFFFFFFFFFLL )
    {
      v10 = 0;
      sub_1400FD010();
      *(_QWORD *)&result = v10;
      *(_DWORD *)(a1 + 64) = v9;
      return result;
    }
    return 0.0;
  }
  if ( *(_DWORD *)(a1 + 4) != *(_DWORD *)a1 )
    return 0.0;
  v5 = *(_QWORD *)(a1 + 8);
  if ( v5 == 0 )
    return 0.0;
  v6 = 0;
  v10 = 0;
  do
  {
    v11 = 0;
    v7 = HV_TranslateGuestVa_Present(v5, v6 + a2, &v11);
    if ( (unsigned __int64)(v7 - 1) > 0x7FFFFFFFFFLL )
      break;
    v8 = v11;
    if ( 4 - v6 < v11 )
      v8 = 4 - v6;
    Util_Memcpy((char *)&v10 + v6, (char *)(v7 + 0x7F8000000000LL), v8);
    v6 += v8;
  }
  while ( v6 < 4 );
  *(_QWORD *)&result = v10;
  return result;
}


===== sub_1401625B0 size=358 proto=__int64 __fastcall(__int64)
callers: [{"ea": "0x1400015a0", "name": "sub_1400015A0"}, {"ea": "0x1400015c0", "name": "sub_1400015C0"}, {"ea": "0x140001a30", "name": "sub_140001A30"}, {"ea": "0x140001a50", "name": "sub_140001A50"}, {"ea": "0x140001a70", "name": "sub_140001A70"}, {"ea": "0x140001f90", "name": "sub_140001F90"}, {"ea": "0x14016cfd0", "name": "sub_14016CFD0"}, {"ea": "0x140172840", "name": "sub_140172840"}, {"ea": "0x140176310", "name": "sub_140176310"}]
callees: [{"ea": "0x1400029f0", "name": "Mem_HeapFree"}, {"ea": "0x140133e10", "name": "Mem_HeapAlloc"}, {"ea": "0x1401536b0", "name": "HV_Dispatch"}, {"ea": "0x1401625b0", "name": "sub_1401625B0"}]
--- PSEUDOCODE ---
__int64 __fastcall sub_1401625B0(__int64 a1)
{
  _QWORD *v2; // rax
  __int64 v3; // rbx
  _OWORD *v4; // rax
  _QWORD *v5; // rdi
  unsigned __int64 v6; // rcx
  __int64 v7; // rdx
  _QWORD *v8; // rax
  __int64 retaddr; // [rsp+38h] [rbp+0h]

  *(_DWORD *)a1 = 0;
  *(_QWORD *)(a1 + 8) = 0;
  *(_QWORD *)(a1 + 16) = 0;
  v2 = Mem_HeapAlloc(0x20u);
  if ( v2 == nullptr )
  {
    HV_Dispatch(0x3678656u, 32, retaddr, retaddr - 0x140000000LL, 0);
    JUMPOUT(0x140162715LL);
  }
  v2[2] = 0;
  v2[3] = 0;
  *v2 = v2;
  v2[1] = v2;
  *(_QWORD *)(a1 + 8) = v2;
  *(_QWORD *)(a1 + 24) = 0;
  *(_QWORD *)(a1 + 32) = 0;
  *(_QWORD *)(a1 + 40) = 0;
  *(_QWORD *)(a1 + 48) = 7;
  *(_QWORD *)(a1 + 56) = 8;
  *(_DWORD *)a1 = 1065353216;
  v3 = *(_QWORD *)(a1 + 8);
  v4 = Mem_HeapAlloc(0x80u);
  v5 = v4;
  if ( v4 == nullptr )
  {
    HV_Dispatch(0x3678656u, 128, retaddr, retaddr - 0x140000000LL, 0);
    __debugbreak();
  }
  *v4 = 0;
  v4[1] = 0;
  v4[2] = 0;
  v4[3] = 0;
  v4[4] = 0;
  v4[5] = 0;
  v4[6] = 0;
  v4[7] = 0;
  v6 = *(_QWORD *)(a1 + 24);
  v7 = (__int64)(*(_QWORD *)(a1 + 40) - v6) >> 3;
  if ( v7 != 0 )
    Mem_HeapFree(v6, 8 * v7);
  v8 = v5 + 16;
  *(_QWORD *)(a1 + 24) = v5;
  *(_QWORD *)(a1 + 32) = v5 + 16;
  *(_QWORD *)(a1 + 40) = v5 + 16;
  do
    *v5++ = v3;
  while ( v5 != v8 );
  return a1;
}


===== sub_140166D10 size=412 proto=_OWORD *__fastcall(int *, _OWORD *, unsigned __int64)
callers: [{"ea": "0x140164f60", "name": "sub_140164F60"}, {"ea": "0x140165ae0", "name": "sub_140165AE0"}, {"ea": "0x140165bf0", "name": "sub_140165BF0"}, {"ea": "0x140165d30", "name": "sub_140165D30"}, {"ea": "0x140166d10", "name": "sub_140166D10"}, {"ea": "0x140168a70", "name": "sub_140168A70"}, {"ea": "0x14016d230", "name": "sub_14016D230"}, {"ea": "0x140172530", "name": "sub_140172530"}, {"ea": "0x140172be0", "name": "sub_140172BE0"}, {"ea": "0x140172ee0", "name": "sub_140172EE0"}, {"ea": "0x1401734e0", "name": "sub_1401734E0"}, {"ea": "0x1401891d0", "name": "Hook_InstallAll"}]
callees: [{"ea": "0x1400fd010", "name": "sub_1400FD010"}, {"ea": "0x14011c2a0", "name": "HV_TranslateGuestVa_Present"}, {"ea": "0x14011fb10", "name": "HV_Rdgsbase"}, {"ea": "0x140166d10", "name": "sub_140166D10"}, {"ea": "0x1401ea340", "name": "Util_Memcpy"}]
--- PSEUDOCODE ---
_OWORD *__fastcall sub_140166D10(int *a1, _OWORD *a2, unsigned __int64 a3)
{
  __int128 v6; // xmm0
  __int64 v7; // r15
  unsigned __int64 v8; // rsi
  __int64 v9; // rax
  unsigned __int64 v10; // rbx
  _QWORD v12[2]; // [rsp+20h] [rbp-88h] BYREF
  int v13; // [rsp+30h] [rbp-78h]
  int v14; // [rsp+34h] [rbp-74h]
  int v15; // [rsp+38h] [rbp-70h]
  int v16; // [rsp+40h] [rbp-68h]
  __int64 v17; // [rsp+48h] [rbp-60h]
  unsigned __int64 v18; // [rsp+50h] [rbp-58h]
  _QWORD *v19; // [rsp+58h] [rbp-50h]
  unsigned __int64 v20; // [rsp+C0h] [rbp+18h] BYREF

  if ( a3 > 0x10000 )
  {
    if ( g_Wddm_DisableOverlay == 0 )
    {
      if ( HV_Rdgsbase() != 0 )
      {
        v6 = 0;
        if ( a3 < 0x7FFFFFFFFFFFLL )
        {
          v15 = *a1;
          v13 = 4;
          v19 = v12;
          v18 = a3;
          v17 = 16;
          v16 = 0;
          *(_OWORD *)v12 = 0;
          sub_1400FD010();
          v6 = *(_OWORD *)v12;
          a1[16] = v14;
        }
        *a2 = v6;
      }
      else
      {
        sub_140166D10(a1, a2, a3);
      }
      return a2;
    }
    if ( a1[1] == *a1 )
    {
      v7 = *((_QWORD *)a1 + 1);
      if ( v7 != 0 )
      {
        v8 = 0;
        *(_OWORD *)v12 = 0;
        do
        {
          v20 = 0;
          v9 = HV_TranslateGuestVa_Present(v7, v8 + a3, &v20);
          if ( (unsigned __int64)(v9 - 1) > 0x7FFFFFFFFFLL )
            break;
          v10 = v20;
          if ( 16 - v8 < v20 )
            v10 = 16 - v8;
          Util_Memcpy((char *)v12 + v8, (char *)(v9 + 0x7F8000000000LL), v10);
          v8 += v10;
        }
        while ( v8 < 0x10 );
        *a2 = *(_OWORD *)v12;
        return a2;
      }
    }
  }
  *a2 = 0;
  return a2;
}


===== sub_1401687E0 size=645 proto=__int64 __fastcall(__int64)
callers: [{"ea": "0x140168a70", "name": "sub_140168A70"}]
callees: [{"ea": "0x1400fd010", "name": "sub_1400FD010"}, {"ea": "0x14011c2a0", "name": "HV_TranslateGuestVa_Present"}, {"ea": "0x14011fb10", "name": "HV_Rdgsbase"}, {"ea": "0x1401687e0", "name": "sub_1401687E0"}, {"ea": "0x1401d6a50", "name": "sub_1401D6A50"}, {"ea": "0x1401ea340", "name": "Util_Memcpy"}]
--- PSEUDOCODE ---
__int64 __fastcall sub_1401687E0(__int64 a1)
{
  __int64 result; // rax
  int *v2; // rbx
  unsigned __int64 v3; // rbp
  int v4; // ecx
  bool v5; // zf
  __int64 v6; // r14
  unsigned __int64 i; // rsi
  __int64 v8; // rax
  unsigned __int64 v9; // rbx
  int v10; // ecx
  __int64 v11; // rax
  int v12; // [rsp+30h] [rbp-578h] BYREF
  int v13; // [rsp+34h] [rbp-574h]
  int v14; // [rsp+38h] [rbp-570h]
  int v15; // [rsp+40h] [rbp-568h]
  __int64 v16; // [rsp+48h] [rbp-560h]
  unsigned __int64 v17; // [rsp+50h] [rbp-558h]
  _BYTE *v18; // [rsp+58h] [rbp-550h]
  _BYTE v19[1280]; // [rsp+80h] [rbp-528h] BYREF
  unsigned __int64 v20; // [rsp+5B8h] [rbp+10h] BYREF

  result = *(unsigned int *)(g_Hook_OffsetTable + 132);
  if ( (_DWORD)result != 0 )
    return result;
  result = *(unsigned int *)(g_Hook_NtosOffsetsCtx + 2000);
  if ( (_DWORD)result != 0 )
    return result;
  v2 = (int *)g_Hook_GuestCr3OrCtx;
  v3 = a1 - 1280;
  if ( (unsigned __int64)(a1 - 1280) <= 0x10000 )
    return 0;
  if ( g_Wddm_DisableOverlay != 0 )
  {
    if ( *(_DWORD *)(g_Hook_GuestCr3OrCtx + 4) != *(_DWORD *)g_Hook_GuestCr3OrCtx )
      return 0;
    v6 = *(_QWORD *)(g_Hook_GuestCr3OrCtx + 8);
    if ( v6 == 0 )
      return 0;
    for ( i = 0; i < 0x500; i += v9 )
    {
      v20 = 0;
      v8 = HV_TranslateGuestVa_Present(v6, i + v3, &v20);
      if ( (unsigned __int64)(v8 - 1) > 0x7FFFFFFFFFLL )
        break;
      v9 = v20;
      if ( 1280 - i < v20 )
        v9 = 1280 - i;
      Util_Memcpy(&v19[i], (char *)(v8 + 0x7F8000000000LL), v9);
    }
    v5 = i == 1280;
  }
  else
  {
    if ( v3 >= 0x7FFFFFFFFFFFLL )
    {
      v4 = 0;
      goto LABEL_19;
    }
    if ( HV_Rdgsbase() == 0 )
    {
      v4 = sub_1401D6A50((_DWORD)v2, v3, (unsigned int)v19, 1280, 0);
      goto LABEL_19;
    }
    v14 = *v2;
    v18 = v19;
    v12 = 4;
    v17 = v3;
    v16 = 1280;
    v15 = 0;
    sub_1400FD010(&v12);
    v5 = v13 == 0;
    v2[16] = v13;
  }
  v4 = v5;
LABEL_19:
  if ( v4 == 0 )
    return 0;
  v10 = 1272;
  v11 = 1272;
  while ( v19[v11] != 72
       || v19[v11 + 1] != 0x89
       || v19[v11 + 2] != 76
       || v19[v11 + 3] != 36
       || v19[v11 + 5] != 72
       || v19[v11 + 6] != 0x83
       || v19[v11 + 7] != 0xC1 )
  {
    --v10;
    if ( --v11 < 0 )
    {
      _InterlockedCompareExchange(&dword_14026BF70, 0, 1);
      return 0;
    }
  }
  result = (unsigned int)(unsigned __int8)v19[v10 + 4] + 8;
  *(_DWORD *)(g_Hook_NtosOffsetsCtx + 2000) = result;
  return result;
}


===== sub_14016B1C0 size=312 proto=void __fastcall(__int64, __int64, unsigned __int8)
callers: [{"ea": "0x140168a70", "name": "sub_140168A70"}, {"ea": "0x14016b1c0", "name": "sub_14016B1C0"}, {"ea": "0x1401891d0", "name": "Hook_InstallAll"}]
callees: [{"ea": "0x1400fd010", "name": "sub_1400FD010"}, {"ea": "0x14011cac0", "name": "sub_14011CAC0"}, {"ea": "0x14011fb10", "name": "HV_Rdgsbase"}, {"ea": "0x14016b1c0", "name": "sub_14016B1C0"}]
--- PSEUDOCODE ---
void __fastcall sub_14016B1C0(__int64 a1, __int64 a2, unsigned __int8 a3)
{
  __int64 v5; // rcx
  unsigned __int8 v7; // [rsp+90h] [rbp+18h] BYREF

  v7 = a3;
  if ( (unsigned __int64)(a2 - 0x10000) <= 0x7FFFFFFEFFFELL )
  {
    if ( g_Wddm_DisableOverlay != 0 )
    {
      if ( *(_DWORD *)(a1 + 4) == *(_DWORD *)a1 )
      {
        v5 = *(_QWORD *)(a1 + 8);
        if ( v5 != 0 )
          sub_14011CAC0(v5, a2, (__int64)&v7, 1u);
      }
    }
    else if ( HV_Rdgsbase() != 0 )
    {
      sub_1400FD010();
      *(_DWORD *)(a1 + 64) = 0;
    }
    else
    {
      sub_14016B1C0(a1, a2, a3);
    }
  }
}


===== sub_14016B300 size=271 proto=__int64 __fastcall(int *, __int64, __int64)
callers: [{"ea": "0x140168a70", "name": "sub_140168A70"}, {"ea": "0x14016b300", "name": "sub_14016B300"}]
callees: [{"ea": "0x1400fd010", "name": "sub_1400FD010"}, {"ea": "0x14011cac0", "name": "sub_14011CAC0"}, {"ea": "0x14011fb10", "name": "HV_Rdgsbase"}, {"ea": "0x14016b300", "name": "sub_14016B300"}]
--- PSEUDOCODE ---
__int64 __fastcall sub_14016B300(int *a1, __int64 a2, __int64 a3)
{
  __int64 v6; // rcx
  __int64 v7; // [rsp+20h] [rbp-68h] BYREF
  int v8; // [rsp+38h] [rbp-50h]
  __int64 v9; // [rsp+3Ch] [rbp-4Ch]
  int v10; // [rsp+44h] [rbp-44h]
  __int64 v11; // [rsp+48h] [rbp-40h]
  __int64 v12; // [rsp+50h] [rbp-38h]
  __int64 *v13; // [rsp+58h] [rbp-30h]
  __int128 v14; // [rsp+60h] [rbp-28h]
  __int64 v15; // [rsp+70h] [rbp-18h]
  __int64 v16; // [rsp+98h] [rbp+10h] BYREF

  v7 = a3;
  if ( (unsigned __int64)(a2 - 0x10000) > 0x7FFFFFFEFFFELL )
    return 0;
  if ( g_Wddm_DisableOverlay != 0 )
  {
    if ( a1[1] == *a1 )
    {
      v6 = *((_QWORD *)a1 + 1);
      if ( v6 != 0 )
        return sub_14011CAC0(v6, a2, (__int64)&v7, 8u) == 8;
    }
    return 0;
  }
  v16 = a3;
  if ( HV_Rdgsbase() == 0 )
    return sub_14016B300(a1, a2, v16);
  v8 = *a1;
  v13 = &v16;
  v9 = 0;
  v10 = 0;
  v14 = 0;
  v15 = 0;
  v12 = a2;
  v11 = 8;
  sub_1400FD010();
  a1[16] = 0;
  return 1;
}


===== sub_14016B410 size=291 proto=__int64 __fastcall(int *, __int64, __int64)
callers: [{"ea": "0x140168a70", "name": "sub_140168A70"}, {"ea": "0x14016b410", "name": "sub_14016B410"}, {"ea": "0x1401881d0", "name": "sub_1401881D0"}]
callees: [{"ea": "0x1400fd010", "name": "sub_1400FD010"}, {"ea": "0x14011cac0", "name": "sub_14011CAC0"}, {"ea": "0x14011fb10", "name": "HV_Rdgsbase"}, {"ea": "0x14016b410", "name": "sub_14016B410"}]
--- PSEUDOCODE ---
__int64 __fastcall sub_14016B410(int *a1, __int64 a2, __int64 a3)
{
  int v5; // eax
  bool v7; // zf
  __int64 v8; // rcx
  __int64 v9; // [rsp+20h] [rbp-78h] BYREF
  int v10; // [rsp+28h] [rbp-70h]
  __int64 v11; // [rsp+30h] [rbp-68h] BYREF
  int v12; // [rsp+38h] [rbp-60h]
  __int64 v13; // [rsp+40h] [rbp-58h]
  int v14; // [rsp+48h] [rbp-50h]
  __int64 v15; // [rsp+4Ch] [rbp-4Ch]
  int v16; // [rsp+54h] [rbp-44h]
  __int64 v17; // [rsp+58h] [rbp-40h]
  __int64 v18; // [rsp+60h] [rbp-38h]
  __int64 *v19; // [rsp+68h] [rbp-30h]
  __int128 v20; // [rsp+70h] [rbp-28h]
  __int64 v21; // [rsp+80h] [rbp-18h]

  if ( (unsigned __int64)(a2 - 0x10000) > 0x7FFFFFFEFFFELL )
    return 0;
  if ( g_Wddm_DisableOverlay != 0 )
  {
    if ( a1[1] == *a1 )
    {
      v8 = *((_QWORD *)a1 + 1);
      if ( v8 != 0 )
        return sub_14011CAC0(v8, a2, a3, 0xCu) == 12;
    }
    return 0;
  }
  v5 = *(_DWORD *)(a3 + 8);
  v9 = *(_QWORD *)a3;
  v10 = v5;
  if ( HV_Rdgsbase() != 0 )
  {
    v14 = *a1;
    v13 = 2;
    v19 = &v9;
    v15 = 0;
    v16 = 0;
    v20 = 0;
    v21 = 0;
    v18 = a2;
    v17 = 12;
    sub_1400FD010();
    v7 = HIDWORD(v13) == 0;
    a1[16] = HIDWORD(v13);
    return v7;
  }
  else
  {
    v11 = v9;
    v12 = v10;
    return sub_14016B410(a1, a2, &v11);
  }
}


===== sub_1401755B0 size=558 proto=__int64 __fastcall(unsigned __int64)
callers: [{"ea": "0x14015b4a0", "name": "sub_14015B4A0"}, {"ea": "0x14015b960", "name": "sub_14015B960"}, {"ea": "0x140166200", "name": "sub_140166200"}, {"ea": "0x140166690", "name": "sub_140166690"}, {"ea": "0x14016a7b0", "name": "sub_14016A7B0"}, {"ea": "0x14016cdc0", "name": "sub_14016CDC0"}, {"ea": "0x14016d230", "name": "sub_14016D230"}, {"ea": "0x14016dbc0", "name": "sub_14016DBC0"}, {"ea": "0x14016dd70", "name": "sub_14016DD70"}, {"ea": "0x140170330", "name": "sub_140170330"}, {"ea": "0x1401703f0", "name": "sub_1401703F0"}, {"ea": "0x140170d60", "name": "sub_140170D60"}, {"ea": "0x140172530", "name": "sub_140172530"}, {"ea": "0x140172e50", "name": "sub_140172E50"}, {"ea": "0x1401734e0", "name": "sub_1401734E0"}, {"ea": "0x140186cb0", "name": "sub_140186CB0"}, {"ea": "0x140186d90", "name": "sub_140186D90"}, {"ea": "0x140187b90", "name": "sub_140187B90"}, {"ea": "0x140188800", "name": "sub_140188800"}, {"ea": "0x1401891d0", "name": "Hook_InstallAll"}]
callees: [{"ea": "0x140127b80", "name": "HV_HandlePendingEvent"}, {"ea": "0x14015d5c0", "name": "Hv_ReadGuestU64"}, {"ea": "0x14016b540", "name": "sub_14016B540"}, {"ea": "0x1401755b0", "name": "sub_1401755B0"}, {"ea": "0x1401764f0", "name": "sub_1401764F0"}, {"ea": "0x140185790", "name": "Hook_PatchSoftBpTargets"}]
--- PSEUDOCODE ---
__int64 __fastcall sub_1401755B0(unsigned __int64 a1)
{
  unsigned __int64 GuestU64; // rdi
  _QWORD *v4; // rdx
  _QWORD *v5; // r8
  _QWORD *v6; // rcx
  _QWORD *v7; // rax
  _QWORD *v8; // rcx
  __int64 v9; // rax
  __int64 v10; // rbx
  __int64 v11; // rcx
  _QWORD v12[2]; // [rsp+40h] [rbp-58h] BYREF
  _BYTE v13[16]; // [rsp+50h] [rbp-48h] BYREF
  unsigned __int64 v14; // [rsp+B0h] [rbp+18h] BYREF

  GuestU64 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, a1);
  if ( *(_BYTE *)(g_Hook_NtosOffsetsCtx + 2130) == 0 )
    return GuestU64 & 0x7FFFFFFFFFFFLL;
  if ( GuestU64 <= 0x7FFFFFFFFFFFLL )
    return GuestU64;
  v14 = a1;
  Hook_PatchSoftBpTargets();
  v4 = (_QWORD *)qword_14828F2F0;
  if ( *(_QWORD *)(qword_14828F2F0 + 16) > 0x186A0u )
  {
    HV_HandlePendingEvent((_QWORD *)qword_14828F2F0);
    v4 = (_QWORD *)qword_14828F2F0;
  }
  v5 = (_QWORD *)v4[1];
  v6 = (_QWORD *)(v4[3]
                + 16
                * (v4[6]
                 & (0x100000001B3LL
                  * (HIBYTE(a1)
                   ^ (0x100000001B3LL
                    * (BYTE6(a1)
                     ^ (0x100000001B3LL
                      * (BYTE5(a1)
                       ^ (0x100000001B3LL
                        * (BYTE4(a1)
                         ^ (0x100000001B3LL
                          * (BYTE3(a1)
                           ^ (0x100000001B3LL
                            * (BYTE2(a1)
                             ^ (0x100000001B3LL
                              * (BYTE1(a1) ^ (0x100000001B3LL * ((unsigned __int8)a1 ^ 0xCBF29CE484222325uLL))))))))))))))))));
  v7 = (_QWORD *)v6[1];
  if ( v7 == v5 )
    goto LABEL_11;
  v8 = (_QWORD *)*v6;
  if ( a1 != v7[2] )
  {
    while ( v7 != v8 )
    {
      v7 = (_QWORD *)v7[1];
      if ( a1 == v7[2] )
        goto LABEL_12;
    }
LABEL_11:
    v7 = nullptr;
  }
LABEL_12:
  if ( v7 == nullptr )
    v7 = (_QWORD *)v4[1];
  if ( v7 != v5 && v7[3] == GuestU64 )
    return v7[4];
  v9 = sub_14016B540(
         *(_QWORD *)(g_Hook_NtosOffsetsCtx + 1592) + *(unsigned int *)(g_Hook_OffsetTable + 176),
         a1 - 400,
         0);
  v12[0] = GuestU64;
  v12[1] = v9;
  v10 = v9;
  sub_1401764F0(v11, v13, &v14, v12);
  return v10;
}


===== sub_140176080 size=144 proto=__int64 __fastcall(unsigned int)
callers: [{"ea": "0x140172840", "name": "sub_140172840"}, {"ea": "0x140176110", "name": "sub_140176110"}, {"ea": "0x140176160", "name": "sub_140176160"}, {"ea": "0x140176310", "name": "sub_140176310"}]
callees: [{"ea": "0x14014fee0", "name": "sub_14014FEE0"}, {"ea": "0x140175d20", "name": "sub_140175D20"}, {"ea": "0x140176080", "name": "sub_140176080"}, {"ea": "0x140176810", "name": "sub_140176810"}]
--- PSEUDOCODE ---
__int64 __fastcall sub_140176080(unsigned int a1)
{
  __int64 v2; // rdx
  __int64 v3; // rax
  __int64 result; // rax
  char v5; // [rsp+30h] [rbp+8h] BYREF
  unsigned __int16 v6; // [rsp+38h] [rbp+10h] BYREF

  v6 = 0;
  v2 = *(unsigned int *)(g_Hook_OffsetTable + 16);
  v5 = 0;
  v3 = sub_140176810(
         g_Hook_GuestCr3OrCtx,
         *(_QWORD *)(g_Hook_NtosOffsetsCtx + 1592) + v2 + 8 * ((unsigned __int64)a1 >> 18) + 8);
  result = sub_140175D20(v3 + 2 * (a1 & 0x3FFFF), &v5, &v6);
  if ( v5 != 0 )
  {
    sub_14014FEE0(result, v6, 0x14DD92210LL, 4096);
    return 0x14DD92210LL;
  }
  return result;
}


===== sub_140176110 size=70 proto=const char *__fastcall(unsigned int)
callers: [{"ea": "0x140187e60", "name": "sub_140187E60"}]
callees: [{"ea": "0x140176080", "name": "sub_140176080"}, {"ea": "0x140176110", "name": "sub_140176110"}, {"ea": "0x1401e9d70", "name": "sub_1401E9D70"}]
--- PSEUDOCODE ---
const char *__fastcall sub_140176110(unsigned int a1)
{
  __int64 v2; // rbx
  __int64 v3; // rax

  if ( a1 == 0 )
    return "NULL0";
  v2 = sub_140176080(a1);
  v3 = sub_1401E9D70(v2, qword_1401F1A30);
  if ( v3 != 0 )
    *(_BYTE *)(v3 + 2) = 0;
  return (const char *)v2;
}


===== sub_140176B60 size=618 proto=__int64 __fastcall(__int64, __int64, unsigned __int8 *, _QWORD *)
callers: [{"ea": "0x140176310", "name": "sub_140176310"}]
callees: [{"ea": "0x140002790", "name": "nullsub_3"}, {"ea": "0x140133e10", "name": "Mem_HeapAlloc"}, {"ea": "0x1401536b0", "name": "HV_Dispatch"}, {"ea": "0x140176b60", "name": "sub_140176B60"}, {"ea": "0x1401772e0", "name": "sub_1401772E0"}]
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


===== sub_140176FD0 size=779 proto=__int64 __fastcall(float *, __int64, unsigned __int8 *)
callers: [{"ea": "0x140175230", "name": "sub_140175230"}, {"ea": "0x140187e60", "name": "sub_140187E60"}]
callees: [{"ea": "0x140002790", "name": "nullsub_3"}, {"ea": "0x1400669f0", "name": "sub_1400669F0"}, {"ea": "0x140133e10", "name": "Mem_HeapAlloc"}, {"ea": "0x1401536b0", "name": "HV_Dispatch"}, {"ea": "0x140176fd0", "name": "sub_140176FD0"}, {"ea": "0x1401e9c60", "name": "sub_1401E9C60"}]
--- PSEUDOCODE ---
__int64 __fastcall sub_140176FD0(float *a1, __int64 a2, unsigned __int8 *a3)
{
  _QWORD *v6; // rbp
  unsigned __int64 v7; // r15
  __int64 v8; // rcx
  _QWORD *v9; // rax
  __int64 result; // rax
  _QWORD *v11; // rax
  __int64 v12; // rdx
  _QWORD *v13; // rbx
  __int64 v14; // rcx
  bool v15; // sf
  __int64 v16; // rcx
  unsigned __int64 v17; // rdi
  float v18; // xmm0_4
  unsigned __int64 v19; // rax
  float v20; // xmm2_4
  float v21; // xmm0_4
  unsigned __int64 v22; // rcx
  unsigned __int64 v23; // rax
  unsigned __int64 v24; // rcx
  __int64 v25; // rdx
  _QWORD *v26; // rax
  _QWORD *v27; // rdx
  __int64 v28; // rcx
  _QWORD *v29; // rdx
  __int64 v30; // rcx
  __int64 v31; // rax
  _QWORD *v32; // r8
  __int64 retaddr; // [rsp+48h] [rbp+0h]

  v6 = *((_QWORD **)a1 + 1);
  v7 = 0x100000001B3LL
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
  v8 = *((_QWORD *)a1 + 3);
  v9 = *(_QWORD **)(v8 + 16 * (*((_QWORD *)a1 + 6) & v7) + 8);
  if ( v9 != v6 )
  {
    if ( *(_QWORD *)a3 == v9[2] )
    {
LABEL_5:
      *(_QWORD *)a2 = v9;
      *(_BYTE *)(a2 + 8) = 0;
      return a2;
    }
    while ( v9 != *(_QWORD **)(v8
                             + 16
                             * (*((_QWORD *)a1 + 6)
                              & (0x100000001B3LL
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
                                         * (a3[2]
                                          ^ (0x100000001B3LL
                                           * (a3[1] ^ (0x100000001B3LL * (*a3 ^ 0xCBF29CE484222325uLL)))))))))))))))))) )
    {
      v9 = (_QWORD *)v9[1];
      if ( *(_QWORD *)a3 == v9[2] )
        goto LABEL_5;
    }
    v6 = v9;
  }
  if ( *((_QWORD *)a1 + 2) == 0x666666666666666LL )
  {
    nullsub_3();
    JUMPOUT(0x1401772DALL);
  }
  v11 = Mem_HeapAlloc(0x28u);
  v13 = v11;
  if ( v11 == nullptr )
  {
    HV_Dispatch(0x3678656u, 40, retaddr, retaddr - 0x140000000LL, 0);
    __debugbreak();
  }
  *(_OWORD *)v11 = 0;
  *((_OWORD *)v11 + 1) = 0;
  v11[4] = 0;
  v11[2] = *(_QWORD *)a3;
  v11[3] = 0;
  *((_DWORD *)v11 + 8) = 0;
  v14 = *((_QWORD *)a1 + 2);
  v15 = v14 + 1 < 0;
  v16 = v14 + 1;
  v17 = *((_QWORD *)a1 + 7);
  if ( v15 )
  {
    v19 = v16;
    v16 &= 1u;
    v18 = (float)(int)(v16 | (v19 >> 1)) + (float)(int)(v16 | (v19 >> 1));
  }
  else
  {
    v18 = (float)(int)v16;
  }
  if ( (v17 & 0x8000000000000000uLL) != 0LL )
  {
    v16 = *((_QWORD *)a1 + 7) & 1LL | (v17 >> 1);
    v20 = (float)(int)v16 + (float)(int)v16;
  }
  else
  {
    v20 = (float)(int)v17;
  }
  if ( (float)(v18 / v20) > *a1 )
  {
    v21 = sub_1401E9C60(v16, v12);
    v22 = 0;
    if ( v21 >= 9.223372e18 )
    {
      v21 = v21 - 9.223372e18;
      if ( v21 < 9.223372e18 )
        v22 = 0x8000000000000000uLL;
    }
    v23 = v22 + (unsigned int)(int)v21;
    v24 = 8;
    if ( v23 > 8 )
      v24 = v23;
    if ( v17 < v24 )
    {
      if ( v17 >= 0x200 || (v17 *= 8LL, v17 < v24) )
        v17 = v24;
    }
    sub_1400669F0(a1, v17);
    v25 = *((_QWORD *)a1 + 3);
    v6 = *((_QWORD **)a1 + 1);
    v26 = *(_QWORD **)(v25 + 16 * (v7 & *((_QWORD *)a1 + 6)) + 8);
    if ( v26 != v6 )
    {
      v27 = *(_QWORD **)(v25 + 16 * (v7 & *((_QWORD *)a1 + 6)));
      v28 = v13[2];
      if ( v28 == v26[2] )
      {
LABEL_29:
        v6 = (_QWORD *)*v26;
      }
      else
      {
        while ( v26 != v27 )
        {
          v26 = (_QWORD *)v26[1];
          if ( v28 == v26[2] )
            goto LABEL_29;
        }
        v6 = v26;
      }
    }
  }
  v29 = (_QWORD *)v6[1];
  ++*((_QWORD *)a1 + 2);
  *v13 = v6;
  v13[1] = v29;
  *v29 = v13;
  v6[1] = v13;
  v30 = *((_QWORD *)a1 + 3);
  v31 = 2 * (v7 & *((_QWORD *)a1 + 6));
  v32 = *(_QWORD **)(v30 + 16 * (v7 & *((_QWORD *)a1 + 6)));
  if ( v32 == *((_QWORD **)a1 + 1) )
  {
    *(_QWORD *)(v30 + 16 * (v7 & *((_QWORD *)a1 + 6))) = v13;
LABEL_36:
    *(_QWORD *)(v30 + 8 * v31 + 8) = v13;
    goto LABEL_37;
  }
  if ( v32 == v6 )
  {
    *(_QWORD *)(v30 + 16 * (v7 & *((_QWORD *)a1 + 6))) = v13;
    *(_QWORD *)a2 = v13;
    *(_BYTE *)(a2 + 8) = 1;
    return a2;
  }
  if ( *(_QWORD **)(v30 + 16 * (v7 & *((_QWORD *)a1 + 6)) + 8) == v29 )
    goto LABEL_36;
LABEL_37:
  *(_QWORD *)a2 = v13;
  result = a2;
  *(_BYTE *)(a2 + 8) = 1;
  return result;
}


===== sub_140178FB0 size=254 proto=char __fastcall(int, _QWORD *)
callers: [{"ea": "0x140179540", "name": "sub_140179540"}, {"ea": "0x140179790", "name": "sub_140179790"}]
callees: [{"ea": "0x140178fb0", "name": "sub_140178FB0"}]
--- PSEUDOCODE ---
char __fastcall sub_140178FB0(int a1, _QWORD *a2)
{
  char v3; // r10
  __int64 *v4; // rcx
  __int64 v5; // rax
  __int64 v6; // rcx
  __int64 v7; // rcx

  if ( a1 == 0 || a2 == nullptr )
    return 0;
  v3 = 0;
  while ( _InterlockedCompareExchange64(&qword_14DB95CB8, 1, 0) == 1 )
    _mm_pause();
  v4 = (__int64 *)(qword_14828F318
                 + 16
                 * (qword_14828F330
                  & (0x100000001B3LL
                   * (HIBYTE(a1)
                    ^ (0x100000001B3LL
                     * (BYTE2(a1)
                      ^ (0x100000001B3LL
                       * (BYTE1(a1) ^ (0x100000001B3LL * ((unsigned __int8)a1 ^ 0xCBF29CE484222325uLL))))))))));
  v5 = v4[1];
  if ( v5 == qword_14828F308 )
    goto LABEL_10;
  v6 = *v4;
  if ( a1 != *(_DWORD *)(v5 + 16) )
  {
    while ( v5 != v6 )
    {
      v5 = *(_QWORD *)(v5 + 8);
      if ( a1 == *(_DWORD *)(v5 + 16) )
        goto LABEL_11;
    }
LABEL_10:
    v5 = 0;
  }
LABEL_11:
  v7 = qword_14828F308;
  if ( v5 != 0 )
    v7 = v5;
  if ( v7 != qword_14828F308 )
  {
    v3 = 1;
    *a2 = *(_QWORD *)(v7 + 24);
  }
  _InterlockedExchange64(&qword_14DB95CB8, 0);
  return v3;
}


===== sub_140179340 size=498 proto=__int64 __fastcall(__int64, __int64)
callers: [{"ea": "0x140179540", "name": "sub_140179540"}]
callees: [{"ea": "0x14015cf60", "name": "Hv_ReadGuestU32"}, {"ea": "0x14015d5c0", "name": "Hv_ReadGuestU64"}, {"ea": "0x140176810", "name": "sub_140176810"}, {"ea": "0x140179340", "name": "sub_140179340"}]
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


===== sub_14017B600 size=872 proto=void __fastcall(__int64, __int64)
callers: [{"ea": "0x14017baf0", "name": "sub_14017BAF0"}]
callees: [{"ea": "0x14015cdc0", "name": "Hv_ReadGuestU8"}, {"ea": "0x14015cf60", "name": "Hv_ReadGuestU32"}, {"ea": "0x14015d5c0", "name": "Hv_ReadGuestU64"}, {"ea": "0x140176810", "name": "sub_140176810"}, {"ea": "0x14017b030", "name": "sub_14017B030"}, {"ea": "0x14017b600", "name": "sub_14017B600"}, {"ea": "0x1401ea040", "name": "Util_Memset"}]
--- PSEUDOCODE ---
void __fastcall sub_14017B600(__int64 a1, __int64 a2)
{
  __int64 v4; // rcx
  __int128 v5; // xmm1
  __int128 v6; // xmm0
  __int128 v7; // xmm1
  __int128 v8; // xmm0
  __int128 v9; // xmm1
  __int128 v10; // xmm0
  __int128 v11; // xmm1
  __int128 v12; // xmm0
  __int128 v13; // xmm1
  __int64 v14; // rax
  unsigned __int64 GuestU64; // rax
  __int64 v16; // rax
  __int64 v17; // rcx
  int GuestU32; // eax
  __int64 v19; // rcx
  int v20; // eax
  __int64 v21; // rcx
  int v22; // eax
  __int64 v23; // rcx
  unsigned __int8 GuestU8; // al
  __int64 v25; // rcx
  __int64 v26; // rax
  __int64 v27; // rcx
  int v28; // eax
  __int64 v29; // rcx
  int v30; // eax
  __int64 v31; // rcx
  int v32; // eax
  __int64 v33; // rcx
  int v34; // eax
  __int64 v35; // rcx
  char v36; // al
  __int64 v37; // rcx
  char v38; // al
  __int64 v39; // rcx
  __int64 v40; // rax
  __int64 v41; // rdi
  __int64 v42; // rax
  __int64 v43; // rcx
  int v44; // eax
  __int64 v45; // rcx
  int v46; // eax
  __int64 v47; // rcx
  int v48; // eax
  __int64 v49; // rcx
  int v50; // eax
  __int64 v51; // rcx
  int v52; // eax
  __int64 v53; // rcx
  __int64 v54; // rax
  __int64 v55; // rcx
  __int64 v56; // rax
  __int64 v57; // rcx
  __int64 v58; // rax
  __int64 v59; // rcx
  __int64 v60; // rax
  __int64 v61; // rcx
  int v62; // eax
  __int64 v63; // rcx
  int v64; // eax
  __int64 v65; // rcx
  _QWORD v66[24]; // [rsp+20h] [rbp-C8h] BYREF

  if ( a2 != 0 && (unsigned __int64)(a1 - 0xFFFF) <= 0x7FFFFFFF0000LL )
  {
    Util_Memset((__int64)v66, 0, 184);
    v4 = g_Hook_GuestCr3OrCtx;
    v5 = *(_OWORD *)&v66[2];
    *(_OWORD *)a2 = *(_OWORD *)v66;
    v6 = *(_OWORD *)&v66[4];
    *(_OWORD *)(a2 + 16) = v5;
    v7 = *(_OWORD *)&v66[6];
    *(_OWORD *)(a2 + 32) = v6;
    v8 = *(_OWORD *)&v66[8];
    *(_OWORD *)(a2 + 48) = v7;
    v9 = *(_OWORD *)&v66[10];
    *(_OWORD *)(a2 + 64) = v8;
    v10 = *(_OWORD *)&v66[12];
    *(_OWORD *)(a2 + 80) = v9;
    v11 = *(_OWORD *)&v66[16];
    *(_OWORD *)(a2 + 96) = v10;
    *(_OWORD *)(a2 + 112) = *(_OWORD *)&v66[14];
    v12 = *(_OWORD *)&v66[18];
    *(_OWORD *)(a2 + 128) = v11;
    v13 = *(_OWORD *)&v66[20];
    v14 = v66[22];
    *(_OWORD *)(a2 + 144) = v12;
    *(_OWORD *)(a2 + 160) = v13;
    *(_QWORD *)(a2 + 176) = v14;
    *(_BYTE *)a2 = 1;
    GuestU64 = Hv_ReadGuestU64(v4, a1 + 40);
    sub_14017B030((_BYTE *)(a2 + 16), 0x40u, GuestU64);
    v16 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, a1 + 48);
    v17 = g_Hook_GuestCr3OrCtx;
    *(_QWORD *)(a2 + 8) = v16;
    GuestU32 = Hv_ReadGuestU32(v17, a1 + 56);
    v19 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 88) = GuestU32;
    v20 = Hv_ReadGuestU32(v19, a1 + 60);
    v21 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 80) = v20;
    v22 = Hv_ReadGuestU32(v21, a1 + 64);
    v23 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 92) = v22;
    GuestU8 = Hv_ReadGuestU8(v23, a1 + 68);
    v25 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 84) = GuestU8;
    v26 = sub_140176810(v25, a1 + 72);
    v27 = g_Hook_GuestCr3OrCtx;
    *(_QWORD *)(a2 + 112) = v26;
    v28 = Hv_ReadGuestU32(v27, a1 + 88);
    v29 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 96) = v28;
    v30 = Hv_ReadGuestU32(v29, a1 + 92);
    v31 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 100) = v30;
    v32 = Hv_ReadGuestU32(v31, a1 + 96);
    v33 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 104) = v32;
    v34 = Hv_ReadGuestU32(v33, a1 + 100);
    v35 = g_Hook_GuestCr3OrCtx;
    *(_DWORD *)(a2 + 172) = v34;
    v36 = Hv_ReadGuestU8(v35, a1 + 105);
    v37 = g_Hook_GuestCr3OrCtx;
    *(_BYTE *)(a2 + 176) = v36 != 0;
    v38 = Hv_ReadGuestU8(v37, a1 + 108);
    v39 = g_Hook_GuestCr3OrCtx;
    *(_BYTE *)(a2 + 177) = v38 != 0;
    if ( (unsigned int)Hv_ReadGuestU32(v39, a1 + 124) == 20
      && (v40 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, a1 + 112),
          v41 = v40,
          (unsigned __int64)(v40 - 0xFFFF) <= 0x7FFFFFFF0000LL) )
    {
      v42 = sub_140176810(g_Hook_GuestCr3OrCtx, v40 + 64);
      v43 = g_Hook_GuestCr3OrCtx;
      *(_QWORD *)(a2 + 112) = v42;
      v44 = sub_140176810(v43, v41 + 72);
      v45 = g_Hook_GuestCr3OrCtx;
      *(_DWORD *)(a2 + 92) = v44;
      v46 = Hv_ReadGuestU32(v45, v41 + 80);
      v47 = g_Hook_GuestCr3OrCtx;
      *(_DWORD *)(a2 + 160) = v46;
      v48 = Hv_ReadGuestU32(v47, v41 + 88);
      v49 = g_Hook_GuestCr3OrCtx;
      *(_DWORD *)(a2 + 96) = v48;
      v50 = Hv_ReadGuestU32(v49, v41 + 92);
      v51 = g_Hook_GuestCr3OrCtx;
      *(_DWORD *)(a2 + 100) = v50;
      v52 = Hv_ReadGuestU32(v51, v41 + 96);
      v53 = g_Hook_GuestCr3OrCtx;
      *(_DWORD *)(a2 + 104) = v52;
      v54 = sub_140176810(v53, v41 + 104);
      v55 = g_Hook_GuestCr3OrCtx;
      *(_QWORD *)(a2 + 136) = v54;
      v56 = sub_140176810(v55, v41 + 112);
      v57 = g_Hook_GuestCr3OrCtx;
      *(_QWORD *)(a2 + 128) = v56;
      v58 = sub_140176810(v57, v41 + 120);
      v59 = g_Hook_GuestCr3OrCtx;
      *(_QWORD *)(a2 + 120) = v58;
      v60 = Hv_ReadGuestU64(v59, v41 + 128);
      v61 = g_Hook_GuestCr3OrCtx;
      *(_QWORD *)(a2 + 152) = v60;
      v62 = Hv_ReadGuestU32(v61, v41 + 140);
      v63 = g_Hook_GuestCr3OrCtx;
      *(_DWORD *)(a2 + 164) = v62;
      v64 = Hv_ReadGuestU32(v63, v41 + 152);
      v65 = g_Hook_GuestCr3OrCtx;
      *(_DWORD *)(a2 + 168) = v64;
      *(_QWORD *)(a2 + 144) = sub_140176810(v65, v41 + 232);
    }
    else
    {
      *(_QWORD *)(a2 + 120) = *(_QWORD *)(a2 + 112);
    }
  }
}


===== sub_140180A80 size=212 proto=__int64 *__fastcall(__int64, __int64 *, unsigned __int8 *)
callers: [{"ea": "0x1401777e0", "name": "sub_1401777E0"}, {"ea": "0x140178cf0", "name": "sub_140178CF0"}, {"ea": "0x140179540", "name": "sub_140179540"}, {"ea": "0x140179790", "name": "sub_140179790"}]
callees: [{"ea": "0x140180a80", "name": "sub_140180A80"}]
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


===== sub_140180D20 size=745 proto=__int64 __fastcall(__int64, __int64, unsigned __int8 *)
callers: [{"ea": "0x14017baf0", "name": "sub_14017BAF0"}, {"ea": "0x14017bdb0", "name": "sub_14017BDB0"}, {"ea": "0x14017bfa0", "name": "sub_14017BFA0"}, {"ea": "0x1401906e0", "name": "Hook_NtApi_VmExitHandler"}]
callees: [{"ea": "0x140002790", "name": "nullsub_3"}, {"ea": "0x140180d20", "name": "sub_140180D20"}, {"ea": "0x140183b50", "name": "sub_140183B50"}, {"ea": "0x1401843b0", "name": "sub_1401843B0"}, {"ea": "0x1401e9c60", "name": "sub_1401E9C60"}, {"ea": "0x1401ea040", "name": "Util_Memset"}]
--- PSEUDOCODE ---
__int64 __fastcall sub_140180D20(__int64 a1, __int64 a2, unsigned __int8 *a3)
{
  __int64 v3; // rsi
  unsigned __int64 v6; // rbp
  __int64 v7; // rax
  __int64 *v9; // rbx
  __int64 v10; // rdx
  unsigned __int64 v11; // rcx
  float v12; // xmm0_4
  unsigned __int64 v13; // rdi
  float v14; // xmm2_4
  float v15; // xmm0_4
  unsigned __int64 v16; // rcx
  unsigned __int64 v17; // rax
  unsigned __int64 v18; // rcx
  __int64 *v19; // rax
  __int64 v20; // rcx
  __int64 **v21; // r8
  __int64 v22; // rcx
  __int64 v23; // rax
  __int64 v24; // rdx

  v3 = qword_14DD8A2F8;
  v6 = 0x100000001B3LL
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
  v7 = *(_QWORD *)(qword_14DD8A308 + 16 * (qword_14DD8A320 & v6) + 8);
  if ( v7 != qword_14DD8A2F8 )
  {
    if ( *(_QWORD *)a3 == *(_QWORD *)(v7 + 16) )
    {
LABEL_5:
      *(_QWORD *)a2 = v7;
      *(_BYTE *)(a2 + 8) = 0;
      return a2;
    }
    while ( v7 != *(_QWORD *)(qword_14DD8A308
                            + 16
                            * (qword_14DD8A320
                             & (0x100000001B3LL
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
                                        * (a3[2]
                                         ^ (0x100000001B3LL * (a3[1] ^ (0x100000001B3LL * (*a3 ^ 0xCBF29CE484222325uLL)))))))))))))))))) )
    {
      v7 = *(_QWORD *)(v7 + 8);
      if ( *(_QWORD *)a3 == *(_QWORD *)(v7 + 16) )
        goto LABEL_5;
    }
    v3 = v7;
  }
  if ( qword_14DD8A300 == 0x3074988F18528LL )
  {
    nullsub_3();
    JUMPOUT(0x140181008LL);
  }
  v9 = (__int64 *)sub_1401843B0();
  v9[2] = *(_QWORD *)a3;
  Util_Memset((__int64)(v9 + 3), 0, 21616);
  v10 = qword_14DD8A300;
  v11 = qword_14DD8A300 + 1;
  if ( qword_14DD8A300 + 1 < 0 )
  {
    v11 &= 1u;
    v12 = (float)(int)(v11 | ((unsigned __int64)(qword_14DD8A300 + 1) >> 1))
        + (float)(int)(v11 | ((unsigned __int64)(qword_14DD8A300 + 1) >> 1));
  }
  else
  {
    v12 = (float)(int)v11;
  }
  v13 = qword_14DD8A328;
  if ( qword_14DD8A328 < 0 )
  {
    v11 = qword_14DD8A328 & 1 | ((unsigned __int64)qword_14DD8A328 >> 1);
    v14 = (float)(int)v11 + (float)(int)v11;
  }
  else
  {
    v14 = (float)(int)qword_14DD8A328;
  }
  if ( (float)(v12 / v14) > *(float *)&dword_14DD8A2F0 )
  {
    v15 = sub_1401E9C60(v11, qword_14DD8A300);
    v16 = 0;
    if ( v15 >= 9.223372e18 )
    {
      v15 = v15 - 9.223372e18;
      if ( v15 < 9.223372e18 )
        v16 = 0x8000000000000000uLL;
    }
    v17 = v16 + (unsigned int)(int)v15;
    v18 = 8;
    if ( v17 > 8 )
      v18 = v17;
    if ( v13 < v18 )
    {
      if ( v13 >= 0x200 || (v13 *= 8LL, v13 < v18) )
        v13 = v18;
    }
    sub_140183B50(v18, v13);
    v3 = qword_14DD8A2F8;
    v19 = *(__int64 **)(qword_14DD8A308 + 16 * (v6 & qword_14DD8A320) + 8);
    if ( v19 != (__int64 *)qword_14DD8A2F8 )
    {
      v20 = v9[2];
      if ( v20 == v19[2] )
      {
LABEL_29:
        v3 = *v19;
      }
      else
      {
        while ( v19 != *(__int64 **)(qword_14DD8A308 + 16 * (v6 & qword_14DD8A320)) )
        {
          v19 = (__int64 *)v19[1];
          if ( v20 == v19[2] )
            goto LABEL_29;
        }
        v3 = (__int64)v19;
      }
    }
    v10 = qword_14DD8A300;
  }
  v21 = *(__int64 ***)(v3 + 8);
  qword_14DD8A300 = v10 + 1;
  *v9 = v3;
  v9[1] = (__int64)v21;
  *v21 = v9;
  *(_QWORD *)(v3 + 8) = v9;
  v22 = qword_14DD8A308;
  v23 = 2 * (v6 & qword_14DD8A320);
  v24 = *(_QWORD *)(qword_14DD8A308 + 16 * (v6 & qword_14DD8A320));
  if ( v24 == qword_14DD8A2F8 )
  {
    *(_QWORD *)(qword_14DD8A308 + 16 * (v6 & qword_14DD8A320)) = v9;
    goto LABEL_37;
  }
  if ( v24 != v3 )
  {
    if ( *(__int64 ***)(qword_14DD8A308 + 16 * (v6 & qword_14DD8A320) + 8) != v21 )
    {
LABEL_38:
      *(_QWORD *)a2 = v9;
      *(_BYTE *)(a2 + 8) = 1;
      return a2;
    }
LABEL_37:
    *(_QWORD *)(v22 + 8 * v23 + 8) = v9;
    goto LABEL_38;
  }
  *(_QWORD *)(qword_14DD8A308 + 16 * (v6 & qword_14DD8A320)) = v9;
  *(_QWORD *)a2 = v9;
  *(_BYTE *)(a2 + 8) = 1;
  return a2;
}


===== sub_140181890 size=829 proto=__int64 __fastcall(__int64, __int64, unsigned __int8 *)
callers: [{"ea": "0x1401778f0", "name": "sub_1401778F0"}, {"ea": "0x140179540", "name": "sub_140179540"}, {"ea": "0x140179790", "name": "sub_140179790"}]
callees: [{"ea": "0x140002790", "name": "nullsub_3"}, {"ea": "0x140133e10", "name": "Mem_HeapAlloc"}, {"ea": "0x1401536b0", "name": "HV_Dispatch"}, {"ea": "0x140181890", "name": "sub_140181890"}, {"ea": "0x1401840f0", "name": "sub_1401840F0"}, {"ea": "0x1401e9c60", "name": "sub_1401E9C60"}]
--- PSEUDOCODE ---
__int64 __fastcall sub_140181890(__int64 a1, __int64 a2, unsigned __int8 *a3)
{
  __int64 v3; // rsi
  unsigned __int64 v6; // rbp
  __int64 v7; // rax
  __int64 result; // rax
  __int64 *v9; // rax
  __int64 *v10; // rbx
  __int64 v11; // rdx
  unsigned __int64 v12; // rcx
  float v13; // xmm0_4
  unsigned __int64 v14; // rdi
  float v15; // xmm2_4
  float v16; // xmm0_4
  unsigned __int64 v17; // rcx
  unsigned __int64 v18; // rax
  unsigned __int64 v19; // rcx
  __int64 *v20; // rax
  __int64 v21; // rcx
  __int64 **v22; // r8
  __int64 v23; // rcx
  __int64 v24; // rax
  __int64 v25; // rdx
  __int64 retaddr; // [rsp+48h] [rbp+0h]

  v3 = qword_14DD8A378;
  v6 = 0x100000001B3LL
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
  v7 = *(_QWORD *)(qword_14DD8A388 + 16 * (qword_14DD8A3A0 & v6) + 8);
  if ( v7 != qword_14DD8A378 )
  {
    if ( *(_QWORD *)a3 == *(_QWORD *)(v7 + 16) )
    {
LABEL_5:
      *(_QWORD *)a2 = v7;
      *(_BYTE *)(a2 + 8) = 0;
      return a2;
    }
    while ( v7 != *(_QWORD *)(qword_14DD8A388
                            + 16
                            * (qword_14DD8A3A0
                             & (0x100000001B3LL
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
                                        * (a3[2]
                                         ^ (0x100000001B3LL * (a3[1] ^ (0x100000001B3LL * (*a3 ^ 0xCBF29CE484222325uLL)))))))))))))))))) )
    {
      v7 = *(_QWORD *)(v7 + 8);
      if ( *(_QWORD *)a3 == *(_QWORD *)(v7 + 16) )
        goto LABEL_5;
    }
    v3 = v7;
  }
  if ( qword_14DD8A380 == 0x249249249249249LL )
  {
    nullsub_3();
    JUMPOUT(0x140181BCCLL);
  }
  v9 = (__int64 *)Mem_HeapAlloc(0x70u);
  v10 = v9;
  if ( v9 == nullptr )
  {
    HV_Dispatch(0x3678656u, 112, retaddr, retaddr - 0x140000000LL, 0);
    __debugbreak();
  }
  *(_OWORD *)v9 = 0;
  *((_OWORD *)v9 + 1) = 0;
  *((_OWORD *)v9 + 2) = 0;
  *((_OWORD *)v9 + 3) = 0;
  *((_OWORD *)v9 + 4) = 0;
  *((_OWORD *)v9 + 5) = 0;
  *((_OWORD *)v9 + 6) = 0;
  v9[2] = *(_QWORD *)a3;
  v11 = qword_14DD8A380;
  v12 = qword_14DD8A380 + 1;
  if ( qword_14DD8A380 + 1 < 0 )
  {
    v12 &= 1u;
    v13 = (float)(int)(v12 | ((unsigned __int64)(qword_14DD8A380 + 1) >> 1))
        + (float)(int)(v12 | ((unsigned __int64)(qword_14DD8A380 + 1) >> 1));
  }
  else
  {
    v13 = (float)(int)v12;
  }
  v14 = qword_14DD8A3A8;
  if ( qword_14DD8A3A8 < 0 )
  {
    v12 = qword_14DD8A3A8 & 1 | ((unsigned __int64)qword_14DD8A3A8 >> 1);
    v15 = (float)(int)v12 + (float)(int)v12;
  }
  else
  {
    v15 = (float)(int)qword_14DD8A3A8;
  }
  if ( (float)(v13 / v15) > *(float *)&dword_14DD8A370 )
  {
    v16 = sub_1401E9C60(v12, qword_14DD8A380);
    v17 = 0;
    if ( v16 >= 9.223372e18 )
    {
      v16 = v16 - 9.223372e18;
      if ( v16 < 9.223372e18 )
        v17 = 0x8000000000000000uLL;
    }
    v18 = v17 + (unsigned int)(int)v16;
    v19 = 8;
    if ( v18 > 8 )
      v19 = v18;
    if ( v14 < v19 )
    {
      if ( v14 >= 0x200 || (v14 *= 8LL, v14 < v19) )
        v14 = v19;
    }
    sub_1401840F0(v19, v14);
    v3 = qword_14DD8A378;
    v20 = *(__int64 **)(qword_14DD8A388 + 16 * (v6 & qword_14DD8A3A0) + 8);
    if ( v20 != (__int64 *)qword_14DD8A378 )
    {
      v21 = v10[2];
      if ( v21 == v20[2] )
      {
LABEL_29:
        v3 = *v20;
      }
      else
      {
        while ( v20 != *(__int64 **)(qword_14DD8A388 + 16 * (v6 & qword_14DD8A3A0)) )
        {
          v20 = (__int64 *)v20[1];
          if ( v21 == v20[2] )
            goto LABEL_29;
        }
        v3 = (__int64)v20;
      }
    }
    v11 = qword_14DD8A380;
  }
  v22 = *(__int64 ***)(v3 + 8);
  qword_14DD8A380 = v11 + 1;
  *v10 = v3;
  v10[1] = (__int64)v22;
  *v22 = v10;
  *(_QWORD *)(v3 + 8) = v10;
  v23 = qword_14DD8A388;
  v24 = 2 * (v6 & qword_14DD8A3A0);
  v25 = *(_QWORD *)(qword_14DD8A388 + 16 * (v6 & qword_14DD8A3A0));
  if ( v25 == qword_14DD8A378 )
  {
    *(_QWORD *)(qword_14DD8A388 + 16 * (v6 & qword_14DD8A3A0)) = v10;
LABEL_37:
    *(_QWORD *)(v23 + 8 * v24 + 8) = v10;
    goto LABEL_38;
  }
  if ( v25 == v3 )
  {
    *(_QWORD *)(qword_14DD8A388 + 16 * (v6 & qword_14DD8A3A0)) = v10;
    *(_QWORD *)a2 = v10;
    *(_BYTE *)(a2 + 8) = 1;
    return a2;
  }
  if ( *(__int64 ***)(qword_14DD8A388 + 16 * (v6 & qword_14DD8A3A0) + 8) == v22 )
    goto LABEL_37;
LABEL_38:
  *(_QWORD *)a2 = v10;
  result = a2;
  *(_BYTE *)(a2 + 8) = 1;
  return result;
}


===== sub_140184D90 size=95 proto=__int64 __fastcall(__int64, __int64, unsigned int)
callers: [{"ea": "0x140165d30", "name": "sub_140165D30"}, {"ea": "0x1401881d0", "name": "sub_1401881D0"}]
callees: [{"ea": "0x14015d5c0", "name": "Hv_ReadGuestU64"}, {"ea": "0x140176810", "name": "sub_140176810"}, {"ea": "0x140184d90", "name": "sub_140184D90"}]
--- PSEUDOCODE ---
__int64 __fastcall sub_140184D90(__int64 a1, __int64 a2, unsigned int a3)
{
  __int64 result; // rax

  result = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, a2 + 8LL * (a3 / *(_DWORD *)(g_Hook_OffsetTable + 32)));
  if ( result != 0 )
    return sub_140176810(
             g_Hook_GuestCr3OrCtx,
             result + *(_DWORD *)(g_Hook_OffsetTable + 36) * (a3 % *(_DWORD *)(g_Hook_OffsetTable + 32)));
  return result;
}


===== sub_14018C6B0 size=422 proto=_QWORD *__fastcall(__int64, _QWORD *, unsigned __int64)
callers: [{"ea": "0x140187e60", "name": "sub_140187E60"}, {"ea": "0x1401881d0", "name": "sub_1401881D0"}, {"ea": "0x14018c6b0", "name": "sub_14018C6B0"}]
callees: [{"ea": "0x1400fd010", "name": "sub_1400FD010"}, {"ea": "0x14011c2a0", "name": "HV_TranslateGuestVa_Present"}, {"ea": "0x14011fb10", "name": "HV_Rdgsbase"}, {"ea": "0x14018c6b0", "name": "sub_14018C6B0"}, {"ea": "0x1401ea340", "name": "Util_Memcpy"}]
--- PSEUDOCODE ---
_QWORD *__fastcall sub_14018C6B0(__int64 a1, _QWORD *a2, unsigned __int64 a3)
{
  __int64 v6; // r15
  unsigned __int64 v7; // r14
  __int64 v8; // rax
  unsigned __int64 v9; // rbx
  int v11; // [rsp+24h] [rbp-84h]
  __int64 v12; // [rsp+C0h] [rbp+18h] BYREF
  unsigned __int64 v13; // [rsp+C8h] [rbp+20h] BYREF

  if ( a3 > 0x10000 )
  {
    if ( g_Wddm_DisableOverlay == 0 )
    {
      if ( HV_Rdgsbase() != 0 )
      {
        if ( a3 >= 0x7FFFFFFFFFFFLL )
        {
          *a2 = 0;
        }
        else
        {
          v12 = 0;
          sub_1400FD010();
          *(_DWORD *)(a1 + 64) = v11;
          *a2 = v12;
        }
      }
      else
      {
        sub_14018C6B0(a1, a2, a3);
      }
      return a2;
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
          v13 = 0;
          v8 = HV_TranslateGuestVa_Present(v6, v7 + a3, &v13);
          if ( (unsigned __int64)(v8 - 1) > 0x7FFFFFFFFFLL )
            break;
          v9 = v13;
          if ( 8 - v7 < v13 )
            v9 = 8 - v7;
          Util_Memcpy((char *)&v12 + v7, (char *)(v8 + 0x7F8000000000LL), v9);
          v7 += v9;
        }
        while ( v7 < 8 );
        *a2 = v12;
        return a2;
      }
    }
  }
  *a2 = 0;
  return a2;
}


===== sub_14018CC80 size=367 proto=__int64 __fastcall(__int64, unsigned __int8 *)
callers: [{"ea": "0x140187b90", "name": "sub_140187B90"}]
callees: [{"ea": "0x140133bc0", "name": "Mem_HeapFreeTracked"}, {"ea": "0x1401340a0", "name": "Mem_HeapFreeLocal"}, {"ea": "0x14018cc80", "name": "sub_14018CC80"}]
--- PSEUDOCODE ---
__int64 __fastcall sub_14018CC80(__int64 a1, unsigned __int8 *a2)
{
  __int64 v3; // r9
  __int64 *v4; // rdx
  __int64 *v5; // r11
  __int64 *v6; // rcx
  __int64 *v7; // rax
  __int64 v8; // rdx
  __int64 retaddr; // [rsp+28h] [rbp+0h]

  v3 = qword_14828F388;
  v4 = (__int64 *)(qword_14828F398
                 + 16
                 * (qword_14828F3B0
                  & (0x100000001B3LL
                   * (a2[7]
                    ^ (0x100000001B3LL
                     * (a2[6]
                      ^ (0x100000001B3LL
                       * (a2[5]
                        ^ (0x100000001B3LL
                         * (a2[4]
                          ^ (0x100000001B3LL
                           * (a2[3]
                            ^ (0x100000001B3LL
                             * (a2[2] ^ (0x100000001B3LL * (a2[1] ^ (0x100000001B3LL * (*a2 ^ 0xCBF29CE484222325uLL))))))))))))))))));
  v5 = (__int64 *)v4[1];
  v6 = v5;
  if ( v5 != (__int64 *)qword_14828F388 )
  {
    if ( *(_QWORD *)a2 == v5[2] )
      goto LABEL_7;
    while ( v6 != (__int64 *)*v4 )
    {
      v6 = (__int64 *)v6[1];
      if ( *(_QWORD *)a2 == v6[2] )
        goto LABEL_7;
    }
  }
  v6 = nullptr;
LABEL_7:
  if ( v6 == nullptr )
    return 0;
  v7 = (__int64 *)*v4;
  if ( v5 == v6 )
  {
    if ( v7 == v6 )
      *v4 = qword_14828F388;
    else
      v3 = v6[1];
    v4[1] = v3;
  }
  else if ( v7 == v6 )
  {
    *v4 = *v6;
  }
  v8 = *v6;
  --qword_14828F390;
  *(_QWORD *)v6[1] = v8;
  *(_QWORD *)(v8 + 8) = v6[1];
  if ( (v6 < &qword_14D2952A0 || v6 >= qword_14DB952A0) && (v6 < qword_14027F000 || v6 >= qword_14827F000) )
  {
    Mem_HeapFreeTracked((unsigned __int64)v6, retaddr);
    return 1;
  }
  else
  {
    Mem_HeapFreeLocal((__int64)v6);
    return 1;
  }
}


===== sub_1401E98D0 size=159 proto=__int64 __fastcall(unsigned __int8 *, unsigned __int8 *)
callers: [{"ea": "0x14003f1f0", "name": "Util_IsMicrosoftSigner"}, {"ea": "0x14004bdd0", "name": "sub_14004BDD0"}, {"ea": "0x140051c50", "name": "sub_140051C50"}, {"ea": "0x140055770", "name": "sub_140055770"}, {"ea": "0x140055da0", "name": "sub_140055DA0"}, {"ea": "0x1400565c0", "name": "sub_1400565C0"}, {"ea": "0x140056b80", "name": "sub_140056B80"}, {"ea": "0x1400577a0", "name": "sub_1400577A0"}, {"ea": "0x1400580b0", "name": "sub_1400580B0"}, {"ea": "0x1400584d0", "name": "sub_1400584D0"}, {"ea": "0x1400588d0", "name": "sub_1400588D0"}, {"ea": "0x1400591c0", "name": "sub_1400591C0"}, {"ea": "0x140059de0", "name": "sub_140059DE0"}, {"ea": "0x14005a400", "name": "sub_14005A400"}, {"ea": "0x14005ade0", "name": "sub_14005ADE0"}, {"ea": "0x14005b810", "name": "sub_14005B810"}, {"ea": "0x14005bcd0", "name": "sub_14005BCD0"}, {"ea": "0x14005ef30", "name": "sub_14005EF30"}, {"ea": "0x14005f140", "name": "sub_14005F140"}, {"ea": "0x14005f4a0", "name": "sub_14005F4A0"}, {"ea": "0x14005fc60", "name": "sub_14005FC60"}, {"ea": "0x140060160", "name": "sub_140060160"}, {"ea": "0x140060f10", "name": "sub_140060F10"}, {"ea": "0x1400610e0", "name": "sub_1400610E0"}, {"ea": "0x1400611b0", "name": "sub_1400611B0"}, {"ea": "0x140061370", "name": "sub_140061370"}, {"ea": "0x140061470", "name": "sub_140061470"}, {"ea": "0x140061660", "name": "sub_140061660"}, {"ea": "0x140062650", "name": "sub_140062650"}, {"ea": "0x140074b30", "name": "sub_140074B30"}, {"ea": "0x1400762e0", "name": "Rule_DownloadAofBloom"}, {"ea": "0x140081420", "name": "Rule_InstallAofBloom"}, {"ea": "0x140111350", "name": "sub_140111350"}, {"ea": "0x140112100", "name": "sub_140112100"}, {"ea": "0x14013bce0", "name": "sub_14013BCE0"}, {"ea": "0x14013dd00", "name": "sub_14013DD00"}, {"ea": "0x140153890", "name": "sub_140153890"}, {"ea": "0x140187e60", "name": "sub_140187E60"}, {"ea": "0x14e7fc4dc", "name": "sub_14E7FC4DC"}, {"ea": "0x14e807b8c", "name": "sub_14E807B8C"}, {"ea": "0x14e80f842", "name": "sub_14E80F842"}, {"ea": "0x14e80f9f4", "name": "sub_14E80F9F4"}]
callees: [{"ea": "0x1401e98d0", "name": "sub_1401E98D0"}]
--- PSEUDOCODE ---
__int64 __fastcall sub_1401E98D0(unsigned __int8 *a1, unsigned __int8 *a2)
{
  unsigned __int8 *v2; // r10
  unsigned __int8 *v3; // r8
  unsigned __int8 i; // r9
  unsigned __int8 v6; // al
  unsigned __int8 v7; // r11
  unsigned __int8 v8; // dl
  unsigned __int8 v9; // cl

  v2 = a2;
  v3 = a1;
  if ( a1 == a2 )
    return 0;
  if ( a1 == nullptr )
    return 0xFFFFFFFFLL;
  if ( a2 == nullptr )
    return 1;
  for ( i = *a1; i != 0; ++v2 )
  {
    v6 = *v2;
    if ( *v2 == 0 )
      break;
    v7 = i + 32;
    if ( (unsigned __int8)(i - 65) > 0x19u )
      v7 = i;
    if ( (unsigned __int8)(v6 - 65) <= 0x19u )
      v6 += 32;
    if ( v7 != v6 )
      return v7 - (unsigned int)v6;
    i = *++v3;
  }
  v8 = *v3;
  if ( (unsigned __int8)(*v3 - 65) <= 0x19u )
    v8 += 32;
  v9 = *v2;
  if ( (unsigned __int8)(*v2 - 65) <= 0x19u )
    v9 += 32;
  return v8 - (unsigned int)v9;
}


===== sub_1401E9D70 size=139 proto=_BYTE *__fastcall(_BYTE *, _BYTE *)
callers: [{"ea": "0x1400b7e70", "name": "sub_1400B7E70"}, {"ea": "0x140112ce0", "name": "sub_140112CE0"}, {"ea": "0x140172840", "name": "sub_140172840"}, {"ea": "0x140176110", "name": "sub_140176110"}, {"ea": "0x140176160", "name": "sub_140176160"}, {"ea": "0x140176310", "name": "sub_140176310"}, {"ea": "0x14017c890", "name": "sub_14017C890"}, {"ea": "0x14017d480", "name": "sub_14017D480"}, {"ea": "0x14017e0b0", "name": "sub_14017E0B0"}]
callees: [{"ea": "0x1401e9d70", "name": "sub_1401E9D70"}]
--- PSEUDOCODE ---
_BYTE *__fastcall sub_1401E9D70(_BYTE *a1, _BYTE *a2)
{
  _BYTE *v4; // r10
  __int64 v5; // r10
  __int64 v6; // rdx
  _BYTE *v7; // rax
  _BYTE *v8; // r9

  if ( a1 == nullptr || a2 == nullptr )
    return nullptr;
  if ( *a2 == 0 )
    return a1;
  v4 = a2;
  do
    ++v4;
  while ( *v4 != 0 );
  v5 = v4 - a2;
  if ( *a1 == 0 )
    return nullptr;
  v6 = v5;
  v7 = a2;
  v8 = a1;
  if ( v5 != 0 )
  {
    while ( v8 != a2 )
    {
      while ( 1 )
      {
        --v6;
        if ( *a1 == 0 || *a1 != *v7 )
          break;
        ++a1;
        ++v7;
        if ( v6 == 0 )
          return v8;
      }
      if ( v6 == -1 || *a1 == *v7 )
        break;
      a1 = ++v8;
      if ( *v8 == 0 )
        return nullptr;
      v6 = v5;
      v7 = a2;
    }
  }
  return v8;
}


