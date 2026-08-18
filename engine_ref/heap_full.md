===== 0x140133e10 Mem_HeapAlloc size=653 =====
// Custom size-class heap allocator; OOM callers use HV_Dispatch(0x3678656, size, rip, rva)
void *__fastcall Mem_HeapAlloc(unsigned __int64 size)
{
  void *result; // rax
  unsigned __int64 v2; // r10
  unsigned int v3; // ecx
  unsigned int v4; // ecx
  volatile signed __int64 *v5; // r11
  __int64 v6; // rdi
  __int128 v7; // rt0
  signed __int64 *v8; // r8
  __int128 v9; // rax
  __int128 v10; // rt0
  unsigned __int8 v11; // tt
  unsigned __int64 v12; // rbx
  signed __int64 v13; // rax
  signed __int64 v14; // rdx
  signed __int64 v15; // rcx
  signed __int64 v16; // rax
  unsigned __int64 v17; // rax
  _QWORD *v18; // rbx
  _QWORD *v19; // rcx
  _QWORD *v20; // rdx
  _QWORD *v21; // r11
  unsigned __int64 v22; // r8
  unsigned __int64 v23; // rax
  _QWORD *v24; // rcx
  __int128 v25; // [rsp+0h] [rbp-18h]

  if ( !size )
    return nullptr;
  v2 = (size + 7) & 0xFFFFFFFFFFFFFFF8uLL;
  _BitScanReverse(&v3, v2 - 1);
  v4 = v3 - 4;
  if ( v4 <= 5 )
  {
    v5 = &qword_14DB952A0[2 * v4];
    v6 = v4;
    *(_QWORD *)&v7 = 0;
    *((_QWORD *)&v7 + 1) = _mm_srli_si128((__m128i)0LL, 8).m128i_u64[0];
    _InterlockedCompareExchange128(v5, 0, 0, (signed __int64 *)&v7);
    v25 = v7;
    v8 = (signed __int64 *)v7;
    if ( (_QWORD)v7 )
    {
      v9 = v25;
      while ( 1 )
      {
        v10 = v9;
        v11 = _InterlockedCompareExchange128(v5, *((_QWORD *)&v9 + 1) + 1LL, *v8, (signed __int64 *)&v10);
        v9 = v10;
        if ( v11 )
          break;
        v8 = (signed __int64 *)v9;
        if ( !(_QWORD)v9 )
          goto LABEL_10;
      }
      if ( v8 )
      {
LABEL_15:
        *v8 = 0;
        v17 = qword_14022A9E8[v6];
        v8[1] = v17;
        v8[2] = 0x42494E414C4C4F43LL;
        _InterlockedAdd64(&g_PreAllocBinStats, v17);
        _InterlockedIncrement64(&qword_140270828[v6]);
        result = v8 + 4;
        if ( v8 != (signed __int64 *)-32LL )
          return result;
        goto LABEL_16;
      }
    }
LABEL_10:
    v12 = (qword_14022A9E8[v4] + 47) & 0xFFFFFFFFFFFFFFF0uLL;
    v13 = _InterlockedCompareExchange64(&qword_14DB95300, 0, 0);
    v14 = v13 + v12;
    v15 = v13;
    if ( (__int64)(v13 + v12) <= 9437184 )
    {
      while ( v15 != _InterlockedCompareExchange64(&qword_14DB95300, v14, v15) )
      {
        v16 = _InterlockedCompareExchange64(&qword_14DB95300, 0, 0);
        v14 = v16 + v12;
        v15 = v16;
        if ( (__int64)(v16 + v12) > 9437184 )
          goto LABEL_16;
      }
      v8 = (__int64 *)((char *)&qword_14D2952A0 + v15);
      if ( (char *)&qword_14D2952A0 + v15 )
        goto LABEL_15;
    }
  }
LABEL_16:
  while ( _InterlockedCompareExchange64(&g_PreAllocListLock, 1, 0) == 1 )
    _mm_pause();
  g_PreAllocTotalAlloc += v2;
  v18 = nullptr;
  v19 = g_PreAllocFreeListHead;
  v20 = nullptr;
  v21 = nullptr;
  v22 = -1;
  if ( !g_PreAllocFreeListHead )
    goto LABEL_34;
  do
  {
    if ( *v19 >= v2 )
    {
      v23 = *v19 - v2;
      if ( !v20 || v23 < v22 )
      {
        v20 = v19;
        v21 = v18;
        v22 = *v19 - v2;
        if ( !v23 )
          break;
      }
    }
    v18 = v19;
    v19 = (_QWORD *)v19[1];
  }
  while ( v19 );
  if ( v20 )
  {
    if ( *v20 < v2 + 32 )
    {
      if ( v21 )
        v21[1] = v20[1];
      else
        g_PreAllocFreeListHead = (_UNKNOWN *)v20[1];
      v20[1] = 0;
    }
    else
    {
      v24 = (_QWORD *)((char *)v20 + v2 + 24);
      *v24 = *v20 - v2 - 24;
      v24[1] = v20[1];
      v24[2] = 0x5052454652454544LL;
      *v20 = v2;
      v20[1] = 0;
      if ( v21 )
        v21[1] = v24;
      else
        g_PreAllocFreeListHead = (_UNKNOWN *)((char *)v20 + v2 + 24);
    }
    v20[2] = 0x505245414C4C4F43LL;
    result = v20 + 3;
  }
  else
  {
LABEL_34:
    result = nullptr;
  }
  _InterlockedExchange64(&g_PreAllocListLock, 0);
  return result;
}


===== 0x1401340a0 Mem_HeapFreeLocal size=713 =====
void __fastcall Mem_HeapFreeLocal(__int64 a1)
{
  unsigned __int64 v1; // r8
  unsigned __int64 v3; // r10
  __int64 *v4; // rax
  unsigned __int64 v5; // rbx
  unsigned __int64 v6; // r10
  _QWORD *v7; // rax
  _QWORD *v8; // rdx
  unsigned int v9; // ecx
  unsigned int v10; // ecx
  volatile signed __int64 *v11; // r9
  __int64 v12; // r11
  __m128i v13; // rt0
  signed __int64 v14; // rcx
  __m128i v15; // rax
  unsigned __int8 v16; // tt
  __m128i v17; // rt0
  unsigned __int8 v18; // tt

  if ( a1 )
  {
    v1 = a1 - 32;
    if ( a1 - 32 < (unsigned __int64)&qword_14D2952A0
      || v1 >= (unsigned __int64)qword_14DB952A0
      || v1 + 31 < (unsigned __int64)&qword_14D2952A0
      || v1 + 31 >= (unsigned __int64)qword_14DB952A0
      || a1 == 32 )
    {
      goto LABEL_10;
    }
    v3 = *(_QWORD *)(v1 + 8);
    v4 = qword_14022A9E8;
    while ( v3 != *v4 )
    {
      if ( ++v4 == (__int64 *)&unk_14022AA18 )
        goto LABEL_10;
    }
    _BitScanReverse(&v9, v3 - 1);
    v10 = v9 - 4;
    if ( v10 > 5
      || _InterlockedCompareExchange64((volatile signed __int64 *)(v1 + 16), 0x42494E4652454544LL, 0x42494E414C4C4F43LL) != 0x42494E414C4C4F43LL )
    {
LABEL_10:
      while ( _InterlockedCompareExchange64(&g_PreAllocListLock, 1, 0) == 1 )
        _mm_pause();
      v5 = a1 - 24;
      if ( v5 >= (unsigned __int64)qword_14027F000
        && v5 < (unsigned __int64)&qword_14827F000
        && v5 + 23 >= (unsigned __int64)qword_14027F000
        && v5 + 23 < (unsigned __int64)&qword_14827F000
        && v5
        && *(_QWORD *)(v5 + 16) == 0x505245414C4C4F43LL
        && (v6 = *(_QWORD *)v5) != 0
        && (v6 & 7) == 0
        && v6 <= 0x7FFFFE8 )
      {
        g_PreAllocTotalFree += v6;
        v7 = g_PreAllocFreeListHead;
        v8 = nullptr;
        *(_QWORD *)(v5 + 16) = 0x5052454652454544LL;
        if ( !v7 )
          goto LABEL_32;
        do
        {
          if ( (unsigned __int64)v7 >= v5 )
            break;
          v8 = v7;
          v7 = (_QWORD *)v7[1];
        }
        while ( v7 );
        if ( v8 && (_QWORD *)((char *)v8 + *v8 + 24) == (_QWORD *)v5 )
        {
          v5 = (unsigned __int64)v8;
          *v8 += v6 + 24;
        }
        else
        {
LABEL_32:
          *(_QWORD *)(v5 + 8) = v7;
          if ( v8 )
            v8[1] = v5;
          else
            g_PreAllocFreeListHead = (_UNKNOWN *)v5;
        }
        if ( v7 )
        {
          if ( (_QWORD *)(v5 + *(_QWORD *)v5 + 24LL) == v7 )
          {
            *(_QWORD *)v5 += *v7 + 24LL;
            *(_QWORD *)(v5 + 8) = v7[1];
          }
        }
        *(_QWORD *)(v5 + 16) = 0x5052454652454544LL;
        _InterlockedExchange64(&g_PreAllocListLock, 0);
      }
      else
      {
        _InterlockedExchange64(&g_PreAllocListLock, 0);
      }
    }
    else
    {
      v11 = &qword_14DB952A0[2 * v10];
      v12 = v10;
      v13.m128i_i64[0] = 0;
      v13.m128i_i64[1] = _mm_srli_si128((__m128i)0LL, 8).m128i_u64[0];
      _InterlockedCompareExchange128(v11, 0, 0, v13.m128i_i64);
      v14 = v13.m128i_i64[1] + 1;
      *(_QWORD *)v1 = v13.m128i_i64[0];
      v13.m128i_i64[1] = _mm_srli_si128(v13, 8).m128i_u64[0];
      v16 = _InterlockedCompareExchange128(v11, v14, v1, v13.m128i_i64);
      v15 = v13;
      if ( !v16 )
      {
        do
        {
          *(_QWORD *)v1 = v15.m128i_i64[0];
          v17 = v15;
          v18 = _InterlockedCompareExchange128(v11, v15.m128i_i64[1] + 1, v1, v17.m128i_i64);
          v15 = v17;
        }
        while ( !v18 );
      }
      _InterlockedAdd64(&qword_140270630, v3);
      _InterlockedIncrement64(&qword_140270858[v12]);
    }
  }
}


===== 0x1400029f0 Mem_HeapFree size=139 =====
void __fastcall Mem_HeapFree(unsigned __int64 a1, unsigned __int64 a2)
{
  void *retaddr; // [rsp+38h] [rbp+0h]

  if ( a2 >= 0x1000 )
  {
    if ( a1 - *(_QWORD *)(a1 - 8) - 8 > 0x1F )
      sub_1401E98C0();
    a1 = *(_QWORD *)(a1 - 8);
  }
  if ( a1 )
  {
    if ( (a1 < (unsigned __int64)&qword_14D2952A0 || a1 >= (unsigned __int64)qword_14DB952A0)
      && (a1 < (unsigned __int64)&qword_14027F000 || a1 >= (unsigned __int64)&qword_14827F000) )
    {
      Mem_HeapFreeTracked(a1, retaddr);
    }
    else
    {
      Mem_HeapFreeLocal(a1, retaddr);
    }
  }
}

