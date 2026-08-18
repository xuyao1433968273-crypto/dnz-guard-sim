===== sub_140175230 size= 404 __int64 __fastcall(unsigned __int64, __int64 *)
__int64 __fastcall sub_140175230(unsigned __int64 a1, __int64 *a2)
{
  __int64 v2; // rtt
  __int64 *v3; // rcx
  __int64 v4; // rax
  __int64 v5; // rcx
  __int64 v6; // rcx
  __int64 result; // rax
  int v8; // ebx
  __int64 v9; // rcx
  _BYTE v10[24]; // [rsp+20h] [rbp-18h] BYREF
  unsigned __int64 v11; // [rsp+40h] [rbp+8h] BYREF
  __int64 v12; // [rsp+50h] [rbp+18h]

  v11 = a1;
  if ( qword_14DB95C90 == -1 )
    goto LABEL_14;
  v2 = qword_14DB95C90;
  if ( v2 != _InterlockedCompareExchange64(&qword_14DB95C90, qword_14DB95C90 + 1, qword_14DB95C90) )
    goto LABEL_14;
  v3 = (__int64 *)(qword_14828F2C8
                 + 16
                 * (qword_14828F2E0
                  & (0x100000001B3LL
                   * (HIBYTE(v11)
                    ^ (0x100000001B3LL
                     * ((0x100000001B3LL
                       * (BYTE5(v11)
                        ^ (0x100000001B3LL
                         * (BYTE4(v11)
                          ^ (0x100000001B3LL
                           * (BYTE3(v11)
                            ^ (0x100000001B3LL
                             * (BYTE2(v11)
                              ^ (0x100000001B3LL
                               * (BYTE1(v11) ^ (0x100000001B3LL * ((unsigned __int8)v11 ^ 0xCBF29CE484222325uLL))))))))))))
                      ^ BYTE6(v11)))))));
  v4 = v3[1];
  if ( v4 == qword_14828F2B8 )
    goto LABEL_8;
  v5 = *v3;
  if ( v11 != *(_QWORD *)(v4 + 16) )
  {
    while ( v4 != v5 )
    {
      v4 = *(_QWORD *)(v4 + 8);
      if ( v11 == *(_QWORD *)(v4 + 16) )
        goto LABEL_9;
    }
LABEL_8:
    v4 = 0;
  }
LABEL_9:
  v6 = qword_14828F2B8;
  if ( v4 != 0 )
    v6 = v4;
  if ( v6 != qword_14828F2B8 )
  {
    result = *((unsigned int *)a2 + 2);
    *(_QWORD *)(v6 + 24) = *a2;
    *(_DWORD *)(v6 + 32) = result;
    _InterlockedDecrement64(&qword_14DB95C90);
    return result;
  }
  _InterlockedDecrement64(&qword_14DB95C90);
LABEL_14:
  result = _InterlockedCompareExchange64(&qword_14DB95C90, -1, 0);
  if ( result == 0 )
  {
    v8 = *((_DWORD *)a2 + 2);
    v12 = *a2;
    result = sub_140176FD0(&qword_14828F2B0, v10, &v11);
    v9 = *(_QWORD *)result;
    *(_QWORD *)(v9 + 24) = v12;
    *(_DWORD *)(v9 + 32) = v8;
    qword_14DB95C90 = 0;
  }
  return result;
}


===== Hv_ReadProcessListFromGuest size= 381 void __fastcall(__int64, __int64)
void __fastcall ACE_ReadProcessListFromGuest(__int64 a1, __int64 a2)
{
  int v2; // esi
  __int64 v5; // rcx
  int v6; // eax
  __int64 v7; // rcx
  int v8; // eax
  __int64 v9; // rcx
  char v10; // al
  int v11; // ebx
  __int64 v12; // rdx
  __int64 v13; // rax
  __int64 v14; // rbp
  unsigned __int64 v15; // r14
  __int64 v16; // rax
  __int64 v17; // rdx

  if ( a2 )
  {
    v2 = 0;
    *(_WORD *)(a2 + 1) = 1;
    *(_BYTE *)a2 = 0;
    *(_DWORD *)(a2 + 12) = 0;
    *(_BYTE *)(a2 + 3) = 0;
    if ( (unsigned __int64)(a1 - 0xFFFF) <= 0x7FFFFFFF0000LL
      && !(unsigned int)Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, a1 + 40) )
    {
      v5 = g_Hook_GuestCr3OrCtx;
      *(_BYTE *)a2 = 1;
      v6 = Hv_ReadGuestU32(v5, a1 + 44);
      v7 = g_Hook_GuestCr3OrCtx;
      *(_DWORD *)(a2 + 4) = v6;
      v8 = Hv_ReadGuestU32(v7, a1 + 52);
      v9 = g_Hook_GuestCr3OrCtx;
      *(_DWORD *)(a2 + 8) = v8;
      v10 = Hv_ReadGuestU8(v9, a1 + 56);
      *(_BYTE *)(a2 + 3) = v10 != 0;
      if ( !v10 )
      {
        v11 = Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, a1 + 24);
        v12 = a1 + 32;
        if ( v11 < 0 )
        {
          Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v12);
          return;
        }
        if ( v11 <= 20 )
        {
          v13 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v12);
          if ( v11 <= 0 )
            return;
        }
        else
        {
          v11 = 20;
          v13 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v12);
        }
        v14 = v13 + 8;
        v15 = v13 - 0xFFFF;
        do
        {
          if ( v15 <= 0x7FFFFFFF0000LL )
          {
            v16 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v14);
            if ( (unsigned __int64)(v16 - 0xFFFF) <= 0x7FFFFFFF0000LL )
            {
              sub_14017B160(v16, a2 + 1080LL * *(int *)(a2 + 12) + 16);
              v17 = *(int *)(a2 + 12);
              if ( *(_BYTE *)(1080 * v17 + a2 + 16) )
                *(_DWORD *)(a2 + 12) = v17 + 1;
            }
          }
          ++v2;
          v14 += 8;
        }
        while ( v2 < v11 );
      }
    }
  }
}


===== sub_1401944D0 size= 171 bool __fastcall(unsigned __int64)
bool __fastcall sub_1401944D0(unsigned __int64 a1)
{
  unsigned __int64 v1; // rax
  __int64 v2; // rcx

  if ( a1 > 0x438094203LL )
  {
    if ( a1 > 0x438A1D881LL )
    {
      if ( a1 != 0x438A1D882LL && a1 - 0x46BE46787LL > 1 )
        return a1 != 0x46BE46794LL;
    }
    else if ( a1 != 0x438A1D881LL )
    {
      switch ( a1 )
      {
        case 0x438094208uLL:
        case 0x43809420AuLL:
        case 0x43809420BuLL:
        case 0x43809420DuLL:
        case 0x43809420EuLL:
        case 0x43809420FuLL:
        case 0x438094211uLL:
        case 0x438094212uLL:
        case 0x438094214uLL:
        case 0x438094215uLL:
        case 0x438094218uLL:
        case 0x438094219uLL:
        case 0x43809421AuLL:
        case 0x43809421BuLL:
        case 0x43809421CuLL:
        case 0x43809421DuLL:
        case 0x438094220uLL:
        case 0x438094221uLL:
        case 0x438094222uLL:
        case 0x438094225uLL:
        case 0x43809422BuLL:
        case 0x43809422EuLL:
        case 0x43809422FuLL:
        case 0x438094232uLL:
        case 0x438094238uLL:
        case 0x438094239uLL:
        case 0x43809423AuLL:
        case 0x43809423BuLL:
        case 0x43809423FuLL:
        case 0x438094244uLL:
        case 0x438094246uLL:
        case 0x438094248uLL:
        case 0x438094249uLL:
          return false;
        default:
          return true;
      }
    }
  }
  else if ( a1 != 0x438094203LL )
  {
    v1 = a1 - 0x435A6E803LL;
    if ( a1 - 0x435A6E803LL > 0x10 )
      return true;
    v2 = 68101;
    if ( !_bittest64(&v2, v1) )
      return true;
  }
  return false;
}


// also callees: ['ACE_ReadProcessListFromGuest']
