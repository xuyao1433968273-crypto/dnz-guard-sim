===== 0x1401757e0
name: sub_1401757E0
--- PSEUDOCODE ---
__int64 __fastcall sub_1401757E0(__int64 a1, unsigned int a2)
{
  __int64 result; // rax
  unsigned int v3; // ecx
  unsigned int v4; // ecx
  unsigned int v5; // ecx
  unsigned int v6; // ecx
  unsigned int v7; // ecx
  unsigned int v8; // ecx
  unsigned int v9; // ecx
  unsigned int v10; // ecx
  unsigned int v11; // ecx
  unsigned int v12; // ecx

  result = 9 * (a2 / 9);
  switch ( a2 % 9 )
  {
    case 0u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_WORD *)(0x14E3B0F50LL + 2 * result) ^= (unsigned __int16)(a2 + (a2 & 0x1F) + 128) | 0x7F;
          v3 = result + 2;
          result = (unsigned int)(result + 2);
        }
        while ( v3 < a2 );
      }
      break;
    case 1u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_WORD *)(0x14E3B0F50LL + 2 * result) ^= (unsigned __int16)(a2 + (a2 ^ 0xDF) + 128) | 0x7F;
          v4 = result + 2;
          result = (unsigned int)(result + 2);
        }
        while ( v4 < a2 );
      }
      break;
    case 2u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_WORD *)(0x14E3B0F50LL + 2 * result) ^= (unsigned __int16)(a2 + (a2 | 0xCF) + 128) | 0x7F;
          v5 = result + 2;
          result = (unsigned int)(result + 2);
        }
        while ( v5 < a2 );
      }
      break;
    case 3u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_WORD *)(0x14E3B0F50LL + 2 * result) ^= (unsigned __int16)(33 * a2 + 128) | 0x7F;
          v6 = result + 2;
          result = (unsigned int)(result + 2);
        }
        while ( v6 < a2 );
      }
      break;
    case 4u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_WORD *)(0x14E3B0F50LL + 2 * result) ^= (unsigned __int16)(a2 + (a2 >> 2) + 128) | 0x7F;
          v7 = result + 2;
          result = (unsigned int)(result + 2);
        }
        while ( v7 < a2 );
      }
      break;
    case 5u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_WORD *)(0x14E3B0F50LL + 2 * result) ^= (unsigned __int16)(3 * a2 + 133) | 0x7F;
          v8 = result + 2;
          result = (unsigned int)(result + 2);
        }
        while ( v8 < a2 );
      }
      break;
    case 6u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_WORD *)(0x14E3B0F50LL + 2 * result) ^= (unsigned __int16)(a2 + ((4 * a2) | 5) + 128) | 0x7F;
          v9 = result + 2;
          result = (unsigned int)(result + 2);
        }
        while ( v9 < a2 );
      }
      break;
    case 7u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_WORD *)(0x14E3B0F50LL + 2 * result) ^= (unsigned __int16)(a2 + ((a2 >> 4) | 7) + 128) | 0x7F;
          v10 = result + 2;
          result = (unsigned int)(result + 2);
        }
        while ( v10 < a2 );
      }
      break;
    case 8u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_WORD *)(0x14E3B0F50LL + 2 * result) ^= (unsigned __int16)(a2 + (a2 ^ 0xC) + 128) | 0x7F;
          v11 = result + 2;
          result = (unsigned int)(result + 2);
        }
        while ( v11 < a2 );
      }
      break;
    default:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_WORD *)(0x14E3B0F50LL + 2 * result) ^= (unsigned __int16)(a2 + (a2 ^ 0x40) + 128) | 0x7F;
          v12 = result + 2;
          result = (unsigned int)(result + 2);
        }
        while ( v12 < a2 );
      }
      break;
  }
  return result;
}


===== 0x140175aa0
name: sub_140175AA0
--- PSEUDOCODE ---
__int64 __fastcall sub_140175AA0(__int64 a1, unsigned int a2)
{
  __int64 result; // rax
  unsigned int v3; // ecx
  unsigned int v4; // ecx
  unsigned int v5; // ecx
  unsigned int v6; // ecx
  unsigned int v7; // ecx
  unsigned int v8; // ecx
  unsigned int v9; // ecx
  unsigned int v10; // ecx
  unsigned int v11; // ecx
  unsigned int v12; // ecx

  result = 9 * (a2 / 9);
  switch ( a2 % 9 )
  {
    case 0u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_BYTE *)(result + 0x14E3B0F50LL) ^= (unsigned __int8)(a2 + (a2 & 0x1F) + 0x80) | 0x7F;
          v3 = result + 1;
          result = (unsigned int)(result + 1);
        }
        while ( v3 < a2 );
      }
      break;
    case 1u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_BYTE *)(result + 0x14E3B0F50LL) ^= (unsigned __int8)(a2 + (a2 ^ 0xDF) + 0x80) | 0x7F;
          v4 = result + 1;
          result = (unsigned int)(result + 1);
        }
        while ( v4 < a2 );
      }
      break;
    case 2u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_BYTE *)(result + 0x14E3B0F50LL) ^= (unsigned __int8)(a2 + (a2 | 0xCF) + 0x80) | 0x7F;
          v5 = result + 1;
          result = (unsigned int)(result + 1);
        }
        while ( v5 < a2 );
      }
      break;
    case 3u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_BYTE *)(result + 0x14E3B0F50LL) ^= (unsigned __int8)(33 * a2 + 0x80) | 0x7F;
          v6 = result + 1;
          result = (unsigned int)(result + 1);
        }
        while ( v6 < a2 );
      }
      break;
    case 4u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_BYTE *)(result + 0x14E3B0F50LL) ^= (unsigned __int8)(a2 + (a2 >> 2) + 0x80) | 0x7F;
          v7 = result + 1;
          result = (unsigned int)(result + 1);
        }
        while ( v7 < a2 );
      }
      break;
    case 5u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_BYTE *)(result + 0x14E3B0F50LL) ^= (unsigned __int8)(2 * a2 + a2 - 123) | 0x7F;
          v8 = result + 1;
          result = (unsigned int)(result + 1);
        }
        while ( v8 < a2 );
      }
      break;
    case 6u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_BYTE *)(result + 0x14E3B0F50LL) ^= (unsigned __int8)(a2 + ((4 * a2) | 5) + 0x80) | 0x7F;
          v9 = result + 1;
          result = (unsigned int)(result + 1);
        }
        while ( v9 < a2 );
      }
      break;
    case 7u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_BYTE *)(result + 0x14E3B0F50LL) ^= (unsigned __int8)(a2 + ((a2 >> 4) | 7) + 0x80) | 0x7F;
          v10 = result + 1;
          result = (unsigned int)(result + 1);
        }
        while ( v10 < a2 );
      }
      break;
    case 8u:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_BYTE *)(result + 0x14E3B0F50LL) ^= (unsigned __int8)(a2 + (a2 ^ 0xC) + 0x80) | 0x7F;
          v11 = result + 1;
          result = (unsigned int)(result + 1);
        }
        while ( v11 < a2 );
      }
      break;
    default:
      if ( MEMORY[0x14E3B0F50] != 0 )
      {
        result = 0;
        do
        {
          *(_BYTE *)(result + 0x14E3B0F50LL) ^= (unsigned __int8)(a2 + (a2 ^ 0x40) + 0x80) | 0x7F;
          v12 = result + 1;
          result = (unsigned int)(result + 1);
        }
        while ( v12 < a2 );
      }
      break;
  }
  return result;
}


===== 0x1401767a0
NOT FOUND

===== 0x1401769b0
name: sub_1401769B0
--- PSEUDOCODE ---
__int64 __fastcall sub_1401769B0(__int64 a1, unsigned __int64 a2)
{
  unsigned __int16 v5; // di
  __int64 v6; // r14
  unsigned __int64 v7; // rsi
  __int64 v8; // rax
  unsigned __int64 v9; // rbx
  int v10; // [rsp+24h] [rbp-74h]
  unsigned __int16 v11; // [rsp+A8h] [rbp+10h] BYREF
  unsigned __int64 v12; // [rsp+B0h] [rbp+18h] BYREF

  if ( a2 <= 0x10000 )
    return 0;
  if ( g_Wddm_DisableOverlay == 0 )
  {
    if ( HV_Rdgsbase() == 0 )
      return sub_1401769B0(a1, a2);
    if ( a2 < 0x7FFFFFFFFFFFLL )
    {
      v11 = 0;
      sub_1400FD010();
      v5 = v11;
      *(_DWORD *)(a1 + 64) = v10;
      return v5;
    }
    return 0;
  }
  if ( *(_DWORD *)(a1 + 4) != *(_DWORD *)a1 )
    return 0;
  v6 = *(_QWORD *)(a1 + 8);
  if ( v6 == 0 )
    return 0;
  v7 = 0;
  v11 = 0;
  do
  {
    v12 = 0;
    v8 = HV_TranslateGuestVa_Present(v6, v7 + a2, &v12);
    if ( (unsigned __int64)(v8 - 1) > 0x7FFFFFFFFFLL )
      break;
    v9 = v12;
    if ( 2 - v7 < v12 )
      v9 = 2 - v7;
    Util_Memcpy((char *)&v11 + v7, (char *)(v8 + 0x7F8000000000LL), v9);
    v7 += v9;
  }
  while ( v7 < 2 );
  return v11;
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


===== 0x1401d6ab0
name: sub_1401D6AB0
--- PSEUDOCODE ---
__int64 __fastcall sub_1401D6AB0(
        __int64 a1,
        unsigned __int64 a2,
        __int64 a3,
        unsigned __int64 a4,
        unsigned __int64 *a5)
{
  int v10; // [rsp+34h] [rbp-54h]
  unsigned __int64 v11; // [rsp+60h] [rbp-28h]

  if ( a2 == 0 || a3 == 0 || a4 == 0 || a2 - 0x10000 > 0x7FFFFFFEFFFELL )
    return 0;
  if ( HV_Rdgsbase() == 0 )
    return sub_1401D6A50(a1, a2, a3, a4, a5);
  sub_1400FD010();
  *(_DWORD *)(a1 + 64) = v10;
  if ( a5 != nullptr )
    *a5 = v11;
  return v10 == 0;
}


