===== sub_14017B160 size= 1182 void __fastcall(__int64, __int64)
void __fastcall sub_14017B160(__int64 a1, __int64 a2)
{
  __int64 v2; // rsi
  __int64 v5; // rcx
  unsigned __int64 GuestU64; // rax
  __int64 v7; // rax
  __int64 v8; // rbp
  int GuestU32; // eax
  __int64 v10; // rcx
  int v11; // eax
  __int64 v12; // rcx
  int v13; // eax
  __int64 v14; // rcx
  int v15; // eax
  __int64 v16; // rcx
  int v17; // eax
  __int64 v18; // rcx
  int v19; // eax
  __int64 v20; // rcx
  __int64 v21; // rax
  __int64 v22; // rcx
  __int64 v23; // rax
  __int64 v24; // rcx
  int v25; // eax
  __int64 v26; // rcx
  int v27; // eax
  __int64 v28; // rcx
  unsigned __int8 GuestU8; // al
  __int64 v30; // rcx
  int v31; // eax
  __int64 v32; // rcx
  __int64 v33; // rax
  __int64 v34; // rcx
  __int64 v35; // rax
  __int64 v36; // rcx
  __int64 v37; // rax
  __int64 v38; // rcx
  __int64 v39; // rax
  __int64 v40; // rcx
  __int64 v41; // rax
  __int64 v42; // rcx
  char v43; // al
  __int64 v44; // rcx
  char v45; // al
  __int64 v46; // rcx
  __int64 v47; // rax
  __int64 v48; // rdi
  __int64 v49; // rax
  __int64 v50; // rcx
  __int64 v51; // rax
  __int64 v52; // rcx
  int v53; // eax
  __int64 v54; // rcx
  int v55; // eax
  __int64 v56; // rcx
  int v57; // eax
  __int64 v58; // rcx
  __int64 v59; // rax
  __int64 v60; // rcx
  __int64 v61; // rax
  __int64 v62; // rcx
  __int64 v63; // rax
  bool v64; // zf
  int v65; // eax
  __int64 v66; // rcx
  int v67; // eax
  __int64 v68; // rcx
  int v69; // eax
  __int64 v70; // rcx

  if ( a2 != 0 )
  {
    v2 = a2 + 136;
    *(_WORD *)a2 = 0;
    *(_BYTE *)(a2 + 2) = 0;
    *(_OWORD *)(a2 + 136) = 0;
    *(_QWORD *)(a2 + 184) = 0;
    *(_QWORD *)(a2 + 192) = 0;
    *(_QWORD *)(a2 + 200) = 0;
    *(_QWORD *)(a2 + 208) = 0;
    *(_QWORD *)(a2 + 216) = 0;
    *(_WORD *)(a2 + 224) = 0;
    *(_QWORD *)(a2 + 232) = 0;
    *(_QWORD *)(a2 + 240) = 0;
    *(_QWORD *)(a2 + 248) = 0;
    *(_QWORD *)(a2 + 256) = 0;
    *(_QWORD *)(a2 + 264) = 0;
    *(_DWORD *)(a2 + 272) = 0;
    *(_QWORD *)(a2 + 280) = 0;
    *(_QWORD *)(a2 + 288) = 0;
    *(_QWORD *)(a2 + 296) = 0;
    *(_QWORD *)(a2 + 304) = 0;
    *(_QWORD *)(a2 + 312) = 0;
    *(_DWORD *)(a2 + 320) = 0;
    *(_OWORD *)(a2 + 152) = 0;
    *(_OWORD *)(a2 + 168) = 0;
    if ( a2 != -328 )
    {
      *(_BYTE *)(a2 + 328) = 0;
      *(_QWORD *)(a2 + 332) = 0;
      *(_DWORD *)(a2 + 340) = 0;
    }
    if ( (unsigned __int64)(a1 - 0xFFFF) <= 0x7FFFFFFF0000LL )
    {
      v5 = g_Hook_GuestCr3OrCtx;
      *(_BYTE *)a2 = 1;
      GuestU64 = Hv_ReadGuestU64(v5, a1 + 64);
      sub_14017B030((_BYTE *)(a2 + 2), 0x80u, GuestU64);
      v7 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, a1 + 72);
      v8 = v7;
      if ( v2 != 0 && (unsigned __int64)(v7 - 0xFFFF) <= 0x7FFFFFFF0000LL )
      {
        GuestU32 = Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, v7 + 16);
        v10 = g_Hook_GuestCr3OrCtx;
        *(_DWORD *)v2 = GuestU32;
        v11 = Hv_ReadGuestU32(v10, v8 + 20);
        v12 = g_Hook_GuestCr3OrCtx;
        *(_DWORD *)(v2 + 4) = v11;
        v13 = Hv_ReadGuestU32(v12, v8 + 24);
        v14 = g_Hook_GuestCr3OrCtx;
        *(_DWORD *)(v2 + 8) = v13;
        v15 = Hv_ReadGuestU32(v14, v8 + 28);
        v16 = g_Hook_GuestCr3OrCtx;
        *(_DWORD *)(v2 + 12) = v15;
        v17 = Hv_ReadGuestU32(v16, v8 + 32);
        v18 = g_Hook_GuestCr3OrCtx;
        *(_DWORD *)(v2 + 16) = v17;
        v19 = Hv_ReadGuestU32(v18, v8 + 36);
        v20 = g_Hook_GuestCr3OrCtx;
        *(_DWORD *)(v2 + 20) = v19;
        v21 = Hv_ReadGuestU64(v20, v8 + 40);
        v22 = g_Hook_GuestCr3OrCtx;
        *(_QWORD *)(v2 + 24) = v21;
        v23 = sub_140176810(v22, v8 + 48);
        v24 = g_Hook_GuestCr3OrCtx;
        *(_QWORD *)(v2 + 32) = v23;
        *(_DWORD *)(v2 + 40) = Hv_ReadGuestU32(v24, v8 + 56);
      }
      v25 = Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, a1 + 96);
      v26 = g_Hook_GuestCr3OrCtx;
      *(_DWORD *)(a2 + 184) = v25;
      v27 = Hv_ReadGuestU32(v26, a1 + 100);
      v28 = g_Hook_GuestCr3OrCtx;
      *(_DWORD *)(a2 + 188) = v27;
      GuestU8 = Hv_ReadGuestU8(v28, a1 + 104);
      v30 = g_Hook_GuestCr3OrCtx;
      *(_DWORD *)(a2 + 192) = GuestU8;
      v31 = Hv_ReadGuestU32(v30, a1 + 108);
      v32 = g_Hook_GuestCr3OrCtx;
      *(_DWORD *)(a2 + 196) = v31;
      v33 = Hv_ReadGuestU64(v32, a1 + 112);
      v34 = g_Hook_GuestCr3OrCtx;
      *(_QWORD *)(a2 + 200) = v33;
      v35 = Hv_ReadGuestU64(v34, a1 + 120);
      v36 = g_Hook_GuestCr3OrCtx;
      *(_QWORD *)(a2 + 208) = v35;
      v37 = Hv_ReadGuestU64(v36, a1 + 128);
      v38 = g_Hook_GuestCr3OrCtx;
      *(_QWORD *)(a2 + 216) = v37;
      v39 = sub_140176810(v38, a1 + 160);
      v40 = g_Hook_GuestCr3OrCtx;
      *(_QWORD *)(a2 + 240) = v39;
      v41 = sub_140176810(v40, a1 + 168);
      v42 = g_Hook_GuestCr3OrCtx;
      *(_QWORD *)(a2 + 232) = v41;
      v43 = Hv_ReadGuestU8(v42, a1 + 188);
      v44 = g_Hook_GuestCr3OrCtx;
      *(_BYTE *)(a2 + 224) = v43 != 0;
      v45 = Hv_ReadGuestU8(v44, a1 + 189);
      v46 = g_Hook_GuestCr3OrCtx;
      *(_BYTE *)(a2 + 225) = v45 == 1;
      if ( (unsigned int)Hv_ReadGuestU32(v46, a1 + 252) == 20 )
      {
        v47 = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, a1 + 240);
        v48 = v47;
        if ( (unsigned __int64)(v47 - 0xFFFF) <= 0x7FFFFFFF0000LL )
        {
          v49 = sub_140176810(g_Hook_GuestCr3OrCtx, v47 + 64);
          v50 = g_Hook_GuestCr3OrCtx;
          *(_QWORD *)(a2 + 248) = v49;
          v51 = sub_140176810(v50, v48 + 72);
          v52 = g_Hook_GuestCr3OrCtx;
          *(_QWORD *)(a2 + 256) = v51;
          v53 = Hv_ReadGuestU32(v52, v48 + 88);
          v54 = g_Hook_GuestCr3OrCtx;
          *(_DWORD *)(a2 + 264) = v53;
          v55 = Hv_ReadGuestU32(v54, v48 + 92);
          v56 = g_Hook_GuestCr3OrCtx;
          *(_DWORD *)(a2 + 268) = v55;
          v57 = Hv_ReadGuestU32(v56, v48 + 96);
          v58 = g_Hook_GuestCr3OrCtx;
          *(_DWORD *)(a2 + 272) = v57;
          v59 = sub_140176810(v58, v48 + 104);
          v60 = g_Hook_GuestCr3OrCtx;
          *(_QWORD *)(a2 + 296) = v59;
          v61 = sub_140176810(v60, v48 + 112);
          v62 = g_Hook_GuestCr3OrCtx;
          *(_QWORD *)(a2 + 280) = v61;
          v63 = sub_140176810(v62, v48 + 120);
          v64 = *(_QWORD *)(a2 + 208) == 0;
          *(_QWORD *)(a2 + 288) = v63;
          if ( v64 )
            *(_QWORD *)(a2 + 208) = Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, v48 + 128);
          v65 = Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, v48 + 140);
          v66 = g_Hook_GuestCr3OrCtx;
          *(_DWORD *)(a2 + 312) = v65;
          v67 = Hv_ReadGuestU32(v66, v48 + 152);
          v68 = g_Hook_GuestCr3OrCtx;
          *(_DWORD *)(a2 + 316) = v67;
          v69 = Hv_ReadGuestU32(v68, v48 + 200);
          v70 = g_Hook_GuestCr3OrCtx;
          *(_DWORD *)(a2 + 320) = v69;
          *(_QWORD *)(a2 + 304) = sub_140176810(v70, v48 + 232);
        }
      }
    }
  }
}


