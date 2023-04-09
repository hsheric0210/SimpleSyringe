#pragma once
#include "includes.h"

#define DLL_METASPLOIT_ATTACH	4
#define DLL_METASPLOIT_DETACH	5
#define DLL_QUERY_HMODULE		6

#define DEREF(x) *(UINT_PTR *)(x)
#define DEREF_64(x) *(DWORD64 *)(x)
#define DEREF_32(x) *(DWORD *)(x)
#define DEREF_16(x) *(WORD *)(x)
#define DEREF_8(x) *(BYTE *)(x)

typedef ULONG_PTR(WINAPI *MyReflectiveLoader)(VOID);
typedef BOOL(WINAPI *MyDllMain)(HINSTANCE, DWORD, LPVOID);
