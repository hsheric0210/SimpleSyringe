#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define DLL_QUERY_HMODULE		6

#define DEREF(x) *(UINT_PTR *)(x)
#define DEREF_64(x) *(DWORD64 *)(x)
#define DEREF_32(x) *(DWORD *)(x)
#define DEREF_16(x) *(WORD *)(x)
#define DEREF_8(x) *(BYTE *)(x)

typedef ULONG_PTR(WINAPI *MyReflectiveLoader)(VOID);
typedef BOOL(WINAPI *MyDllMain)(HINSTANCE, DWORD, LPVOID);

#define DLLEXPORT   __declspec( dllexport ) 
