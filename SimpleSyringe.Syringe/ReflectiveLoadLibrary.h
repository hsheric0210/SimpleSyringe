#pragma once
#include "includes.h"
#include "ReflectiveLoaderDefs.h"
DWORD GetReflectiveLoaderOffset(UINT_PTR baseAddress, LPCSTR procName);
HMODULE WINAPI LoadLibraryR(LPVOID lpBuffer, DWORD dwLength, LPCSTR procName);
HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPCSTR procName, LPVOID lpParameter);
