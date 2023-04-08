#pragma once
#include "includes.h"

LPVOID WriteProcessMem(HANDLE process, size_t size, LPVOID data, DWORD protect);
BOOL FindModule(DWORD pid, LPWSTR moduleName, PMODULEENTRY32W entry);
DWORD_PTR FindProcAddress(PVOID srcModuleBase, PVOID dstModuleBase, std::string funcName);
