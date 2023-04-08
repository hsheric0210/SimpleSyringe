#pragma once
#include "includes.h"
DWORD CallInjectedFunc(DWORD pid, LPWSTR moduleName, std::string funcName, size_t funcParamSize, LPVOID funcParam);