#include "utils.h"

LPVOID WriteProcessMem(HANDLE process, size_t size, LPVOID data, DWORD protect)
{
	std::cout << "[WriteProcessMem] Write requested of " << size << " bytes\n";

	LPVOID memory = VirtualAllocEx(process, nullptr, size, MEM_COMMIT, protect);
	if (!memory)
	{
		std::cout << "[WriteProcessMem] Allocation failure with error " << GetLastError() << '\n';
		return nullptr;
	}

	std::cout << "[WriteProcessMem] Allocated " << memory << '\n';

	BOOL state = WriteProcessMemory(process, memory, data, size, nullptr);
	if (!state)
	{
		std::cout << "[WriteProcessMem] Write failure with error " << GetLastError() << '\n';
		return nullptr;
	}

	return memory;
}

BOOL FindModule(DWORD pid, LPWSTR moduleName, PMODULEENTRY32W entry)
{
	using namespace std;

	HANDLE moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	cout << "[FindModule] Enumerating modules of the target process. error code " << GetLastError() << '\n';
	if (moduleSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	MODULEENTRY32W moduleEntry = { sizeof(MODULEENTRY32W) };
	BOOL found = FALSE;

	LPWSTR moduleNameCopy = new WCHAR[wcslen(moduleName) + 1];
	lstrcpyW(moduleNameCopy, moduleName);
	_wcslwr_s(moduleNameCopy, wcslen(moduleName) + 1);
	wstring targetModulePath(moduleNameCopy);
	delete[] moduleNameCopy;

	for (BOOL hasNext = Module32FirstW(moduleSnapshot, &moduleEntry); hasNext; hasNext = Module32NextW(moduleSnapshot, &moduleEntry))
	{
		LPWSTR _modulePath = new WCHAR[wcslen(moduleEntry.szExePath) + 1];
		lstrcpyW(_modulePath, moduleEntry.szExePath);
		_wcslwr_s(_modulePath, wcslen(moduleEntry.szExePath) + 1);
		wstring modulePath(_modulePath);
		delete[] _modulePath;

		wcout << "[FindModule] Module available: " << modulePath << '\n';
		if (targetModulePath == modulePath)
		{
			found = TRUE;

			break;
		}
	}

	if (!found)
	{
		cout << "[FindModule] Specified module not found. (maybe not loaded yet)\n";
		return FALSE;
	}
	wcout << "[FindModule] Specified module '" << moduleEntry.szExePath << "' found. Base address is 0x" << moduleEntry.modBaseAddr << "\n";

	*entry = moduleEntry;
	return TRUE;
}

DWORD_PTR FindProcAddress(PVOID srcModuleBase, PVOID dstModuleBase, std::string funcName)
{
	using namespace std;

	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(static_cast<HMODULE>(srcModuleBase));
	if (!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		cout << "[FindProcAddress] Invalid DOS header\n";
		return NULL;
	}

	PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PCHAR>(srcModuleBase) + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		cout << "[FindProcAddress] Invalid NT header\n";
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<PBYTE>(srcModuleBase) + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (exportDirectory->AddressOfNames == NULL)
	{
		cout << "[FindProcAddress] There are no exported address names\n";
		return NULL;
	}

	PDWORD nameRVAs = reinterpret_cast<PDWORD>(reinterpret_cast<PBYTE>(srcModuleBase) + exportDirectory->AddressOfNames);
	PWORD nameOrdinals = reinterpret_cast<PWORD>(reinterpret_cast<PBYTE>(srcModuleBase) + exportDirectory->AddressOfNameOrdinals);
	PDWORD funcAddresses = reinterpret_cast<PDWORD>(reinterpret_cast<PBYTE>(srcModuleBase) + exportDirectory->AddressOfFunctions);

	FARPROC exportAddress = NULL;
	for (DWORD i = 0, j = exportDirectory->NumberOfNames; i < j; i++)
	{
		PSTR thisFuncName = reinterpret_cast<PSTR>(reinterpret_cast<PBYTE>(srcModuleBase) + nameRVAs[i]);
		if (funcName != thisFuncName) continue;
		WORD ord = nameOrdinals[i];
		exportAddress = reinterpret_cast<FARPROC>(reinterpret_cast<PBYTE>(srcModuleBase) + funcAddresses[ord]);
	}

	// Relocate pointer (exportFunctionAddress - loadedModuleBase) + targetProcessModuleBase
	return (reinterpret_cast<DWORD_PTR>(exportAddress) - reinterpret_cast<DWORD_PTR>(srcModuleBase)) + reinterpret_cast<DWORD_PTR>(dstModuleBase);
}