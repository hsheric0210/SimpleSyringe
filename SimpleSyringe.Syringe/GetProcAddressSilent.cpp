#include "GetProcAddressSilent.h"

FARPROC GetProcAddressSilent(LPCWSTR libraryName, LPCSTR procName)
{
	using namespace std;

	size_t libraryNameLen = wcslen(libraryName);
	wstring libraryNameStr(libraryName);
	transform(libraryNameStr.begin(), libraryNameStr.end(), libraryNameStr.begin(), towupper);

	ULONG_PTR peb;
	//https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
#ifdef _WIN64
	peb = __readgsqword(0x60);
#else
	peb = __readfsdword(0x30);
#endif

	//cout << "[GetProcAddressSilent] Found PEB: " << (LPVOID)peb << '\n';

	// get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
	auto ldrData = (ULONG_PTR)((_PPEB)peb)->pLdr;

	//cout << "[GetProcAddressSilent] Found _PEB_LDR_DATA: " << (LPVOID)ldrData << '\n';

	// get the first entry of the InMemoryOrder module list
	auto beginEntry = (ULONG_PTR)((PPEB_LDR_DATA)ldrData)->InMemoryOrderModuleList.Flink;
	ULONG_PTR entry = beginEntry;
	while (entry)
	{
		auto dataEntry = (PLDR_DATA_TABLE_ENTRY)entry;
		auto moduleNameBuffer = dataEntry->BaseDllName.pBuffer;
		DWORD moduleNameLength1 = min(dataEntry->BaseDllName.Length, libraryNameLen);
		wstring currentLibraryName(moduleNameBuffer, moduleNameBuffer + moduleNameLength1);
		transform(currentLibraryName.begin(), currentLibraryName.end(), currentLibraryName.begin(), towupper);
		//wcout << "[GetProcAddressSilent] list entry - " << dataEntry << " module name " << currentLibraryName << " module base " << dataEntry->DllBase << '\n';

		if (libraryNameStr == currentLibraryName)
		{
			auto dllBase = (ULONG_PTR)dataEntry->DllBase;

			// get the VA of the modules NT Header
			ULONG_PTR ntHeader = dllBase + ((PIMAGE_DOS_HEADER)dllBase)->e_lfanew;

			// the address of the modules export directory entry
			PIMAGE_DATA_DIRECTORY exportDirOffset = (PIMAGE_DATA_DIRECTORY) & (((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

			// get the VA of the export directory
			PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(dllBase + exportDirOffset->VirtualAddress);

			// get the VA for the array of name pointers
			ULONG_PTR names = (dllBase + exportDir->AddressOfNames);

			// get the VA for the array of name ordinals
			ULONG_PTR nameOrdinals = (dllBase + exportDir->AddressOfNameOrdinals);

			DWORD funcCount = exportDir->NumberOfNames;

			//cout << "[GetProcAddressSilent] Total " << exportDir->NumberOfNames << " names, " << exportDir->NumberOfFunctions << " functions available\n";

			while (funcCount--)
			{
				LPSTR curFuncName = (LPSTR)(dllBase + DEREF_32(names));
				if (!strcmp(procName, curFuncName))
				{
					UINT_PTR address = (dllBase + exportDir->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					address += (DEREF_16(nameOrdinals) * sizeof(DWORD));
					address = dllBase + DEREF_32(address);
					//wcout << "[GetProcAddressSilent] Found specified proc " << currentLibraryName << '!' << curFuncName << " from " << (LPVOID)address << '\n';

					return (FARPROC)address;
				}

				// get the next exported function name
				names += sizeof(DWORD);

				// get the next exported function name ordinal
				nameOrdinals += sizeof(WORD);
			}

			cout << "[GetProcAddressSilent] Specified procedure " << procName << " not found!\n";

			return nullptr;
		}

		entry = DEREF(dataEntry);
		if (entry == beginEntry) // Because it's an cyclic doubly linked list
			break;
	}

	cout << "[GetProcAddressSilent] Specified library " << libraryName << " not found!\n";

	return nullptr;
}

// Prevent detection by string analysis
FARPROC GetProcAddressSilentObscured(DWORD libNameLen, LPCWSTR _libName, DWORD procNameLen, LPCSTR _procName)
{
	int i;
	LPWSTR libName = new WCHAR[libNameLen + 1]{ 0 };
	for (i = 0; i < libNameLen; i++)
		libName[i] = _libName[i] ^ XOR_KEY;
	LPSTR procName = new CHAR[procNameLen + 1]{ 0 };
	for (i = 0; i < procNameLen; i++)
		procName[i] = _procName[i] ^ XOR_KEY;
	FARPROC ret = GetProcAddressSilent(libName, procName);
	delete[] libName;
	delete[] procName;
	return ret;
}