#include "ReflectiveLoadLibrary.h"
//https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/inject/src/LoadLibraryR.c

DWORD Rva2Offset(DWORD rva, UINT_PTR baseAddress)
{
	auto ntHeader = (PIMAGE_NT_HEADERS)(baseAddress + ((PIMAGE_DOS_HEADER)baseAddress)->e_lfanew);
	auto sectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&ntHeader->OptionalHeader) + ntHeader->FileHeader.SizeOfOptionalHeader); // section header is located next to the optional header

	if (rva < sectionHeader[0].PointerToRawData)
		return rva;

	for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		if (rva >= sectionHeader[i].VirtualAddress && rva < (sectionHeader[i].VirtualAddress + sectionHeader[i].SizeOfRawData))
			return (rva - sectionHeader[i].VirtualAddress + sectionHeader[i].PointerToRawData);
	}

	return 0;
}

DWORD GetReflectiveLoaderOffset(UINT_PTR baseAddress)
{
#ifdef _WIN64
	DWORD isW64 = 1;
#else
	// This will catch Win32 and WinRT.
	DWORD isW64 = 0;
#endif

	UINT_PTR ntHeader = baseAddress + ((PIMAGE_DOS_HEADER)baseAddress)->e_lfanew;

	// currenlty we can only process a PE file which is the same type as the one this fuction has  
	// been compiled as, due to various offset in the PE structures being defined at compile time.
	if (((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.Magic == 0x010B) // PE32
	{
		if (isW64 != 0)
			return 0;
	}
	else if (((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.Magic == 0x020B) // PE64
	{
		if (isW64 != 1)
			return 0;
	}
	else
	{
		return 0;
	}

	// relocate export directory
	auto exportDirectory = (UINT_PTR) & ((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	UINT_PTR relocatedExportDirectory = baseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)exportDirectory)->VirtualAddress, baseAddress);

	// arrays from relocated export directory
	UINT_PTR names = baseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)relocatedExportDirectory)->AddressOfNames, baseAddress);
	UINT_PTR addresses = baseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)relocatedExportDirectory)->AddressOfFunctions, baseAddress);
	UINT_PTR ordinals = baseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)relocatedExportDirectory)->AddressOfNameOrdinals, baseAddress);

	// loop through exported func array; to find ReflectiveLoader()
	DWORD count = ((PIMAGE_EXPORT_DIRECTORY)relocatedExportDirectory)->NumberOfNames;
	while (count--)
	{
		auto cpExportedFunctionName = (PSTR)(baseAddress + Rva2Offset(DEREF_32(names), baseAddress));

		if (strstr(cpExportedFunctionName, "ReflectiveLoader"))
		{
			// get the File Offset for the array of 
			// already this value
			// addresses = baseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)vaOffset)->AddressOfFunctions, baseAddress);

			addresses += (DEREF_16(ordinals) * sizeof(DWORD));
			return Rva2Offset(DEREF_32(addresses), baseAddress);
		}

		names += sizeof(DWORD);
		ordinals += sizeof(WORD);
	}

	return 0;
}

//===============================================================================================//
// Loads a DLL image from memory via its exported ReflectiveLoader function
HMODULE WINAPI LoadLibraryR(LPVOID baseAddress, DWORD size)
{
	if (baseAddress == nullptr || size == 0)
		return nullptr;

	HMODULE hResult = nullptr;
	__try
	{
		// check if the library has a ReflectiveLoader...
		DWORD loaderOffset = GetReflectiveLoaderOffset((UINT_PTR)baseAddress);
		if (loaderOffset != 0)
		{
			auto loader = (REFLECTIVELOADER)((UINT_PTR)baseAddress + loaderOffset);

			// we must VirtualProtect the buffer to RWX so we can execute the ReflectiveLoader...
			DWORD prevProtect = 0, prevProtect2 = 0;
			if (VirtualProtect(baseAddress, size, PAGE_EXECUTE_READWRITE, &prevProtect))
			{
				// call the librarys ReflectiveLoader...
				DLLMAIN dllMain = (DLLMAIN)loader();
				if (dllMain)
				{
					// call the loaded librarys DllMain to get its HMODULE
					if (!dllMain(nullptr, DLL_QUERY_HMODULE, &hResult))
						hResult = nullptr;
				}

				// revert to the previous protection flags...
				VirtualProtect(baseAddress, size, prevProtect, &prevProtect2);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		hResult = nullptr;
	}

	return hResult;
}
//===============================================================================================//
// Loads a PE image from memory into the address space of a host process via the image's exported ReflectiveLoader function
// Note: You must compile whatever you are injecting with REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR 
//       defined in order to use the correct RDI prototypes.
// Note: The hProcess handle must have these access rights: PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
//       PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
// Note: If you are passing in an lpParameter value, if it is a pointer, remember it is for a different address space.
// Note: This function currently cant inject accross architectures, but only to architectures which are the 
//       same as the arch this function is compiled as, e.g. x86->x86 and x64->x64 but not x64->x86 or x86->x64.
HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter)
{
	BOOL bSuccess = FALSE;
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	DWORD dwThreadId = 0;

	__try
	{
		do
		{
			if (!hProcess || !lpBuffer || !dwLength)
				break;

			// check if the library has a ReflectiveLoader...
			dwReflectiveLoaderOffset = GetReflectiveLoaderOffset((UINT_PTR)lpBuffer);
			if (!dwReflectiveLoaderOffset)
				break;

			// alloc memory (RWX) in the host process for the image...
			lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!lpRemoteLibraryBuffer)
				break;

			// write the image into the host process...
			if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
				break;

			// add the offset to ReflectiveLoader() to the remote library address...
			lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

			// create a remote thread in the host process to call the ReflectiveLoader!
			hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, lpParameter, (DWORD)NULL, &dwThreadId);

		} while (0);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		hThread = NULL;
	}

	return hThread;
}