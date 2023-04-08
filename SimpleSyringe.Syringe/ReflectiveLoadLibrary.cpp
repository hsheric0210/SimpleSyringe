#include "ReflectiveLoadLibrary.h"
#include <stdio.h>

DWORD Rva2Offset(DWORD rva, UINT_PTR baseAddress)
{
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(baseAddress + ((PIMAGE_DOS_HEADER)baseAddress)->e_lfanew);

	PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&ntHeader->OptionalHeader) + ntHeader->FileHeader.SizeOfOptionalHeader);

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
	DWORD compileArch = 2;
#else
	// This will catch Win32 and WinRT.
	DWORD compileArch = 1;
#endif

	// get the File Offset of the modules NT Header
	UINT_PTR ntHeader = baseAddress + ((PIMAGE_DOS_HEADER)baseAddress)->e_lfanew;

	// currenlty we can only process a PE file which is the same type as the one this fuction has 
	// been compiled as, due to various offset in the PE structures being defined at compile time.
	if (((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.Magic == 0x010B) // PE32
	{
		if (compileArch != 1)
			return 0;
	}
	else if (((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.Magic == 0x020B) // PE64
	{
		if (compileArch != 2)
			return 0;
	}
	else
		return 0;

	// uiNameArray = the address of the modules export directory entry
	auto exportDirectory = (UINT_PTR) & ((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// get the File Offset of the export directory
	UINT_PTR exportDirectoryOffset = baseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)exportDirectory)->VirtualAddress, baseAddress);

	// get the File Offset for the array of name pointers
	UINT_PTR nameOffsets = baseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)exportDirectoryOffset)->AddressOfNames, baseAddress);

	// get the File Offset for the array of addresses
	UINT_PTR funcOffsets = baseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)exportDirectoryOffset)->AddressOfFunctions, baseAddress);

	// get the File Offset for the array of name ordinals
	UINT_PTR nameOrdinalOffsets = baseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)exportDirectoryOffset)->AddressOfNameOrdinals, baseAddress);

	// get a counter for the number of exported functions...
	DWORD nameCount = ((PIMAGE_EXPORT_DIRECTORY)exportDirectoryOffset)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	while (nameCount--)
	{
		char *funcName = (char *)(baseAddress + Rva2Offset(DEREF_32(nameOffsets), baseAddress));

		if (strstr(funcName, "ReflectiveLoader") != NULL)
		{
			/*
			// get the File Offset for the array of addresses
			funcOffsets = baseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)exportDirectoryOffset)->AddressOfFunctions, baseAddress);

			// use the functions name ordinal as an index into the array of name pointers
			funcOffsets += (DEREF_16(nameOrdinalOffsets) * sizeof(DWORD));
			*/

			// return the File Offset to the ReflectiveLoader() functions code...
			return Rva2Offset(DEREF_32(funcOffsets + (DEREF_16(nameOrdinalOffsets) * sizeof(DWORD))), baseAddress);
		}
		// get the next exported function name
		nameOffsets += sizeof(DWORD);

		// get the next exported function name ordinal
		nameOrdinalOffsets += sizeof(WORD);
	}

	return 0;
}

// Loads a DLL image from memory via its exported ReflectiveLoader function
HMODULE WINAPI LoadLibraryR(LPVOID baseAddress, DWORD dwLength)
{
	HMODULE moduleHandle = nullptr;

	if (!baseAddress || !dwLength)
		return nullptr;

	__try
	{
		// check if the library has a ReflectiveLoader...
		DWORD reflectiveLoaderOffset = GetReflectiveLoaderOffset((UINT_PTR)baseAddress);
		if (reflectiveLoaderOffset)
		{
			REFLECTIVELOADER reflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)baseAddress + reflectiveLoaderOffset);

			// we must VirtualProtect the buffer to RWX so we can execute the ReflectiveLoader...
			// this assumes lpBuffer is the base address of the region of pages and dwLength the size of the region
			DWORD prevProtect = 0;
			if (VirtualProtect(baseAddress, dwLength, PAGE_EXECUTE_READWRITE, &prevProtect))
			{
				// call the librarys ReflectiveLoader...
				DLLMAIN dllMain = (DLLMAIN)reflectiveLoader();
				if (dllMain)
				{
					// call the loaded librarys DllMain to get its HMODULE
					if (!dllMain(nullptr, DLL_QUERY_HMODULE, &moduleHandle))
						moduleHandle = nullptr;
				}

				// revert to the previous protection flags...
				DWORD _prevProtect = 0;
				VirtualProtect(baseAddress, dwLength, prevProtect, &_prevProtect);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		moduleHandle = nullptr;
	}

	return moduleHandle;
}

// Loads a PE image from memory into the address space of a host process via the image's exported ReflectiveLoader function
// Note: You must compile whatever you are injecting with REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR 
//       defined in order to use the correct RDI prototypes.
// Note: The hProcess handle must have these access rights: PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
//       PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
// Note: If you are passing in an lpParameter value, if it is a pointer, remember it is for a different address space.
// Note: This function currently cant inject accross architectures, but only to architectures which are the 
//       same as the arch this function is compiled as, e.g. x86->x86 and x64->x64 but not x64->x86 or x86->x64.
LPVOID WINAPI LoadRemoteLibraryR(HANDLE process, LPVOID myBuffer, DWORD size, LPVOID param)
{
	using namespace std;
	__try
	{
		do
		{
			if (!process || !myBuffer || !size)
				break;

			// check if the library has a ReflectiveLoader...
			DWORD reflectiveLoaderOffset = GetReflectiveLoaderOffset((UINT_PTR)myBuffer);
			if (!reflectiveLoaderOffset)
				break;

			// alloc memory (RWX) in the host process for the image...
			LPVOID buffer = VirtualAllocEx(process, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			cout << "Allocated target process memory " << buffer << " / error code " << GetLastError() << '\n';
			if (!buffer)
				break;

			// write the image into the host process...
			BOOL state = WriteProcessMemory(process, buffer, myBuffer, size, nullptr);
			cout << "Write DLL image to target process / error code " << GetLastError() << '\n';
			if (!state)
				break;

			// add the offset to ReflectiveLoader() to the remote library address...
			auto lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)buffer + reflectiveLoaderOffset);
			cout << "[LoadRemoveLibraryR] Reflective Loader address: " << lpReflectiveLoader << '\n';

			// create a remote thread in the host process to call the ReflectiveLoader!
			HANDLE hThread = CreateRemoteThread(process, nullptr, 1024 * 1024, lpReflectiveLoader, param, (DWORD)NULL, nullptr);
			cout << "[LoadRemoteLibraryR] Remote thread " << hThread << " creation error code " << GetLastError() << '\n';
			WaitForSingleObject(hThread, INFINITE);
			CloseHandle(hThread);
			return buffer;
		} while (FALSE);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return nullptr;
	}
}
