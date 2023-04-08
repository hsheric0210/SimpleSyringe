#include "pch.h"
#include "ReflectiveLoader.h"

// Our loader will set this to a pseudo correct HINSTANCE/HMODULE value
HINSTANCE hAppInstance = NULL;

#pragma intrinsic( _ReturnAddress )
// This function can not be inlined by the compiler or we will not get the address we expect. Ideally 
// this code will be compiled with the /O2 and /Ob1 switches. Bonus points if we could take advantage of 
// RIP relative addressing in this instance but I dont believe we can do so with the compiler intrinsics 
// available (and no inline asm available under x64).
__declspec(noinline) ULONG_PTR caller(VOID)
{
	return (ULONG_PTR)_ReturnAddress();
}

// Note 1: If you want to have your own DllMain, define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN,  
//         otherwise the DllMain at the end of this file will be used.

// Note 2: If you are injecting the DLL via LoadRemoteLibraryR, define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR,
//         otherwise it is assumed you are calling the ReflectiveLoader via a stub.

// This is our position independent reflective DLL loader/injector
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID parameter)
{
	// the functions we need
	MyLoadLibraryA myLoadLibraryA = NULL;
	MyGetProcAddress myGetProcAddress = NULL;
	MyVirtualAlloc myVirtualAlloc = NULL;
	MyNtFlushInstructionCache myNtFlushInstructionCache = NULL;

#pragma region("STEP 0: calculate our images current base address")

	// the initial location of this image in memory
	// we will start searching backwards from our callers return address.
	ULONG_PTR libraryLocation = caller();

	// loop through memory backwards searching for our images base address
	// we dont need SEH style search as we shouldnt generate any access violations with this from here
	while (TRUE)
	{
		// Let's find MZ header
		if (((PIMAGE_DOS_HEADER)libraryLocation)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			UINT_PTR headerValue = ((PIMAGE_DOS_HEADER)libraryLocation)->e_lfanew;

			// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
			// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
			if (headerValue >= sizeof(IMAGE_DOS_HEADER) && headerValue < 1024)
			{
				headerValue += libraryLocation;
				// break if we have found a valid MZ/PE header
				if (((PIMAGE_NT_HEADERS)headerValue)->Signature == IMAGE_NT_SIGNATURE)
					break;
			}
		}
		libraryLocation--;
	}
#pragma endregion

#pragma region("STEP 1: process the kernels exports for the functions our loader needs...")

	// get the Process Enviroment Block
#ifdef _WIN64
	ULONG_PTR peb = __readgsqword(0x60);
#elif _WIN32
	ULONG_PTR peb = __readfsdword(0x30);
#else _M_ARM 
	ULONG_PTR peb = *(DWORD *)((BYTE *)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30);
#endif

	// get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
	auto ldrData = (ULONG_PTR)((_PPEB)peb)->pLdr;

	// get the first entry of the InMemoryOrder module list
	auto inMemoryOrderModuleEntry = (ULONG_PTR)((PPEB_LDR_DATA)ldrData)->InMemoryOrderModuleList.Flink;
	while (inMemoryOrderModuleEntry)
	{
		// get pointer to current modules name (unicode string)
		auto moduleName = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)inMemoryOrderModuleEntry)->BaseDllName.pBuffer;
		// set bCounter to the length for the loop
		DWORD moduleNameLength = ((PLDR_DATA_TABLE_ENTRY)inMemoryOrderModuleEntry)->BaseDllName.Length;
		// clear uiValueC which will store the hash of the module name
		DWORD dllNameHash = 0;

		// compute the hash of the module name...
		// using the hash because we can't use any string literals here as this code is being code-injected.
		do
		{
			dllNameHash = ror(dllNameHash);
			// normalize to uppercase if the madule name is in lowercase
			if (*((BYTE *)moduleName) >= 'a')
				dllNameHash += *((BYTE *)moduleName) - 0x20;
			else
				dllNameHash += *((BYTE *)moduleName);
			moduleName++;
		} while (--moduleNameLength);

		// compare the hash with that of kernel32.dll
		if (dllNameHash == KERNEL32DLL_HASH)
		{
#pragma region ("kernel32.dll - LoadLibraryA, GetProcAddress, VirtualAlloc")
			// get this modules base address
			auto dllBase = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)inMemoryOrderModuleEntry)->DllBase;

			// get the VA of the modules NT Header
			ULONG_PTR ntHeader = dllBase + ((PIMAGE_DOS_HEADER)dllBase)->e_lfanew;

			// the address of the modules export directory entry
			auto exportDir = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			ULONG_PTR exportDirVA = (dllBase + ((PIMAGE_DATA_DIRECTORY)exportDir)->VirtualAddress);

			// get the VA for the array of name pointers
			ULONG_PTR names = (dllBase + ((PIMAGE_EXPORT_DIRECTORY)exportDirVA)->AddressOfNames);

			// get the VA for the array of name ordinals
			ULONG_PTR nameOrdinals = (dllBase + ((PIMAGE_EXPORT_DIRECTORY)exportDirVA)->AddressOfNameOrdinals);

			DWORD funcCount = 3;

			// loop while we still have imports to find
			while (funcCount > 0)
			{
				// compute the hash values for this function name
				DWORD nameHash = hash((char *)(dllBase + DEREF_32(names)));

				// if we have found a function we want we get its virtual address
				if (nameHash == LOADLIBRARYA_HASH || nameHash == GETPROCADDRESS_HASH || nameHash == VIRTUALALLOC_HASH)
				{
					// get the VA for the array of addresses
					UINT_PTR adress = (dllBase + ((PIMAGE_EXPORT_DIRECTORY)exportDirVA)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					adress += (DEREF_16(nameOrdinals) * sizeof(DWORD));

					// store this functions VA
					if (nameHash == LOADLIBRARYA_HASH)
						myLoadLibraryA = (MyLoadLibraryA)(dllBase + DEREF_32(adress));
					else if (nameHash == GETPROCADDRESS_HASH)
						myGetProcAddress = (MyGetProcAddress)(dllBase + DEREF_32(adress));
					else if (nameHash == VIRTUALALLOC_HASH)
						myVirtualAlloc = (MyVirtualAlloc)(dllBase + DEREF_32(adress));

					// decrement our counter
					funcCount--;
				}

				// get the next exported function name
				names += sizeof(DWORD);

				// get the next exported function name ordinal
				nameOrdinals += sizeof(WORD);
			}
#pragma endregion
		}
		else if (dllNameHash == NTDLLDLL_HASH)
		{
#pragma region("ntdll.dll - NtFlushInstructionCache")
			// get this modules base address
			ULONG_PTR uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)inMemoryOrderModuleEntry)->DllBase;

			// get the VA of the modules NT Header
			ULONG_PTR ntHeader = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			ULONG_PTR exportDir = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			ULONG_PTR exportDirVA = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)exportDir)->VirtualAddress);

			// get the VA for the array of name pointers
			ULONG_PTR names = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)exportDirVA)->AddressOfNames);

			// get the VA for the array of name ordinals
			ULONG_PTR nameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)exportDirVA)->AddressOfNameOrdinals);

			DWORD funcCount = 1;

			// loop while we still have imports to find
			while (funcCount > 0)
			{
				// compute the hash values for this function name
				DWORD nameHash = hash((char *)(uiBaseAddress + DEREF_32(names)));

				// if we have found a function we want we get its virtual address
				if (nameHash == NTFLUSHINSTRUCTIONCACHE_HASH)
				{
					// get the VA for the array of addresses
					ULONG_PTR uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)exportDirVA)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(nameOrdinals) * sizeof(DWORD));

					// store this functions VA
					if (nameHash == NTFLUSHINSTRUCTIONCACHE_HASH)
						myNtFlushInstructionCache = (MyNtFlushInstructionCache)(uiBaseAddress + DEREF_32(uiAddressArray));

					// decrement our counter
					funcCount--;
				}

				// get the next exported function name
				names += sizeof(DWORD);

				// get the next exported function name ordinal
				nameOrdinals += sizeof(WORD);
			}
#pragma endregion
		}

		// we stop searching when we have found everything we need.
		if (myLoadLibraryA && myGetProcAddress && myVirtualAlloc && myNtFlushInstructionCache)
			break;

		// get the next entry
		inMemoryOrderModuleEntry = DEREF(inMemoryOrderModuleEntry);
	}
#pragma endregion

#pragma region("STEP 2: load our image into a new permanent location in memory...")
	// get the VA of the NT Header for the PE to be loaded
	UINT_PTR ntHeader = libraryLocation + ((PIMAGE_DOS_HEADER)libraryLocation)->e_lfanew;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	UINT_PTR buffer = (ULONG_PTR)myVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// we must now copy over the headers
	DWORD headerSize = ((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.SizeOfHeaders;
	UINT_PTR localHeader = libraryLocation;
	UINT_PTR remoteHeader = buffer;

	while (headerSize--)
		*(BYTE *)remoteHeader++ = *(BYTE *)localHeader++; // NOTE: Can't use memcpy because this code will be code-injected

#pragma endregion

#pragma region("STEP 3: load in all of our sections...")
	// the VA of the first section
	UINT_PTR sectionEntry = ((ULONG_PTR) & ((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader + ((PIMAGE_NT_HEADERS)ntHeader)->FileHeader.SizeOfOptionalHeader);

	// iterate through all sections, loading them into memory.
	DWORD sectionCount = ((PIMAGE_NT_HEADERS)ntHeader)->FileHeader.NumberOfSections;
	while (sectionCount--)
	{
		UINT_PTR remoteSectionVA = (buffer + ((PIMAGE_SECTION_HEADER)sectionEntry)->VirtualAddress);
		UINT_PTR localSectionDataVA = (libraryLocation + ((PIMAGE_SECTION_HEADER)sectionEntry)->PointerToRawData);

		// copy the section over
		DWORD sectionSize = ((PIMAGE_SECTION_HEADER)sectionEntry)->SizeOfRawData;

		while (sectionSize--)
			*(BYTE *)remoteSectionVA++ = *(BYTE *)localSectionDataVA++;

		// get the VA of the next section
		sectionEntry += sizeof(IMAGE_SECTION_HEADER);
	}
#pragma endregion

#pragma region("STEP 4: process our images import table...")
	// uiValueB = the address of the import directory
	auto importDir = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// we assume their is an import table to process
	// the first entry in the import table
	UINT_PTR iatEntry = (buffer + ((PIMAGE_DATA_DIRECTORY)importDir)->VirtualAddress);

	// iterate through all imports
	while (((PIMAGE_IMPORT_DESCRIPTOR)iatEntry)->Name)
	{
		// use LoadLibraryA to load the imported module into memory
		// TODO: Use LoadLibraryW instead
		auto moduleBase = (ULONG_PTR)myLoadLibraryA((LPCSTR)(buffer + ((PIMAGE_IMPORT_DESCRIPTOR)iatEntry)->Name));

		// firstThunkVA = VA of the OriginalFirstThunk
		UINT_PTR firstThunkVA = (buffer + ((PIMAGE_IMPORT_DESCRIPTOR)iatEntry)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		ULONG_PTR iatVA = (buffer + ((PIMAGE_IMPORT_DESCRIPTOR)iatEntry)->FirstThunk);

		// iterate through all imported functions, importing by ordinal if no name present
		while (DEREF(iatVA))
		{
			// sanity check firstThunkVA as some compilers only import by FirstThunk
			if (firstThunkVA && ((PIMAGE_THUNK_DATA)firstThunkVA)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// get the VA of the modules NT Header
				UINT_PTR ntHeader = moduleBase + ((PIMAGE_DOS_HEADER)moduleBase)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				auto exportDir = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				// get the VA of the export directory
				UINT_PTR exportDirVA = (moduleBase + ((PIMAGE_DATA_DIRECTORY)exportDir)->VirtualAddress);

				// get the VA for the array of addresses
				UINT_PTR address = (moduleBase + ((PIMAGE_EXPORT_DIRECTORY)exportDirVA)->AddressOfFunctions);

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				address += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)firstThunkVA)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)exportDirVA)->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				DEREF(iatVA) = (moduleBase + DEREF_32(address));
			}
			else
			{
				// get the VA of this functions import by name struct
				UINT_PTR uiValueB = (buffer + DEREF(iatVA));

				// use GetProcAddress and patch in the address for this imported function
				DEREF(iatVA) = (ULONG_PTR)myGetProcAddress((HMODULE)moduleBase, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
			}
			// get the next imported function
			iatVA += sizeof(ULONG_PTR);
			if (firstThunkVA)
				firstThunkVA += sizeof(ULONG_PTR);
		}

		// get the next import
		iatEntry += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
#pragma endregion

#pragma region("STEP 5: process all of our images relocations...")
	// calculate the base address delta and perform relocations (even if we load at desired image base)
	libraryLocation = buffer - ((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.ImageBase;

	// the address of the relocation directory
	UINT_PTR relocDir = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// check if their are any relocations present
	if (((PIMAGE_DATA_DIRECTORY)relocDir)->Size)
	{
		// the first entry (IMAGE_BASE_RELOCATION)
		UINT_PTR remoteRelocEntry = (buffer + ((PIMAGE_DATA_DIRECTORY)relocDir)->VirtualAddress);

		// and we iterate through all entries...
		while (((PIMAGE_BASE_RELOCATION)remoteRelocEntry)->SizeOfBlock)
		{
			// the VA for this relocation block
			UINT_PTR remoteRelocVA = (buffer + ((PIMAGE_BASE_RELOCATION)remoteRelocEntry)->VirtualAddress);

			// number of entries in this relocation block
			DWORD remoteRelocBlockCount = (((PIMAGE_BASE_RELOCATION)remoteRelocEntry)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// the first entry in the current relocation block
			UINT_PTR remoteRelocBlock = remoteRelocEntry + sizeof(IMAGE_BASE_RELOCATION);

			// we iterate through all the entries in the current block...
			while (remoteRelocBlockCount--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table which would not be very position independent!
				if (((PIMAGE_RELOC)remoteRelocBlock)->type == IMAGE_REL_BASED_DIR64)
					*(ULONG_PTR *)(remoteRelocVA + ((PIMAGE_RELOC)remoteRelocBlock)->offset) += libraryLocation;
				else if (((PIMAGE_RELOC)remoteRelocBlock)->type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD *)(remoteRelocVA + ((PIMAGE_RELOC)remoteRelocBlock)->offset) += (DWORD)libraryLocation;
#ifdef WIN_ARM
				// Note: On ARM, the compiler optimization /O2 seems to introduce an off by one issue, possibly a code gen bug. Using /O1 instead avoids this problem.
				else if (((PIMAGE_RELOC)relocBlockEntry)->type == IMAGE_REL_BASED_ARM_MOV32T)
				{
					register DWORD dwInstruction;
					register DWORD dwAddress;
					register WORD wImm;
					// get the MOV.T instructions DWORD value (We add 4 to the offset to go past the first MOV.W which handles the low word)
					dwInstruction = *(DWORD *)(relocBlockVA + ((PIMAGE_RELOC)relocBlockEntry)->offset + sizeof(DWORD));
					// flip the words to get the instruction as expected
					dwInstruction = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
					// sanity chack we are processing a MOV instruction...
					if ((dwInstruction & ARM_MOV_MASK) == ARM_MOVT)
					{
						// pull out the encoded 16bit value (the high portion of the address-to-relocate)
						wImm = (WORD)(dwInstruction & 0x000000FF);
						wImm |= (WORD)((dwInstruction & 0x00007000) >> 4);
						wImm |= (WORD)((dwInstruction & 0x04000000) >> 15);
						wImm |= (WORD)((dwInstruction & 0x000F0000) >> 4);
						// apply the relocation to the target address
						dwAddress = ((WORD)HIWORD(uiLibraryAddress) + wImm) & 0xFFFF;
						// now create a new instruction with the same opcode and register param.
						dwInstruction = (DWORD)(dwInstruction & ARM_MOV_MASK2);
						// patch in the relocated address...
						dwInstruction |= (DWORD)(dwAddress & 0x00FF);
						dwInstruction |= (DWORD)(dwAddress & 0x0700) << 4;
						dwInstruction |= (DWORD)(dwAddress & 0x0800) << 15;
						dwInstruction |= (DWORD)(dwAddress & 0xF000) << 4;
						// now flip the instructions words and patch back into the code...
						*(DWORD *)(relocBlockVA + ((PIMAGE_RELOC)relocBlockEntry)->offset + sizeof(DWORD)) = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
					}
				}
#endif
				else if (((PIMAGE_RELOC)remoteRelocBlock)->type == IMAGE_REL_BASED_HIGH)
					*(WORD *)(remoteRelocVA + ((PIMAGE_RELOC)remoteRelocBlock)->offset) += HIWORD(libraryLocation);
				else if (((PIMAGE_RELOC)remoteRelocBlock)->type == IMAGE_REL_BASED_LOW)
					*(WORD *)(remoteRelocVA + ((PIMAGE_RELOC)remoteRelocBlock)->offset) += LOWORD(libraryLocation);

				// get the next entry in the current relocation block
				remoteRelocBlock += sizeof(IMAGE_RELOC);
			}

			// get the next entry in the relocation directory
			remoteRelocEntry = remoteRelocEntry + ((PIMAGE_BASE_RELOCATION)remoteRelocEntry)->SizeOfBlock;
		}
	}
#pragma endregion

#pragma region("STEP 6: call our images entry point")
	// the VA of our newly loaded DLL/EXE's entry point
	UINT_PTR entryPointVA = (buffer + ((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.AddressOfEntryPoint);

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	myNtFlushInstructionCache((HANDLE)-1, NULL, 0);

	// call our respective entry point, fudging our hInstance value
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
	((DLLMAIN)entryPointVA)((HINSTANCE)buffer, DLL_PROCESS_ATTACH, parameter);
#pragma endregion

	// STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
	return entryPointVA;
}
