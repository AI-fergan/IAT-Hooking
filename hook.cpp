#include "hook.h"

//struct of the old function entry data
_IMAGE_THUNK_DATA64 old_entry_data;

/*
This function using for hook any function on any IAT table of any DLL by function LOOKUP NAME only.
input:
func_to_hook - function LOOKUP NAME.
DLL_to_hook - DLL name.
new_entry_data - data structure with the new function entry data.
output: 1 - function hooked successfully \ 0 - error during the function hook process.
*/
int hook(PCSTR func_to_hook, PCSTR DLL_to_hook, _IMAGE_THUNK_DATA64 new_entry_data) {
	//PE data structers
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS NTHeader;
	PIMAGE_OPTIONAL_HEADER32 optionalHeader;
	IMAGE_DATA_DIRECTORY importDirectory;
	DWORD descriptorStartRVA;
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor;
	int index;

	bool err = true;

	/* GET THE PE DATA STRUCTURES */

	//get the ImageBase address
	uintptr_t baseAddress = reinterpret_cast<uintptr_t>(GetModuleHandle(NULL));

	//get the import directory address
	dosHeader = (PIMAGE_DOS_HEADER)(baseAddress);

	//check if the magic bytes on the dosHeader struct is the dos signature ("MZ")
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	//get the NT header address by adding the base address to the NT header RVA address
	NTHeader = (PIMAGE_NT_HEADERS)(baseAddress + dosHeader->e_lfanew);
	if (NTHeader->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	//get the optionalHeader address
	optionalHeader = (PIMAGE_OPTIONAL_HEADER32)&NTHeader->OptionalHeader;

	//check if the optionalHeader magic byte is correct
	if (optionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC && optionalHeader->Magic  != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return 0;

	//get the DLL's import directory struct address
	importDirectory = NTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	//get the RVA of the import directory
	descriptorStartRVA = importDirectory.VirtualAddress;

	//add the RVA and the BaseAddress toget the VA of the import directory
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(descriptorStartRVA + baseAddress);

	index = 0;
	char* DLL_name;

	//search the DLL name with the function to hook on all the import directory struct objects
	while (importDescriptor[index].Characteristics != 0) {
		DLL_name = (char*)(baseAddress + importDescriptor[index].Name);
		if (!strcmp(DLL_to_hook, DLL_name))
			break;
		index++;
	}

	//check if the DLL found, if not return error
	if (importDescriptor[index].Characteristics == 0)
		return 0;


	/* SEARCH THE FUNCTION ON THE DLL */

	PIMAGE_THUNK_DATA thunkILT; // ImportLookupTable (ILT) - functions names
	PIMAGE_THUNK_DATA thunkIAT; // ImportAddressTable (IAT) - functions addresses
	PIMAGE_IMPORT_BY_NAME nameData; //single ILT struct entry
	DWORD dwOld = NULL; //Vprotect var

	//get the ILT VA address by adding the RVA - (from the DLL import descriptor) and Base Address of the ILT
	thunkILT = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor[index].OriginalFirstThunk);

	//get the IAT VA address by adding the RVA - (from the DLL import descriptor) and Base Address of the IAT
	thunkIAT = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor[index].FirstThunk);

	//check if the ILT & IAT VA address found correctly
	if ((thunkIAT == NULL) or (thunkILT == NULL))
		return 0;

	//loop run if the function defined by its name or by ordinial number, until it get to the last 0 byte
	while ((thunkILT->u1.AddressOfData != 0) & (!(thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG))) {
		//get the function entry name data on the ILT by adding the Base address and the name data RVA
		nameData = (PIMAGE_IMPORT_BY_NAME)(baseAddress + (*thunkILT).u1.AddressOfData);
		
		//compare between the function to hook and the current function entry name on the ILT
		if (!strcmp(func_to_hook, (char*)(*nameData).Name)) {
			err = false;
			break;
		}

		//next entry
		thunkIAT++;
		thunkILT++;
	}

	//if the function name not found return error
	if (err)
		return 0;

	//IAT hooking the function from the DLL
	old_entry_data = (*thunkIAT);

	//remove the virtual 'READ ONLY' protect and give 'READ & WRITE' to the IAT entry page
	VirtualProtect((LPVOID) & ((*thunkIAT).u1.Function), sizeof(DWORD), PAGE_READWRITE, &dwOld);

	//write the hook address insted of the old function address on the IAT
	(*thunkIAT).u1.Function = new_entry_data.u1.Function;

	//return the 'WRITE ONLY' protect
	VirtualProtect((LPVOID) & ((*thunkIAT).u1.Function), sizeof(DWORD), dwOld, NULL);

	return 1;
};

/*
This function using for hooking the CreateFileA api func from the KERNEL32.dll.
input: just like the real CreateFileA.
output: NULL.
*/
void ShowMsgHook(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile) {

	//show hook message to the user
	MessageBoxA(0, "CreateFileA hooked successfully !", "AI-fergan", 0);
}
