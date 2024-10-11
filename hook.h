#pragma once
#ifndef HOOK_H
#define HOOK_H

#include "pch.h"

//CreateFileA function type
typedef HANDLE(*CreateFileA_t)(
	LPCSTR,
	DWORD,
	DWORD,
	LPSECURITY_ATTRIBUTES,
	DWORD,
	DWORD,
	HANDLE
	);

//struct of the old function entry data
static _IMAGE_THUNK_DATA64 old_entry_data;

//hook dll function
int hook(PCSTR func_to_hook, PCSTR DLL_to_hook, _IMAGE_THUNK_DATA64 new_entry_data);

//new function to replace the original function
void ShowMsgHook(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
);

#endif