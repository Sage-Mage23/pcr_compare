#pragma once
#include <ntddk.h>
#include <evntrace.h>
#include <ntstrsafe.h>

extern "C" {
	NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation (
		_In_ ULONG SystemInformationClass ,
		_Out_writes_bytes_opt_ ( SystemInformationLength ) PVOID SystemInformation ,
		_In_ ULONG SystemInformationLength ,
		_Out_opt_ PULONG ReturnLength
	);
}

#include <source/api/tpm.h>
#include <source/secureboot/secureboot.h>