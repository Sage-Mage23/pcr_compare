#include <impl/includes.h>

extern "C" NTSTATUS NTAPI DriverEntry ( PDRIVER_OBJECT DriverObject , PUNICODE_STRING RegistryPath ) {
	UNREFERENCED_PARAMETER ( DriverObject );
	UNREFERENCED_PARAMETER ( RegistryPath );

	DbgPrint ( "[pcr_compare] DriverEntry called\n" );

	sagemage::compare::pcr::secure_boot_state_t state = sagemage::compare::pcr::SecureBootUnknown;
	return sagemage::compare::pcr::get_secure_boot_state ( &state );
}