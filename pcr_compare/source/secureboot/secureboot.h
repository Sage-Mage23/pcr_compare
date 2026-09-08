#pragma once

namespace sagemage {
	namespace compare {
		namespace pcr {

			namespace tpm_api = sagemage::compare::tpm;
			//EFI_GLOBAL_VARIABLE_GUID
			static const GUID efi_global_variable_guid =
			{ 0x8BE4DF61 , 0x93CA , 0x11D2 , { 0xAA , 0x0D , 0x00 , 0xE0 , 0x98 , 0x03 , 0x2B , 0x8C } };

			constexpr ULONG m_system_secureboot_info = 0x91u;


			typedef enum _secure_boot_state {
				SecureBootUnknown = 0 ,
				SecureBootUnsupported ,
				SecureBootCapableDisabled ,
				SecureBootConfigured ,
				SecureBootEnabled ,
				SecureBootPcrMismatch
			} secure_boot_state_t;

#pragma pack(push, 1)
			struct system_secureboot_info_t {
				BOOLEAN m_secureboot_enabled;
				BOOLEAN m_secureboot_capable;
			};
#pragma pack(pop)

			struct secureboot_pcr_report_t {
				BOOLEAN m_efi_readable;
				BOOLEAN m_efi_enabled;
				BOOLEAN m_setup_mode;
				BOOLEAN m_sysinfo_readable;
				BOOLEAN m_sysinfo_enabled;
				BOOLEAN m_sysinfo_capable;
				BOOLEAN m_pcr7_valid;
				UCHAR m_pcr7_sha256 [ 32 ];
				BOOLEAN m_pcr7_all_zero;
				secure_boot_state_t m_state;
			};

			NTSTATUS read_efi_byte ( _In_ PCWSTR Name , _Out_ UCHAR* Value ) {
				UNICODE_STRING name;
				ULONG size = sizeof ( UCHAR );
				NTSTATUS status;

				if ( Value == nullptr )
					return STATUS_INVALID_PARAMETER;

				RtlInitUnicodeString ( &name , Name );
				*Value = 0;

				status = ExGetFirmwareEnvironmentVariable (
					&name ,
					const_cast< GUID* >( &efi_global_variable_guid ) ,
					Value ,
					&size ,
					nullptr
				);

				if ( !NT_SUCCESS ( status ) )
					return status;

				if ( size != sizeof ( UCHAR ) )
					return STATUS_DATA_ERROR;


				DbgPrint ( "[pcr_compare] SecureBoot EFI var read: name=%ws, value=%d\n" , Name , *Value );
				return STATUS_SUCCESS;
			}

			NTSTATUS read_secureboot_state_sysinfo ( _Out_ BOOLEAN* enabled , _Out_ BOOLEAN* capable ) {
				if ( enabled == nullptr || capable == nullptr )
					return STATUS_INVALID_PARAMETER;

				*enabled = FALSE;
				*capable = FALSE;

				system_secureboot_info_t info {};
				ULONG ret = 0;

				NTSTATUS status = ZwQuerySystemInformation (
					m_system_secureboot_info ,
					&info ,
					sizeof ( info ) ,
					&ret
				);

				if ( !NT_SUCCESS ( status ) )
					return status;

				*enabled = info.m_secureboot_enabled;
				*capable = info.m_secureboot_capable;

				DbgPrint ( "[pcr_compare] SecureBoot sysinfo read: enabled=%d, capable=%d\n" , *enabled , *capable );
				return STATUS_SUCCESS;
			}

			bool is_secure_boot_enabled_via_registry ( ) {
				UNICODE_STRING key_path;
				OBJECT_ATTRIBUTES oa;
				HANDLE key = nullptr;

				RtlInitUnicodeString (
					&key_path ,
					L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State"
				);
				InitializeObjectAttributes ( &oa , &key_path , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE , nullptr , nullptr );

				NTSTATUS status = ZwOpenKey ( &key , KEY_READ , &oa );
				if ( !NT_SUCCESS ( status ) )
					return false;

				UNICODE_STRING value_name;
				RtlInitUnicodeString ( &value_name , L"UEFISecureBootEnabled" );

				UCHAR buffer [ sizeof ( KEY_VALUE_PARTIAL_INFORMATION ) + sizeof ( ULONG ) ];
				ULONG result_length = 0;
				status = ZwQueryValueKey (
					key ,
					&value_name ,
					KeyValuePartialInformation ,
					buffer ,
					sizeof ( buffer ) ,
					&result_length
				);

				ZwClose ( key );

				if ( !NT_SUCCESS ( status ) )
					return false;

				auto* info = reinterpret_cast< KEY_VALUE_PARTIAL_INFORMATION* >( buffer );
				if ( info->Type != REG_DWORD || info->DataLength < sizeof ( ULONG ) )
					return false;

				ULONG value = 0;
				RtlCopyMemory ( &value , info->Data , sizeof ( ULONG ) );

				DbgPrint ( "[pcr_compare] SecureBoot registry read: value=%d\n" , value );

				return value != 0;
			}

			bool is_secure_boot_enabled_via_firmware ( ) {
				UCHAR value = 0;
				NTSTATUS status = read_efi_byte ( L"SecureBoot" , &value );
				DbgPrint ( "[pcr_compare] SecureBoot EFI var read: status=0x%08X, value=%d\n" , status , value );
				return NT_SUCCESS ( status ) && value == 1;
			}

			bool is_secure_boot_supported ( ) {
				UCHAR secure_boot_value = 0;
				UCHAR setup_mode_value = 0;

				if ( !NT_SUCCESS ( read_efi_byte ( L"SecureBoot" , &secure_boot_value ) ) )
					return false;

				if ( !NT_SUCCESS ( read_efi_byte ( L"SetupMode" , &setup_mode_value ) ) )
					return false;

				DbgPrint ( "[pcr_compare] SecureBoot EFI vars: SecureBoot=%d, SetupMode=%d\n" , secure_boot_value , setup_mode_value );

				// SetupMode == 1 means PK not enrolled (not a production Secure Boot config).
				UNREFERENCED_PARAMETER ( secure_boot_value );
				return setup_mode_value == 0;
			}

			// PCR7 path: Secure Boot policy is measured into PCR[7].
			// If firmware claims SecureBoot=1 but PCR7 is missing/all-zero, treat as mismatch
			// (spoofed EFI var or TPM not extended for SB policy).
			bool is_secure_boot_enabled_via_tpm ( _Out_opt_ UCHAR* pcr7_sha256 ) {
			

				if ( pcr7_sha256 != nullptr )
					RtlZeroMemory ( pcr7_sha256 , 32 );

				tpm_api::tpm_device_t device {};
				if ( !NT_SUCCESS ( tpm_api::open_device ( &device ) ) )
					return false;

				tpm_api::pcr_digest_t pcr7 {};
				NTSTATUS status = tpm_api::read_pcr_sha256 (
					device.handle ,
					tpm_api::m_tpm_pcr_secureboot_policy ,
					&pcr7
				);
				tpm_api::close_device ( &device );

				if ( !NT_SUCCESS ( status ) || !pcr7.valid )
					return false;

				if ( pcr7_sha256 != nullptr )
					RtlCopyMemory ( pcr7_sha256 , pcr7.sha256 , 32 );

				for ( ULONG i = 0; i < 32; ++i ) {
					if ( pcr7.sha256 [ i ] != 0 )
						return true; // non-zero PCR7 => policy was measured (SB path active)
				}

				return false;
			}

			NTSTATUS collect_secureboot_report ( _Out_ secureboot_pcr_report_t* report ) {
				if ( report == nullptr )
					return STATUS_INVALID_PARAMETER;

				RtlZeroMemory ( report , sizeof ( *report ) );
				report->m_state = SecureBootUnknown;

				UCHAR efi_sb = 0;
				UCHAR efi_setup = 0;
				if ( NT_SUCCESS ( read_efi_byte ( L"SecureBoot" , &efi_sb ) ) ) {
					report->m_efi_readable = TRUE;
					report->m_efi_enabled = ( efi_sb == 1 );
				}
				if ( NT_SUCCESS ( read_efi_byte ( L"SetupMode" , &efi_setup ) ) )
					report->m_setup_mode = ( efi_setup == 1 );

				BOOLEAN sys_en = FALSE , sys_cap = FALSE;
				if ( NT_SUCCESS ( read_secureboot_state_sysinfo ( &sys_en , &sys_cap ) ) ) {
					report->m_sysinfo_readable = TRUE;
					report->m_sysinfo_enabled = sys_en;
					report->m_sysinfo_capable = sys_cap;
				}

				// Always try PCR7  it is the hardware-backed Secure Boot measurement.
				tpm_api::tpm_device_t device {};
				if ( NT_SUCCESS ( tpm_api::open_device ( &device ) ) ) {
					tpm_api::pcr_digest_t dig {};
					if ( NT_SUCCESS ( tpm_api::read_pcr_sha256 (
						device.handle ,
						tpm_api::m_tpm_pcr_secureboot_policy ,
						&dig ) ) && dig.valid ) {
						report->m_pcr7_valid = TRUE;
						RtlCopyMemory ( report->m_pcr7_sha256 , dig.sha256 , 32 );
						report->m_pcr7_all_zero = TRUE;
						for ( ULONG i = 0; i < 32; ++i ) {
							if ( dig.sha256 [ i ] != 0 ) {
								report->m_pcr7_all_zero = FALSE;
								break;
							}
						}
					}
					tpm_api::close_device ( &device );
				}

				DbgPrint ( "[pcr_compare] SecureBoot report: EFI readable=%d, enabled=%d, setup_mode=%d, sysinfo readable=%d, enabled=%d, capable=%d, PCR7 valid=%d, all_zero=%d\n" ,
					report->m_efi_readable , report->m_efi_enabled , report->m_setup_mode ,
					report->m_sysinfo_readable , report->m_sysinfo_enabled , report->m_sysinfo_capable ,
						   report->m_pcr7_valid , report->m_pcr7_all_zero );

				const bool claims_enabled =
					report->m_efi_enabled ||
					report->m_sysinfo_enabled ||
					is_secure_boot_enabled_via_registry ( );

				if ( !report->m_efi_readable && !report->m_sysinfo_readable && !report->m_pcr7_valid ) {
					report->m_state = SecureBootUnsupported;
					DbgPrint ( "[pcr_compare] SecureBoot is unsupported: no EFI vars, no sysinfo, no PCR7\n" );
					return STATUS_SUCCESS;
				}

				if ( claims_enabled && report->m_pcr7_valid && report->m_pcr7_all_zero ) {
					report->m_state = SecureBootPcrMismatch;
					DbgPrint ( "[pcr_compare] SecureBoot is enabled but PCR7 is valid and all-zero, indicating a mismatch\n" );
					return STATUS_SUCCESS;
				}

				if ( claims_enabled && report->m_pcr7_valid && !report->m_pcr7_all_zero && !report->m_setup_mode ) {
					report->m_state = SecureBootEnabled;
					DbgPrint ( "[pcr_compare] SecureBoot is enabled and PCR7 is valid and non-zero\n" );
					return STATUS_SUCCESS;
				}

				if ( report->m_sysinfo_capable || report->m_efi_readable ) {
					report->m_state = claims_enabled ? SecureBootEnabled : SecureBootCapableDisabled;
					DbgPrint ( "[pcr_compare] SecureBoot is %s\n" , claims_enabled ? "enabled" : "capable but disabled" );
					return STATUS_SUCCESS;
				}

				DbgPrint ( "[pcr_compare] SecureBoot state could not be determined, defaulting to unknown\n" );

				report->m_state = SecureBootUnknown;
				return STATUS_SUCCESS;
			}


			NTSTATUS get_secure_boot_state ( secure_boot_state_t* state ) {
				if ( state == nullptr )
					return STATUS_INVALID_PARAMETER;

				secureboot_pcr_report_t report {};
				NTSTATUS status = collect_secureboot_report ( &report );
				if ( !NT_SUCCESS ( status ) ) {
					*state = SecureBootUnknown;
					DbgPrint ( "[pcr_compare] Failed to collect secure boot report: 0x%08X\n" , status );
					return status;
				}

				DbgPrint ( "[pcr_compare] SecureBoot state determined: %d\n" , report.m_state );

				*state = report.m_state;
				return STATUS_SUCCESS;
			}
		}
	}
}