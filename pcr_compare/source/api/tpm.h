#pragma once
namespace sagemage {
	namespace compare {
		namespace tpm {
			constexpr ULONG m_tpm_st_no_sessions = 0x8001u; //m_tpm_st_no_sessions
			constexpr ULONG m_tpm_cc_pcr_read = 0x0000017Eu; //m_tpm_cc_pcr_read
			constexpr ULONG m_tpm_cc_read_public = 0x00000173u; //m_tpm_cc_read_public
			constexpr ULONG m_tpm_cc_get_capability = 0x0000017Au; //m_tpm_cc_get_capability

			constexpr USHORT m_tpm_alg_sha256 = 0x000Bu; //m_tpm_alg_sha256
			constexpr ULONG m_tpm_pcr_digest_size_sha256 = 32u; //m_tpm_pcr_digest_size_sha256
			
			constexpr ULONG m_tpm_pcr_firmware = 0u;           // CRTM / firmware m_tpm_pcr_firmware
			constexpr ULONG m_tpm_pcr_secureboot_policy = 7u;  // Secure Boot PK/KEK/db/dbx TPM_PCR_SECUREBOOT_POLICY
			constexpr ULONG m_tpm_pcr_boot_authority = 14u;    // boot authority / CustomKernelSigners TPM_PCR_BOOT_AUTHORITY

			constexpr ULONG m_tpm_ek_handle_rsa2048 = 0x81010001u; // TPM_EK_HANDLE_RSA2048

			constexpr ULONG m_submit_tpm_command =
				CTL_CODE ( FILE_DEVICE_UNKNOWN , 0x200 , METHOD_BUFFERED , FILE_ANY_ACCESS );

			struct pcr_digest_t {
				BOOLEAN valid;
				UCHAR sha256 [ m_tpm_pcr_digest_size_sha256 ];
			};

			struct tpm_device_t {
				HANDLE handle;
				BOOLEAN open;
			};

			static inline void put_be16 ( UCHAR*& p , USHORT v ) {
				*p++ = ( UCHAR ) ( ( v >> 8 ) & 0xFFu );
				*p++ = ( UCHAR ) ( v & 0xFFu );
			}

			static inline void put_be32 ( UCHAR*& p , ULONG v ) {
				*p++ = ( UCHAR ) ( ( v >> 24 ) & 0xFFu );
				*p++ = ( UCHAR ) ( ( v >> 16 ) & 0xFFu );
				*p++ = ( UCHAR ) ( ( v >> 8 ) & 0xFFu );
				*p++ = ( UCHAR ) ( v & 0xFFu );
			}

			static inline USHORT peek_be16 ( const UCHAR* p ) {
				return ( USHORT ) ( ( ( ULONG ) p [ 0 ] << 8 ) | ( ULONG ) p [ 1 ] );
			}

			static inline ULONG peek_be32 ( const UCHAR* p ) {
				return ( ( ULONG ) p [ 0 ] << 24 ) |
					( ( ULONG ) p [ 1 ] << 16 ) |
					( ( ULONG ) p [ 2 ] << 8 ) |
					( ULONG ) p [ 3 ];
			}

			NTSTATUS open_device ( _Out_ tpm_device_t* device ) {
				if ( device == nullptr )
					return STATUS_INVALID_PARAMETER;

				RtlZeroMemory ( device , sizeof ( *device ) );

				UNICODE_STRING path;
				OBJECT_ATTRIBUTES oa;
				IO_STATUS_BLOCK iosb;

				RtlInitUnicodeString ( &path , L"\\Device\\TPM" );
				InitializeObjectAttributes ( &oa , &path , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE , nullptr , nullptr );

				NTSTATUS status = ZwCreateFile (
					&device->handle ,
					GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE ,
					&oa ,
					&iosb ,
					nullptr ,
					FILE_ATTRIBUTE_NORMAL ,
					0 ,
					FILE_OPEN ,
					FILE_SYNCHRONOUS_IO_NONALERT ,
					nullptr ,
					0
				);

				if ( !NT_SUCCESS ( status ) ) {
					RtlInitUnicodeString ( &path , L"\\Device\\TCM" );
					InitializeObjectAttributes ( &oa , &path , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE , nullptr , nullptr );
					status = ZwCreateFile (
						&device->handle ,
						GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE ,
						&oa ,
						&iosb ,
						nullptr ,
						FILE_ATTRIBUTE_NORMAL ,
						0 ,
						FILE_OPEN ,
						FILE_SYNCHRONOUS_IO_NONALERT ,
						nullptr ,
						0
					);
				}

				if ( NT_SUCCESS ( status ) )
					device->open = TRUE;

				return status;
			}

			void close_device ( _Inout_ tpm_device_t* device ) {
				if ( device == nullptr )
					return;

				if ( device->open && device->handle != nullptr ) {
					ZwClose ( device->handle );
					device->handle = nullptr;
					device->open = FALSE;
				}
			}

			bool is_present ( ) {
				tpm_device_t device {};
				NTSTATUS status = open_device ( &device );
				if ( !NT_SUCCESS ( status ) )
					return false;

				close_device ( &device );
				return true;
			}

			NTSTATUS submit_command (
				_In_ HANDLE device ,
				_In_reads_bytes_ ( cmd_len ) const UCHAR* cmd ,
				_In_ ULONG cmd_len ,
				_Out_writes_bytes_to_ ( rsp_cap , *rsp_used ) UCHAR* rsp ,
				_In_ ULONG rsp_cap ,
				_Out_ ULONG* rsp_used
			) {
				if ( device == nullptr || cmd == nullptr || rsp == nullptr || rsp_used == nullptr )
					return STATUS_INVALID_PARAMETER;

				if ( KeGetCurrentIrql ( ) != PASSIVE_LEVEL )
					return STATUS_INVALID_LEVEL;

				*rsp_used = 0;

				IO_STATUS_BLOCK iosb {};
				NTSTATUS status = ZwDeviceIoControlFile (
					device ,
					nullptr ,
					nullptr ,
					nullptr ,
					&iosb ,
					m_submit_tpm_command ,
					( PVOID ) cmd ,
					cmd_len ,
					rsp ,
					rsp_cap
				);

				if ( NT_SUCCESS ( status ) )
					*rsp_used = ( ULONG ) iosb.Information;

				return status;
			}

			// Build TPM2_PCR_Read for a single SHA-256 PCR index.
			NTSTATUS build_pcr_read ( ULONG pcr_index , UCHAR* cmd_out , ULONG* cmd_len ) {
				if ( cmd_out == nullptr || cmd_len == nullptr || pcr_index >= 24 )
					return STATUS_INVALID_PARAMETER;

				if ( *cmd_len < 20u ) {
					*cmd_len = 20u;
					return STATUS_BUFFER_TOO_SMALL;
				}

				UCHAR* p = cmd_out;
				put_be16 ( p , ( USHORT ) m_tpm_st_no_sessions );
				put_be32 ( p , 20u );
				put_be32 ( p , m_tpm_cc_pcr_read );

				put_be32 ( p , 1u );                         // TPML_PCR_SELECTION.count
				put_be16 ( p , m_tpm_alg_sha256 );
				*p++ = 3;                                   // sizeofSelect

				UCHAR select [ 3 ] = { 0 , 0 , 0 };
				select [ pcr_index / 8 ] = ( UCHAR ) ( 1u << ( pcr_index % 8 ) );
				*p++ = select [ 0 ];
				*p++ = select [ 1 ];
				*p++ = select [ 2 ];

				*cmd_len = 20u;
				return STATUS_SUCCESS;
			}

			NTSTATUS parse_pcr_read_digest (
				_In_reads_bytes_ ( rsp_len ) const UCHAR* rsp ,
				_In_ ULONG rsp_len ,
				_Out_writes_bytes_ ( m_tpm_pcr_digest_size_sha256 ) UCHAR* digest
			) {
				if ( rsp == nullptr || digest == nullptr || rsp_len < 10 )
					return STATUS_INVALID_PARAMETER;

				RtlZeroMemory ( digest , m_tpm_pcr_digest_size_sha256 );

				const UCHAR* p = rsp + 10; // skip TPM2 header
				ULONG remaining = rsp_len - 10;

				if ( remaining < 4 )
					return STATUS_DATA_ERROR;

				p += 4; // pcrUpdateCounter
				remaining -= 4;

				if ( remaining < 4 )
					return STATUS_DATA_ERROR;

				ULONG sel_count = peek_be32 ( p );
				p += 4;
				remaining -= 4;

				for ( ULONG i = 0; i < sel_count; ++i ) {
					if ( remaining < 6 )
						return STATUS_DATA_ERROR;
					p += 6; // hash(2) + sizeofSelect(1) + select(3)
					remaining -= 6;
				}

				if ( remaining < 4 )
					return STATUS_DATA_ERROR;

				ULONG dig_count = peek_be32 ( p );
				p += 4;
				remaining -= 4;

				if ( dig_count == 0 || remaining < 2 )
					return STATUS_NOT_FOUND;

				USHORT dig_size = peek_be16 ( p );
				p += 2;
				remaining -= 2;

				if ( dig_size != m_tpm_pcr_digest_size_sha256 || remaining < ( ULONG ) dig_size )
					return STATUS_DATA_ERROR;

				RtlCopyMemory ( digest , p , m_tpm_pcr_digest_size_sha256 );
				return STATUS_SUCCESS;
			}

			NTSTATUS read_pcr_sha256 ( _In_ HANDLE device , ULONG pcr_index , _Out_ pcr_digest_t* out ) {
				if ( out == nullptr )
					return STATUS_INVALID_PARAMETER;

				RtlZeroMemory ( out , sizeof ( *out ) );

				UCHAR cmd [ 32 ];
				ULONG cmd_len = sizeof ( cmd );
				NTSTATUS status = build_pcr_read ( pcr_index , cmd , &cmd_len );
				if ( !NT_SUCCESS ( status ) )
					return status;

				UCHAR rsp [ 256 ];
				ULONG rsp_used = 0;
				status = submit_command ( device , cmd , cmd_len , rsp , sizeof ( rsp ) , &rsp_used );
				if ( !NT_SUCCESS ( status ) )
					return status;

				status = parse_pcr_read_digest ( rsp , rsp_used , out->sha256 );
				if ( NT_SUCCESS ( status ) )
					out->valid = TRUE;

				return status;
			}

			NTSTATUS build_read_public ( ULONG handle , UCHAR* cmd_out , ULONG* cmd_len ) {
				if ( cmd_out == nullptr || cmd_len == nullptr )
					return STATUS_INVALID_PARAMETER;

				if ( *cmd_len < 14u ) {
					*cmd_len = 14u;
					return STATUS_BUFFER_TOO_SMALL;
				}

				UCHAR* p = cmd_out;
				put_be16 ( p , ( USHORT ) m_tpm_st_no_sessions );
				put_be32 ( p , 14u );
				put_be32 ( p , m_tpm_cc_read_public );
				put_be32 ( p , handle );
				*cmd_len = 14u;
				return STATUS_SUCCESS;
			}

			// Extract TPM2B_NAME from a ReadPublic response (stable EK identity name).
			NTSTATUS parse_read_public_name (
				_In_reads_bytes_ ( rsp_len ) const UCHAR* rsp ,
				_In_ ULONG rsp_len ,
				_Out_writes_bytes_to_ ( name_cap , *name_len ) UCHAR* name ,
				_In_ ULONG name_cap ,
				_Out_ ULONG* name_len
			) {
				if ( rsp == nullptr || name == nullptr || name_len == nullptr || rsp_len < 12 )
					return STATUS_INVALID_PARAMETER;

				*name_len = 0;
				const UCHAR* p = rsp + 10;
				ULONG remaining = rsp_len - 10;

				USHORT public_size = peek_be16 ( p );
				p += 2;
				remaining -= 2;

				if ( remaining < ( ULONG ) public_size + 2u )
					return STATUS_DATA_ERROR;

				p += public_size;
				remaining -= public_size;

				USHORT nsize = peek_be16 ( p );
				p += 2;
				remaining -= 2;

				if ( nsize == 0 || remaining < ( ULONG ) nsize || ( ULONG ) nsize > name_cap )
					return STATUS_BUFFER_TOO_SMALL;

				RtlCopyMemory ( name , p , nsize );
				*name_len = nsize;
				return STATUS_SUCCESS;
			}
		}
	}
}