# pcr_compare
Kernel Secure Boot / TPM PCR cross-check
Concept is reversed from FACEIT and VGK (Vanguard). Same idea as [page_walk](https://github.com/Sage-Mage23/page_walk): don’t trust the OS-visible story, go look at the hardware-backed one. I rewrote it as a standalone compare of “Windows says Secure Boot is on” vs what PCR[7] actually measured. 

Most of this was written by me; Cursor cleaned up the last build errors and some of the readme.
Looking for help or just want to chat? Dm me on discord: @deviceregion

pcr_compare is a read-only x64 kernel inspector: it reads the EFI SecureBoot / SetupMode variables, SystemSecureBootInformation, the UEFISecureBootEnabled registry value, and TPM2 PCR[7] SHA-256, then classifies whether those stories agree. In an anti-cheat kernel it answers “was Secure Boot policy actually measured?” rather than “does some firmware variable claim it was?”
What it does
Software claims are collected independently and OR’d into `claims_enabled`. None of them is treated as proof by itself.
EFI bytes come from `ExGetFirmwareEnvironmentVariable` against `EFI_GLOBAL_VARIABLE_GUID` (`8BE4DF61-93CA-11D2-AA0D-00E0-9803-2B8C`). `SecureBoot == 1` is the firmware claim. `SetupMode == 1` means no Platform Key is enrolled, so it is not a production Secure Boot config even if the SecureBoot variable exists.
`ZwQuerySystemInformation(0x91)` is `SystemSecureBootInformation`: a packed `{ BOOLEAN enabled; BOOLEAN capable; }`. That is the kernel’s cached view, not a TPM quote.
Registry is `\Registry\Machine\SYSTEM\CurrentControlSet\Control\SecureBoot\State` / `UEFISecureBootEnabled` (REG_DWORD). Same class of data as the EFI var, just persisted by the OS.
The TPM path opens `\Device\TPM`, falls back to `\Device\TCM`, and submits `TPM2_PCR_Read` with `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x200, METHOD_BUFFERED, FILE_ANY_ACCESS)` at PASSIVE_LEVEL. The command is TPM_ST_NO_SESSIONS + TPM_CC_PCR_Read, one SHA-256 selection, `sizeofSelect = 3`, bit set for PCR index. PCR[7] is the Secure Boot policy bank (PK / KEK / db / dbx). PCR[0] (CRTM / firmware) and PCR[14] (boot authority / CustomKernelSigners) are defined for later use. The response parser skips the 10-byte TPM2 header, `pcrUpdateCounter`, `TPML_PCR_SELECTION`, then copies the first SHA-256 digest. Success requires NTSTATUS success and a 32-byte digest. There is also a TPM2_ReadPublic builder / name parser aimed at the RSA-2048 EK (`0x81010001`); the Secure Boot report does not use it yet.
Leaves / states:
- no EFI, no sysinfo, no PCR7 → `SecureBootUnsupported`
- software claims enabled + PCR7 readable + all-zero → `SecureBootPcrMismatch` (spoofed EFI/reg or policy never extended)
- claims enabled + PCR7 non-zero + SetupMode == 0 → `SecureBootEnabled`
- sysinfo capable or EFI readable, but the PCR path didn’t settle → enabled vs `SecureBootCapableDisabled` from the software claim
- otherwise `SecureBootUnknown`
`SecureBootConfigured` exists in the enum and is unused. DriverEntry just builds the report and returns that NTSTATUS.
Why this shape matters for anti-cheat
A check that only reads the SecureBoot EFI variable, `SystemSecureBootInformation`, or `UEFISecureBootEnabled` assumes those values were produced by firmware policy. They are software-visible and can be made to agree with each other while the boot measurements never happened. PCR[7] is extended by firmware during measured boot. If Windows says Secure Boot is on and PCR[7] is missing or 32 zero bytes, that is the mismatch FACEIT / VGK style attestation is actually looking for: the OS claim and the TPM bank do not describe the same boot.
This still only sees what the Windows TPM driver will return. It is not a quote, not an EK-bound identity, and not a replay of the TCG event log. A hypervisor or a TPM that will answer `PCR_Read` with whatever you want can still lie. It does not attest the hypervisor.
Small improvements
- Don’t classify in DriverEntry. Queue a worker or expose an IOCTL so a service pulls `secureboot_pcr_report_t`; returning the compare status as the load status is a demo, not how you ship this.
- Fail closed when the TPM is absent. Right now EFI/sysinfo can still produce `SecureBootEnabled` with no PCR7. An AC backend that cares about attestation should treat “no TPM / no PCR7” as unsupported, not enabled.
- Split the software claims instead of OR’ing them. EFI vs sysinfo vs registry disagreeing is itself a signal; collapsing them hides which layer was spoofed.
- Use `SecureBootConfigured`. SetupMode == 0 + SecureBoot == 0 is “keys enrolled, SB off,” which is not the same as capable-disabled or unknown.
- Parse the TCG EFI event log, not just “PCR7 != 0”. A non-zero PCR7 only means something was extended. The EV_EFI_VARIABLE_AUTHORITY / db / dbx events are what tell you *what* was measured.
- Read PCR[0] and PCR[14] too. Firmware CRTM and boot-authority / CustomKernelSigners are the other banks FACEIT / VGK-style checks care about; PCR7 alone is the SB policy slice.
- Finish the EK ReadPublic path and quote it. A raw `PCR_Read` is local and replayable. Binding PCR[7] to the EK name (`0x81010001`) is the difference between “this machine’s TPM said X” and “some digest buffer said X.”
- Don’t treat TCM as a silent alias of TPM 2.0. The fallback open is fine; the command stream is TPM2-only.
- Hash / store the 32-byte PCR7 (and later PCR0/14) instead of only a boolean. The report already copies the digest; a backend wants the bytes, not `m_pcr7_all_zero`.
- Compare against a known-good quote or a previous boot’s digest. Absolute zero vs non-zero catches the dumb spoof. It does not catch “PCR7 is some other policy.”
