# =========================================================
# CIS Windows 11 Remediation – Single Script
# =========================================================

# ---------- ADMIN CHECK ----------
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "You MUST run this script as Administrator."
    exit 1
}

# ---------- REGISTRY HELPER ----------
function Set-RegValue {
    param (
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet("DWORD","STRING")][string]$Type = "DWORD"
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    if ($Type -eq "DWORD") {
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    } else {
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null
    }
}

Write-Host "Applying CIS Windows 11 policies..." -ForegroundColor Cyan

# =========================================================
# BITLOCKER – REMOVABLE DATA DRIVES
# =========================================================

$FVE = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

Set-RegValue $FVE "RDVRecoveryKey" 0
Set-RegValue $FVE "RDVHideRecoveryPage" 1
Set-RegValue $FVE "RDVActiveDirectoryBackup" 0
Set-RegValue $FVE "RDVActiveDirectoryInfoToStore" 1
Set-RegValue $FVE "RDVRequireActiveDirectoryBackup" 0
Set-RegValue $FVE "RDVHardwareEncryption" 0
Set-RegValue $FVE "RDVPassphrase" 0
Set-RegValue $FVE "RDVAllowUserCert" 1
Set-RegValue $FVE "RDVEnforceUserCert" 1
Set-RegValue $FVE "RDVDenyWriteAccess" 1
Set-RegValue $FVE "RDVDenyCrossOrg" 0
Set-RegValue $FVE "DisableExternalDMAUnderLock" 1

# =========================================================
# CAMERA / CLOUD / CONNECT / CREDENTIALS
# =========================================================

Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Camera" "AllowCamera" 0

$Cloud = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
Set-RegValue $Cloud "DisableConsumerAccountStateContent" 1
Set-RegValue $Cloud "DisableCloudOptimizedContent" 1

Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" "RequirePinForPairing" 1
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" "DisablePasswordReveal" 1
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "NoLocalPasswordResetQuestions" 1

# =========================================================
# DATA COLLECTION / INSIDER / APP INSTALLER
# =========================================================

$DC = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
Set-RegValue $DC "DisableEnterpriseAuthProxy" 1
Set-RegValue $DC "EnableOneSettingsAuditing" 1
Set-RegValue $DC "LimitDumpCollection" 1

Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" "AllowBuildPreview" 0

$AI = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
Set-RegValue $AI "EnableAppInstaller" 0
Set-RegValue $AI "EnableExperimentalFeatures" 0
Set-RegValue $AI "EnableHashOverride" 0
Set-RegValue $AI "EnableMSAppInstallerProtocol" 0

# =========================================================
# EVENT LOG SIZES
# =========================================================

Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "MaxSize" 32768
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "MaxSize" 196608
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "MaxSize" 32768
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "MaxSize" 32768

# =========================================================
# MICROSOFT DEFENDER – ASR + NETWORK PROTECTION
# =========================================================

$ASR = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
Set-RegValue $ASR "ExploitGuard_ASR_Rules" 1

$ASRRules = "$ASR\Rules"
$rules = @(
 "26190899-1602-49E8-8B27-EB1D0A1CE869",
 "3B576869-A4EC-4529-8536-B80A7769E899",
 "56A863A9-875E-4185-98A7-B882C64B5CE5",
 "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",
 "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",
 "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C",
 "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",
 "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",
 "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4",
 "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
 "D3E037E1-3EB8-44C8-A917-57927947596D",
 "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"
)

foreach ($r in $rules) {
    Set-RegValue $ASRRules $r 1
}

Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" `
 "EnableNetworkProtection" 1

Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "DisableRemovableDriveScanning" 0
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "DisableEmailScanning" 0
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "PUAProtection" 1

# =========================================================
# APPLICATION GUARD / RDP / PUSH TO INSTALL
# =========================================================

$AG = "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
Set-RegValue $AG "AuditApplicationGuard" 1
Set-RegValue $AG "AllowCameraMicrophoneRedirection" 0
Set-RegValue $AG "AllowPersistence" 0
Set-RegValue $AG "SaveFilesToHost" 0
Set-RegValue $AG "AppHVSIClipboardSettings" 1
Set-RegValue $AG "AllowAppHVSI_ProviderSet" 1

Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall" "DisablePushToInstall" 1
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" `
 "DisableCloudClipboardIntegration" 1
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
 "DisablePasswordSaving" 1

Write-Host "CIS remediation completed successfully." -ForegroundColor Green
