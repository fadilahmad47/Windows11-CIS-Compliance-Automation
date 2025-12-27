# ============================
# Helper: Safe Registry Setter
# ============================
function Set-RegValue {
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        $Value,

        [ValidateSet("DWORD","STRING")]
        [string]$Type = "DWORD"
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    if ($Type -eq "DWORD") {
        New-ItemProperty -Path $Path -Name $Name -Value ([int]$Value) -PropertyType DWORD -Force | Out-Null
    } else {
        New-ItemProperty -Path $Path -Name $Name -Value ([string]$Value) -PropertyType String -Force | Out-Null
    }
}

# ============================
# 1. Interactive Logon Lockout
# CIS 2.3.7.3
# ============================
Set-RegValue `
"HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
"MaxDevicePasswordFailedAttempts" 10

# ============================
# 2. Kerberos Encryption Types
# CIS 2.3.11.4
# ============================
Set-RegValue `
"HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
"SupportedEncryptionTypes" 2147483644

# ============================
# 3. Hardened UNC Paths
# CIS 18.6.14.1
# ============================
$Hardened = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"

Set-RegValue $Hardened "\\*\NETLOGON" `
"RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1" STRING

Set-RegValue $Hardened "\\*\SYSVOL" `
"RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1" STRING

# ============================
# 4. Thunderbolt / DMA Protection
# CIS 18.9.7.1.2
# ============================
$Deny = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$List = "$Deny\DenyDeviceIDs"

Set-RegValue $Deny "DenyDeviceIDs" 1
if (-not (Test-Path $List)) { New-Item -Path $List -Force | Out-Null }
Set-RegValue $List "1" "PCI\CC_0C0A" STRING

# ============================
# BitLocker Base Path
# ============================
$FVE = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

# ============================
# 5. Fixed Data Drives (FAT)
# CIS 18.10.9.1.1
# ============================
Set-RegValue $FVE "FDVDiscoveryVolumeType" 0

# ============================
# 6. OS Drive Recovery
# CIS 18.10.9.2.x
# ============================
Set-RegValue $FVE "OSRecovery" 1
Set-RegValue $FVE "OSManageDRA" 0
Set-RegValue $FVE "OSRecoveryPassword" 1
Set-RegValue $FVE "OSRecoveryKey" 0
Set-RegValue $FVE "OSHideRecoveryPage" 1
Set-RegValue $FVE "OSActiveDirectoryBackup" 1
Set-RegValue $FVE "OSActiveDirectoryInfoToStore" 1
Set-RegValue $FVE "OSRequireActiveDirectoryBackup" 1
Set-RegValue $FVE "OSHardwareEncryption" 0
Set-RegValue $FVE "OSPassphrase" 0

# ============================
# 7. Startup Authentication
# CIS 18.10.9.2.13–18
# ============================
Set-RegValue $FVE "UseAdvancedStartup" 1
Set-RegValue $FVE "EnableBDEWithNoTPM" 0
Set-RegValue $FVE "UseTPM" 0
Set-RegValue $FVE "UseTPMPIN" 1
Set-RegValue $FVE "UseTPMKey" 0
Set-RegValue $FVE "UseTPMKeyPIN" 0

# ============================
# 8. Removable Data Drives
# CIS 18.10.9.3.x
# ============================
Set-RegValue $FVE "RDVDiscoveryVolumeType" 0
Set-RegValue $FVE "RDVRecovery" 1
Set-RegValue $FVE "RDVManageDRA" 1
Set-RegValue $FVE "RDVRecoveryPassword" 0

# ============================
# 9. File Explorer Insights
# CIS 18.10.28.2
# ============================
Set-RegValue `
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
"DisableGraphRecentItems" 1

# ============================
# 10. Block Microsoft Accounts
# CIS 18.10.41.1
# ============================
Set-RegValue `
"HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" `
"DisableUserAuth" 1

# ============================
# 11. Defender File Hash
# CIS 18.10.42.7.1
# ============================
Set-RegValue `
"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" `
"EnableFileHashComputation" 1

# ============================
# 12. Disable Watson Events
# CIS 18.10.42.12.1
# ============================
Set-RegValue `
"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" `
"DisableGenericRePorts" 1

# ============================
# 13. Disable News & Interests
# CIS 18.10.49.1
# ============================
Set-RegValue `
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" `
"EnableFeeds" 0

Write-Host "CIS/Wazuh remediation applied successfully."
Write-Host "Run gpupdate /force and reboot to complete."
