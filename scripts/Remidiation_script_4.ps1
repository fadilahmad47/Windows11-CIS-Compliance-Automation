# ============================================================
# CIS Windows 11 Enterprise – System & Components Remediation
# Compatible with Wazuh registry checks
# ============================================================

# ----------------------------
# Admin check
# ----------------------------
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit 1
}

# ----------------------------
# Helper functions
# ----------------------------
function Ensure-Key {
    param ($Path)
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

function Set-DWORD {
    param ($Path, $Name, $Value)
    Ensure-Key $Path
    New-ItemProperty -Path $Path -Name $Name -Value $Value `
        -PropertyType DWORD -Force | Out-Null
}

# ============================================================
# 18.9.20.1.14 – Turn off Windows Error Reporting
# ============================================================
Set-DWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" `
    "Disabled" 1

# ============================================================
# 18.9.23.1 – Kerberos device authentication (Automatic)
# ============================================================
$Kerb = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters"
Set-DWORD $Kerb "DevicePKInitEnabled" 1
Set-DWORD $Kerb "DevicePKInitBehavior" 0

# ============================================================
# 18.9.24.1 – Kernel DMA Protection (Block All)
# ============================================================
Set-DWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" `
    "DeviceEnumerationPolicy" 0

# ============================================================
# 18.9.25.x – Windows LAPS
# ============================================================
$LAPS = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"

Set-DWORD $LAPS "BackupDirectory" 1
Set-DWORD $LAPS "PwdExpirationProtectionEnabled" 1
Set-DWORD $LAPS "ADPasswordEncryptionEnabled" 1
Set-DWORD $LAPS "PasswordComplexity" 4
Set-DWORD $LAPS "PasswordLength" 15
Set-DWORD $LAPS "PasswordAgeDays" 30
Set-DWORD $LAPS "PostAuthenticationResetDelay" 8
Set-DWORD $LAPS "PostAuthenticationActions" 3

# ============================================================
# 18.9.26.x – LSASS protections
# ============================================================
Set-DWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
    "AllowCustomSSPsAPs" 0

Set-DWORD "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    "RunAsPPL" 1

# ============================================================
# 18.9.27.1 – Locale Services
# ============================================================
Set-DWORD "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" `
    "BlockUserInputMethodsForSignIn" 1

# ============================================================
# 18.9.28.x – Logon protections
# ============================================================
$SysPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"

Set-DWORD $SysPol "BlockUserFromShowingAccountDetailsOnSignin" 1
Set-DWORD $SysPol "DontDisplayNetworkSelectionUI" 1
Set-DWORD $SysPol "DontEnumerateConnectedUsers" 1
Set-DWORD $SysPol "DisableLockScreenAppNotifications" 1
Set-DWORD $SysPol "BlockDomainPicturePassword" 1

# ============================================================
# 18.9.33.6.x – Power / Sleep
# ============================================================
$ConnStandby = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
Set-DWORD $ConnStandby "DCSettingIndex" 0
Set-DWORD $ConnStandby "ACSettingIndex" 0

$SleepStates = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab"
Set-DWORD $SleepStates "DCSettingIndex" 0
Set-DWORD $SleepStates "ACSettingIndex" 0

# ============================================================
# 18.9.36.1 – RPC authentication
# ============================================================
Set-DWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
    "EnableAuthEpResolution" 1

# ============================================================
# 18.9.47.x – Diagnostics
# ============================================================
Set-DWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" `
    "DisableQueryRemoteServer" 0

Set-DWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" `
    "ScenarioExecutionEnabled" 0

# ============================================================
# 18.9.51.1.1 – Windows NTP Client
# ============================================================
Set-DWORD "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" `
    "Enabled" 1

# ============================================================
# 18.10.x – App & Store Controls
# ============================================================
Set-DWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" `
    "BlockNonAdminUserInstall" 1

Set-DWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" `
    "LetAppsActivateWithVoiceAboveLock" 2

Set-DWORD "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    "MSAOptional" 1

Set-DWORD "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    "BlockHostedAppAccessWinRT" 1

# ============================================================
# 18.10.7.x – AutoPlay / AutoRun
# ============================================================
Set-DWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
    "NoAutoplayfornonVolume" 1

Set-DWORD "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    "NoAutorun" 1

Set-DWORD "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    "NoDriveTypeAutoRun" 255

# ============================================================
# 18.10.8.1.1 – Biometrics anti-spoofing
# ============================================================
Set-DWORD "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" `
    "EnhancedAntiSpoofing" 1

# ============================================================
# 18.10.9.x – BitLocker (Fixed + OS Drives)
# ============================================================
$FVE = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

Set-DWORD $FVE "FDVRecovery" 1
Set-DWORD $FVE "FDVManageDRA" 1
Set-DWORD $FVE "FDVRecoveryPassword" 1
Set-DWORD $FVE "FDVRecoveryKey" 1
Set-DWORD $FVE "FDVHideRecoveryPage" 1
Set-DWORD $FVE "FDVActiveDirectoryBackup" 1
Set-DWORD $FVE "FDVActiveDirectoryInfoToStore" 1
Set-DWORD $FVE "FDVRequireActiveDirectoryBackup" 0
Set-DWORD $FVE "FDVHardwareEncryption" 0
Set-DWORD $FVE "FDVPassphrase" 0
Set-DWORD $FVE "FDVAllowUserCert" 1
Set-DWORD $FVE "FDVEnforceUserCert" 1
Set-DWORD $FVE "UseEnhancedPin" 1
Set-DWORD $FVE "OSAllowSecureBootForIntegrity" 1

Write-Host "CIS remediation completed successfully."
