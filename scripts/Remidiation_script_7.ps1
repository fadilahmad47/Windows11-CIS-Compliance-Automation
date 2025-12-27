# =========================================================
# CIS Windows 11 Enterprise – Full Remediation Script
# =========================================================

# ---------------- ADMIN CHECK ----------------
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit 1
}

# ---------------- HELPER FUNCTION ----------------
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
# REMOTE DESKTOP SERVICES – DEVICE & RESOURCE REDIRECTION
# =========================================================
$TS = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

Set-RegValue $TS "EnableUiaRedirection" 0
Set-RegValue $TS "fDisableCcm" 1
Set-RegValue $TS "fDisableCdm" 1
Set-RegValue $TS "fDisableLocationRedir" 1
Set-RegValue $TS "fDisableLPT" 1
Set-RegValue $TS "fDisablePNPRedir" 1
Set-RegValue $TS "fDisableWebAuthn" 1

# ---------------- RDS SECURITY ----------------
Set-RegValue $TS "fPromptForPassword" 1
Set-RegValue $TS "fEncryptRPCTraffic" 1
Set-RegValue $TS "SecurityLayer" 2

# ---------------- SESSION TIME LIMITS ----------------
Set-RegValue $TS "MaxIdleTime" 900000
Set-RegValue $TS "MaxDisconnectionTime" 60000

# =========================================================
# RSS FEEDS
# =========================================================
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" `
 "DisableEnclosureDownload" 1

# =========================================================
# CORTANA
# =========================================================
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
 "AllowCortana" 0

# =========================================================
# KMS / SOFTWARE PROTECTION PLATFORM
# =========================================================
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" `
 "NoGenTicket" 1

# =========================================================
# MICROSOFT STORE
# =========================================================
$Store = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"

Set-RegValue $Store "DisableStoreApps" 1
Set-RegValue $Store "RequirePrivateStoreOnly" 1
Set-RegValue $Store "DisableOSUpgrade" 1
Set-RegValue $Store "RemoveWindowsStore" 1

# =========================================================
# DEFENDER SMARTSCREEN – ENHANCED PHISHING PROTECTION
# =========================================================
$WTDS = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"

Set-RegValue $WTDS "CaptureThreatWindow" 1
Set-RegValue $WTDS "NotifyMalicious" 1
Set-RegValue $WTDS "NotifyPasswordReuse" 1
Set-RegValue $WTDS "NotifyUnsafeApp" 1
Set-RegValue $WTDS "ServiceEnabled" 1

# ---------------- SMARTSCREEN EXPLORER ----------------
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
 "EnableSmartScreen" 1

Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
 "ShellSmartScreenLevel" "Block" STRING

# =========================================================
# WINDOWS INK WORKSPACE
# =========================================================
$Ink = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"

Set-RegValue $Ink "AllowSuggestedAppsInWindowsInkWorkspace" 0
Set-RegValue $Ink "AllowWindowsInkWorkspace" 0

# =========================================================
# LOGON OPTIONS
# =========================================================
$SysPol = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

Set-RegValue $SysPol "EnableMPR" 0
Set-RegValue $SysPol "DisableAutomaticRestartSignOn" 1

# =========================================================
# POWERSHELL TRANSCRIPTION
# =========================================================
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
 "EnableTranscripting" 1

# =========================================================
# WINRM
# =========================================================
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
 "AllowDigest" 0

Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
 "DisableRunAs" 1

Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" `
 "AllowRemoteShellAccess" 0

# =========================================================
# WINDOWS SANDBOX
# =========================================================
$Sandbox = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox"

Set-RegValue $Sandbox "AllowClipboardRedirection" 0
Set-RegValue $Sandbox "AllowNetworking" 0

# =========================================================
# DEFENDER SECURITY CENTER – APP & BROWSER PROTECTION
# =========================================================
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" `
 "DisallowExploitProtectionOverride" 1

# =========================================================
# WINDOWS UPDATE
# =========================================================
$WU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

Set-RegValue $WU "SetDisablePauseUXAccess" 1
Set-RegValue $WU "DeferFeatureUpdates" 1
Set-RegValue $WU "DeferFeatureUpdatesPeriodInDays" 180

Write-Host "CIS remediation completed successfully." -ForegroundColor Green
