# ==============================
# CIS Windows 11 Remediation
# ==============================

# ---- Admin Check ----
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit 1
}

# ---- Helper Function ----
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
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    } else {
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null
    }
}

Write-Host "Applying CIS Windows 11 policies..." -ForegroundColor Cyan

# --------------------------------------------------
# ACCOUNT / LOGON POLICIES
# --------------------------------------------------

# Block Microsoft Accounts
Set-RegValue `
  -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "NoConnectedUser" `
  -Value 3

# Require CTRL+ALT+DEL
Set-RegValue `
  -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "DisableCAD" `
  -Value 0

# Do not display last signed-in user
Set-RegValue `
  -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "DontDisplayLastUserName" `
  -Value 1

# Machine inactivity limit (900 seconds)
Set-RegValue `
  -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "InactivityTimeoutSecs" `
  -Value 900

# --------------------------------------------------
# SMB / NETWORK SECURITY
# --------------------------------------------------

# SMB Server signing (always)
Set-RegValue `
  -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" `
  -Name "RequireSecuritySignature" `
  -Value 1

# SMB Server signing (if client agrees)
Set-RegValue `
  -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" `
  -Name "EnableSecuritySignature" `
  -Value 1

# Disable anonymous SAM enumeration
Set-RegValue `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "RestrictAnonymous" `
  -Value 1

# LAN Manager auth level – NTLMv2 only
Set-RegValue `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "LmCompatibilityLevel" `
  -Value 5

# --------------------------------------------------
# UAC HARDENING
# --------------------------------------------------

Set-RegValue `
  -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "FilterAdministratorToken" `
  -Value 1

Set-RegValue `
  -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "ConsentPromptBehaviorAdmin" `
  -Value 2

Set-RegValue `
  -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "EnableInstallerDetection" `
  -Value 1

# --------------------------------------------------
# FIREWALL LOGGING – DOMAIN
# --------------------------------------------------

$fwDomain = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"

Set-RegValue $fwDomain "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\domainfw.log" STRING
Set-RegValue $fwDomain "LogFileSize" 16384
Set-RegValue $fwDomain "LogDroppedPackets" 1

# --------------------------------------------------
# FIREWALL LOGGING – PRIVATE
# --------------------------------------------------

$fwPrivate = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"

Set-RegValue $fwPrivate "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\privatefw.log" STRING
Set-RegValue $fwPrivate "LogFileSize" 16384
Set-RegValue $fwPrivate "LogDroppedPackets" 1

# --------------------------------------------------
# FIREWALL – PUBLIC PROFILE
# --------------------------------------------------

$fwPublic = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"

Set-RegValue $fwPublic "DisableNotifications" 1
Set-RegValue $fwPublic "AllowLocalPolicyMerge" 0

# --------------------------------------------------
# CRYPTOGRAPHY
# --------------------------------------------------

Set-RegValue `
  -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" `
  -Name "EnableCertPaddingCheck" `
  -Value 1

# --------------------------------------------------
# AUTO LOGON DISABLE
# --------------------------------------------------

Set-RegValue `
  -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
  -Name "AutoAdminLogon" `
  -Value 0

# --------------------------------------------------
# FONT PROVIDERS
# --------------------------------------------------

Set-RegValue `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
  -Name "EnableFontProviders" `
  -Value 0

# --------------------------------------------------
# INSECURE GUEST SMB
# --------------------------------------------------

Set-RegValue `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
  -Name "AllowInsecureGuestAuth" `
  -Value 0

# --------------------------------------------------
# PEER-TO-PEER
# --------------------------------------------------

Set-RegValue `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" `
  -Name "Disabled" `
  -Value 1

# --------------------------------------------------
# HARDENED UNC PATHS
# --------------------------------------------------

$unc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"

Set-RegValue $unc "\\*\NETLOGON" "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1" STRING
Set-RegValue $unc "\\*\SYSVOL"   "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1" STRING

Write-Host "CIS remediation completed successfully." -ForegroundColor Green
