# ===============================
# CIS Windows 11 Remediation
# Failed Policies Only
# ===============================

# ---- Safety check ----
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit 1
}

# ---- Helper functions ----
function Set-RegDWORD {
    param ($Path, $Name, $Value)
    New-Item -Path $Path -Force | Out-Null
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

function Set-RegString {
    param ($Path, $Name, $Value)
    New-Item -Path $Path -Force | Out-Null
    New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Value -Force | Out-Null
}

function Disable-ServiceSecure {
    param ($ServiceName)
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne "Stopped") {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        }
        Set-ItemProperty `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" `
            -Name Start -Value 4 -Type DWord
    }
}

# =====================================================
# 1. USER ACCOUNT CONTROL (UAC)
# =====================================================
$uacPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"

# 26064 – Admin Approval Mode for Built-in Administrator
Set-RegDWORD $uacPath "FilterAdministratorToken" 1

# 26065 – Prompt for consent on secure desktop (Admins)
Set-RegDWORD $uacPath "ConsentPromptBehaviorAdmin" 2

# 26066 – Automatically deny elevation requests (Standard users)
Set-RegDWORD $uacPath "ConsentPromptBehaviorUser" 0

# =====================================================
# 2. DISABLE HIGH-RISK / UNNEEDED SERVICES
# =====================================================
$servicesToDisable = @(
    "BTAGService",        # Bluetooth Audio Gateway
    "bthserv",            # Bluetooth Support
    "MapsBroker",         # Downloaded Maps
    "lfsvc",              # Geolocation
    "lltdsvc",            # LLTD Mapper
    "MSiSCSI",            # iSCSI Initiator
    "sshd",               # OpenSSH Server
    "Spooler",            # Print Spooler
    "wercplsupport",      # Problem Reports
    "RasAuto",            # Remote Access Auto
    "SessionEnv",         # RDP Configuration
    "TermService",        # RDP Services
    "UmRdpService",       # RDP Port Redirector
    "RpcLocator",         # RPC Locator
    "LanmanServer",       # Server
    "SSDPSRV",            # SSDP
    "upnphost",           # UPnP Host
    "WerSvc",             # Windows Error Reporting
    "Wecsvc",             # Windows Event Collector
    "WMPNetworkSvc",      # Media Player Sharing
    "icssvc",             # Mobile Hotspot
    "WpnService",         # Push Notifications
    "PushToInstall",      # Push To Install
    "WinRM",              # WinRM
    "XboxGipSvc",         # Xbox Accessory
    "XblAuthManager",     # Xbox Auth
    "XblGameSave",        # Xbox Game Save
    "XboxNetApiSvc"       # Xbox Networking
)

foreach ($svc in $servicesToDisable) {
    Disable-ServiceSecure $svc
}

# =====================================================
# 3. WINDOWS FIREWALL – DOMAIN PROFILE
# =====================================================
$fwDomain = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
$fwDomainLog = "$fwDomain\Logging"

Set-RegDWORD $fwDomain "DisableNotifications" 1
Set-RegString $fwDomainLog "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
Set-RegDWORD  $fwDomainLog "LogFileSize" 16384
Set-RegDWORD  $fwDomainLog "LogDroppedPackets" 1
Set-RegDWORD  $fwDomainLog "LogSuccessfulConnections" 1

# =====================================================
# 4. WINDOWS FIREWALL – PRIVATE PROFILE
# =====================================================
$fwPrivate = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$fwPrivateLog = "$fwPrivate\Logging"

Set-RegDWORD $fwPrivate "DisableNotifications" 1
Set-RegString $fwPrivateLog "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\privatefw.log"
Set-RegDWORD  $fwPrivateLog "LogFileSize" 16384
Set-RegDWORD  $fwPrivateLog "LogDroppedPackets" 1
Set-RegDWORD  $fwPrivateLog "LogSuccessfulConnections" 1

# =====================================================
# 5. WINDOWS FIREWALL – PUBLIC PROFILE
# =====================================================
$fwPublic = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"

Set-RegDWORD $fwPublic "DisableNotifications" 1
Set-RegDWORD $fwPublic "AllowLocalPolicyMerge" 0

# =====================================================
# FINAL
# =====================================================
Write-Host "CIS Windows 11 FAILED policies remediation completed successfully."
Write-Host "A reboot is recommended for all service and UAC changes to fully apply."
