# ==========================================================
# CIS Windows 11 Enterprise – Security Remediation Script
# Covers Firewall, Audit Policy, MSS, Network, Privacy
# ==========================================================

# --- Ensure script is running as Administrator ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

Write-Host "Applying CIS Windows 11 remediation..." -ForegroundColor Cyan

# ----------------------------------------------------------
# FIREWALL – Public Profile
# ----------------------------------------------------------
$fwPub = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
$fwLog = "$fwPub\Logging"

New-Item -Path $fwPub -Force | Out-Null
Set-ItemProperty $fwPub AllowLocalIPsecPolicyMerge 0 -Type DWord

New-Item -Path $fwLog -Force | Out-Null
Set-ItemProperty $fwLog LogFilePath "%SystemRoot%\System32\logfiles\firewall\publicfw.log" -Type ExpandString
Set-ItemProperty $fwLog LogFileSize 16384 -Type DWord
Set-ItemProperty $fwLog LogDroppedPackets 1 -Type DWord
Set-ItemProperty $fwLog LogSuccessfulConnections 1 -Type DWord

# ----------------------------------------------------------
# ADVANCED AUDIT POLICY
# ----------------------------------------------------------
$auditSettings = @(
    @{C="Credential Validation"; S="Success,Failure"},
    @{C="Application Group Management"; S="Success,Failure"},
    @{C="User Account Management"; S="Success,Failure"},
    @{C="Plug and Play Events"; S="Success"},
    @{C="Process Creation"; S="Success"},
    @{C="Account Lockout"; S="Failure"},
    @{C="Group Membership"; S="Success"},
    @{C="Other Logon/Logoff Events"; S="Success,Failure"},
    @{C="Detailed File Share"; S="Failure"},
    @{C="File Share"; S="Success,Failure"},
    @{C="Other Object Access Events"; S="Success,Failure"},
    @{C="Removable Storage"; S="Success,Failure"},
    @{C="Authorization Policy Change"; S="Success"},
    @{C="MPSSVC Rule-Level Policy Change"; S="Success,Failure"},
    @{C="Other Policy Change Events"; S="Failure"},
    @{C="Sensitive Privilege Use"; S="Success,Failure"},
    @{C="IPsec Driver"; S="Success,Failure"},
    @{C="Security System Extension"; S="Success"}
)

foreach ($a in $auditSettings) {
    auditpol /set /subcategory:"$($a.C)" /success:enable /failure:enable 2>$null
}

# ----------------------------------------------------------
# PERSONALIZATION / PRIVACY
# ----------------------------------------------------------
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
 NoLockScreenSlideshow 1 -Type DWord

Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
 AllowOnlineTips 0 -Type DWord

# ----------------------------------------------------------
# MS SECURITY GUIDE / MSS (LEGACY)
# ----------------------------------------------------------
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" `
 EnableCertPaddingCheck 1 -Type DWord

Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
 DisableExceptionChainValidation 0 -Type DWord

Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" `
 NodeType 2 -Type DWord

Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
 DisableIPSourceRouting 2 -Type DWord

Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
 DisableIPSourceRouting 2 -Type DWord

Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" `
 DisableSavePassword 1 -Type DWord

Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
 EnableICMPRedirect 0 -Type DWord

Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
 KeepAliveTime 300000 -Type DWord

Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
 PerformRouterDiscovery 0 -Type DWord

Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" `
 TcpMaxDataRetransmissions 3 -Type DWord

Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
 TcpMaxDataRetransmissions 3 -Type DWord

# ----------------------------------------------------------
# DNS / NETWORK HARDENING
# ----------------------------------------------------------
$dns = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
New-Item $dns -Force | Out-Null
Set-ItemProperty $dns DoHPolicy 2 -Type DWord
Set-ItemProperty $dns EnableMulticast 0 -Type DWord

Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" `
 DisabledComponents 255 -Type DWord

# ----------------------------------------------------------
# SMB / UNC HARDENING
# ----------------------------------------------------------
$hardened = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
New-Item $hardened -Force | Out-Null

New-ItemProperty $hardened "\\*\NETLOGON" `
 -Value "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1" `
 -PropertyType String -Force

New-ItemProperty $hardened "\\*\SYSVOL" `
 -Value "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1" `
 -PropertyType String -Force

# ----------------------------------------------------------
# NETWORK UI RESTRICTIONS
# ----------------------------------------------------------
$netConn = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
New-Item $netConn -Force | Out-Null

Set-ItemProperty $netConn NC_AllowNetBridge_NLA 0 -Type DWord
Set-ItemProperty $netConn NC_ShowSharedAccessUI 0 -Type DWord
Set-ItemProperty $netConn NC_StdDomainUserSetLocation 1 -Type DWord

# ----------------------------------------------------------
# PEER-TO-PEER
# ----------------------------------------------------------
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" `
 Disabled 1 -Type DWord

Write-Host "Remediation completed. REBOOT REQUIRED." -ForegroundColor Green
