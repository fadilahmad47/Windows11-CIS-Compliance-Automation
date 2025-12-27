# ===============================
# Windows 11 CIS Remediation Script
# ===============================

# --- Admin Check ---
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit 1
}

# --- Helper Function ---
function Set-RegDWORD {
    param (
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWORD -Force | Out-Null
}

function Set-RegString {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null
}

# ===============================
# Windows Connect Now
# ===============================
$WCN = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
Set-RegDWORD $WCN "EnableRegistrars" 0
Set-RegDWORD $WCN "DisableFlashConfigRegistrar" 0
Set-RegDWORD $WCN "DisableInBand802DOT11Registrar" 0
Set-RegDWORD $WCN "DisableUPnPRegistrar" 0
Set-RegDWORD $WCN "DisableWPDRegistrar" 0

Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" "DisableWcnUi" 1

# ===============================
# Windows Connection Manager
# ===============================
$WCM = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
Set-RegDWORD $WCM "fMinimizeConnections" 3
Set-RegDWORD $WCM "fBlockNonDomain" 1

# ===============================
# WLAN Wi-Fi Sense
# ===============================
Set-RegDWORD "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" 0

# ===============================
# Printers / Print Spooler Hardening
# ===============================
$Printers = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
Set-RegDWORD $Printers "RegisterSpoolerRemoteRpcEndPoint" 2
Set-RegDWORD $Printers "DisableWebPnPDownload" 1
Set-RegDWORD $Printers "DisableHTTPPrinting" 1
Set-RegDWORD $Printers "CopyFilesPolicy" 1
Set-RegDWORD $Printers "RedirectionguardPolicy" 1

$RPC = "$Printers\RPC"
Set-RegDWORD $RPC "RpcUseNamedPipeProtocol" 0
Set-RegDWORD $RPC "RpcAuthentication" 0
Set-RegDWORD $RPC "RpcProtocols" 5
Set-RegDWORD $RPC "RpcTcpPort" 0
Set-RegDWORD $RPC "ForceKerberosForRpc" 1

$PnP = "$Printers\PointAndPrint"
Set-RegDWORD $PnP "RestrictDriverInstallationToAdministrators" 1
Set-RegDWORD $PnP "UpdatePromptSettings" 0

# ===============================
# Notifications
# ===============================
Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoCloudApplicationNotification" 1

# ===============================
# Start Menu
# ===============================
Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "HideRecommendedPersonalizedSites" 1

# ===============================
# Audit Process Creation
# ===============================
Set-RegDWORD "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" 1

# ===============================
# CredSSP / Credential Delegation
# ===============================
Set-RegDWORD "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle" 0
Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds" 1

# ===============================
# Device Guard / VBS / Credential Guard
# ===============================
$DG = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
Set-RegDWORD $DG "EnableVirtualizationBasedSecurity" 1
Set-RegDWORD $DG "RequirePlatformSecurityFeatures" 3
Set-RegDWORD $DG "HypervisorEnforcedCodeIntegrity" 1
Set-RegDWORD $DG "HVCIMATRequired" 1
Set-RegDWORD $DG "LsaCfgFlags" 1
Set-RegDWORD $DG "ConfigureKernelShadowStacksLaunch" 1

# ===============================
# ===============================
# Device Installation Restrictions (CIS 18.9.7.x)
# ===============================

$Base = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"

# Enable policy
Set-RegDWORD $Base "DenyDeviceIDs" 1
Set-RegDWORD $Base "DenyDeviceIDsRetroactive" 1
Set-RegDWORD $Base "DenyDeviceClasses" 1
Set-RegDWORD $Base "DenyDeviceClassesRetroactive" 1

# Create DenyDeviceIDs list
$DenyIDs = "$Base\DenyDeviceIDs"
if (-not (Test-Path $DenyIDs)) {
    New-Item -Path $DenyIDs -Force | Out-Null
}

# Thunderbolt controller hardware ID
Set-RegString $DenyIDs "1" "PCI\CC_0C0A"


# ===============================
# Device Metadata
# ===============================
Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" "PreventDeviceMetadataFromNetwork" 1

# ===============================
# Early Launch Antimalware
# ===============================
Set-RegDWORD "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy" 3

# ===============================
# Group Policy Processing
# ===============================
Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoBackgroundPolicy" 0
Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoGPOListChanges" 0

Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" "NoBackgroundPolicy" 0
Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" "NoGPOListChanges" 0

# ===============================
# Cross Device Experience
# ===============================
Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableCdp" 0

# ===============================
# Internet Communication Management
# ===============================
Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoUseStoreOpenWith" 1
Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" "ExitOnMSICW" 1
Set-RegDWORD "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoWebServices" 1
Set-RegDWORD "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoOnlinePrintsWizard" 1
Set-RegDWORD "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoPublishingWizard" 1
Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" "NoRegistration" 1
Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" "DisableContentFileUpdates" 1
Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" "CEIP" 2
Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" "CEIPEnable" 0

Write-Host "CIS remediation completed. Reboot recommended."
