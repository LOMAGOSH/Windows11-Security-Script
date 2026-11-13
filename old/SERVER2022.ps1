#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CyberPatriots Windows Hardening Script
.DESCRIPTION
    Automated Windows security hardening script for CyberPatriots competition
    Compatible with Windows 10/11 and Windows Server 2016/2019/2022
.NOTES
    Written by: JASIAH.O (Enhanced for Server 2022)
    Requires: Administrator privileges
#>

# Check for admin rights
function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-AdminRights)) {
    Write-Host "Failure, no admin rights" -ForegroundColor Red
    pause
    exit
}

Write-Host "Admin rights granted!" -ForegroundColor Green

# Detect OS version
$osInfo = Get-CimInstance Win32_OperatingSystem
$osName = $osInfo.Caption
$isServer = $osName -match "Server"
$osVersion = [System.Environment]::OSVersion.Version

Write-Host "Detected OS: $osName" -ForegroundColor Cyan
Write-Host "OS Version: $($osVersion.Major).$($osVersion.Minor) Build $($osVersion.Build)" -ForegroundColor Cyan
if ($isServer) {
    Write-Host "Server environment detected - server-specific options enabled" -ForegroundColor Yellow
}
Start-Sleep -Seconds 2

# Initial prompt
Clear-Host
$answer = Read-Host "Have you answered all the forensics questions? [y/n]"
if ($answer -ne 'y') {
    Write-Host "Please go and answer them." -ForegroundColor Yellow
    pause
    exit
}

# Main menu function
function Show-Menu {
    Clear-Host
    Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor Cyan
    Write-Host "   #####   ##   ##  #######  ###    ##  ####### " -ForegroundColor Cyan
    Write-Host "  ##       ##   ##  ##       ####   ##     ##   " -ForegroundColor Cyan
    Write-Host "  ##  ###  #######  #####    ## ##  ##     ##   " -ForegroundColor Cyan
    Write-Host "  ##   ##  ##   ##  ##       ##  ## ##     ##   " -ForegroundColor Cyan
    Write-Host "   #####   ##   ##  #######  ##   ####     ##   " -ForegroundColor Cyan
    Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor Cyan
    Write-Host "                    ~Written by: JASIAH.O (Server 2022 Ready)~              " -ForegroundColor Cyan
    Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor Cyan
    Write-Host "1) Set user properties       2) Change all passwords"
    Write-Host "3) Disable guest/admin       4) Set password policy"
    Write-Host "5) Set lockout policy        6) Enable Firewall"
    Write-Host "7) Search for media files    8) Disable services"
    Write-Host "9) Turn on UAC               10) Remote Desktop Config"
    Write-Host "11) Enable auto update       12) Security options"
    Write-Host "13) Audit the machine        14) Edit groups"
    Write-Host "15) Advanced security        16) Apache/IIS security"
    if ($isServer) {
        Write-Host "17) Server Manager Config    18) SMB Security" -ForegroundColor Yellow
    }
    Write-Host "69) Exit                     70) Reboot"
    Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor Cyan
}

# Function 1: Set user properties
function Set-UserProperties {
    Write-Host "`nSetting password properties for all local users..." -ForegroundColor Yellow
    
    try {
        $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
        
        foreach ($user in $users) {
            try {
                $userADSI = [ADSI]"WinNT://$env:COMPUTERNAME/$($user.Name),user"
                $currentFlags = $userADSI.UserFlags.Value
                
                # Remove "Password never expires" (0x10000)
                $currentFlags = $currentFlags -band (-bnot 0x10000)
                # Remove "User cannot change password" (0x0040)
                $currentFlags = $currentFlags -band (-bnot 0x0040)
                
                $userADSI.UserFlags = $currentFlags
                $userADSI.SetInfo()
                
                Write-Host "Updated $($user.Name): Password expires enabled, user CAN change password" -ForegroundColor Green
            }
            catch {
                Write-Host "Error updating $($user.Name): $_" -ForegroundColor Red
            }
        }
        
        Write-Host "`nAll user properties configured!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error setting user properties: $_" -ForegroundColor Red
    }
    pause
}

# Function 2: Change all passwords
function Set-AllPasswords {
    Write-Host "`nChanging all user passwords to '1qaz!QAZ2wsx@WSX'..." -ForegroundColor Yellow
    
    $newPassword = '1qaz!QAZ2wsx@WSX'
    $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    
    foreach ($user in $users) {
        try {
            $username = $user.Name
            ([ADSI]"WinNT://$env:COMPUTERNAME/$username,user").SetPassword($newPassword)
            Write-Host "Password for $username has been changed successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to change password for $username." -ForegroundColor Red
        }
    }
    pause
}

# Function 3: Disable Guest and Administrator
function Disable-GuestAdmin {
    Write-Host "`nDisabling Guest and Administrator accounts..." -ForegroundColor Yellow
    try {
        Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        Write-Host "Guest account disabled." -ForegroundColor Green
        
        Disable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
        Write-Host "Administrator account disabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Error disabling accounts: $_" -ForegroundColor Red
    }
    pause
}

# Function 4: Set password policy
function Set-PasswordPolicy {
    Write-Host "`nConfiguring Password Policy..." -ForegroundColor Yellow
    
    try {
        net accounts /uniquepw:24 2>&1 | Out-Null
        net accounts /maxpwage:20 2>&1 | Out-Null
        net accounts /minpwage:10 2>&1 | Out-Null
        net accounts /minpwlen:14 2>&1 | Out-Null
        
        $secpolPath = "$env:TEMP\secpol.cfg"
        $secpolNewPath = "$env:TEMP\secpol_new.cfg"
        
        secedit /export /cfg $secpolPath /quiet
        
        if (Test-Path $secpolPath) {
            $secpolContent = Get-Content $secpolPath
            $secpolContent = $secpolContent -replace "PasswordComplexity = 0", "PasswordComplexity = 1"
            $secpolContent = $secpolContent -replace "ClearTextPassword = 1", "ClearTextPassword = 0"
            $secpolContent | Set-Content $secpolNewPath
            
            secedit /configure /db secedit.sdb /cfg $secpolNewPath /areas SECURITYPOLICY /quiet
            
            Remove-Item $secpolPath -ErrorAction SilentlyContinue
            Remove-Item $secpolNewPath -ErrorAction SilentlyContinue
        }
        
        Write-Host "Password Policy configured successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error configuring password policy: $_" -ForegroundColor Red
    }
    pause
}

# Function 5: Set lockout policy
function Set-LockoutPolicy {
    Write-Host "`nConfiguring Account Lockout Policy..." -ForegroundColor Yellow
    
    try {
        net accounts /lockoutduration:30 2>&1 | Out-Null
        net accounts /lockoutthreshold:5 2>&1 | Out-Null
        net accounts /lockoutwindow:30 2>&1 | Out-Null
        
        Write-Host "Account Lockout Policy configured successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error configuring lockout policy: $_" -ForegroundColor Red
    }
    pause
}

# Function 6: Enable Firewall
function Enable-WindowsFirewall {
    Write-Host "`nConfiguring Windows Defender Firewall..." -ForegroundColor Yellow
    
    try {
        Set-Service -Name mpssvc -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name mpssvc -ErrorAction SilentlyContinue
        
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
        Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 32767
        
        Write-Host "Windows Defender Firewall configured successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error configuring firewall: $_" -ForegroundColor Red
    }
    pause
}

# Function 7: Search for media files
function Search-MediaFiles {
    Write-Host "`nSearching for media files..." -ForegroundColor Yellow
    Write-Host "This may take a few minutes..." -ForegroundColor Cyan
    
    $extensions = @('*.mp3', '*.mp4', '*.avi', '*.mkv', '*.mov', '*.wmv', '*.flv', '*.wav', '*.flac', '*.aac', '*.jpg', '*.jpeg', '*.png', '*.gif', '*.bmp')
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' }
    
    $results = @()
    foreach ($drive in $drives) {
        Write-Host "Scanning drive: $($drive.Root)" -ForegroundColor Cyan
        foreach ($ext in $extensions) {
            try {
                $files = Get-ChildItem -Path $drive.Root -Recurse -Filter $ext -ErrorAction SilentlyContinue
                $results += $files
            }
            catch { }
        }
    }
    
    if ($results.Count -gt 0) {
        Write-Host "`nFound $($results.Count) media files" -ForegroundColor Yellow
        
        $export = Read-Host "`nExport results to CSV? [y/n]"
        if ($export -eq 'y') {
            $desktopPath = [Environment]::GetFolderPath("Desktop")
            if (-not $desktopPath) { $desktopPath = "$env:USERPROFILE\Desktop" }
            $results | Select-Object FullName, Length, LastWriteTime | Export-Csv -Path "$desktopPath\MediaFiles.csv" -NoTypeInformation
            Write-Host "Results exported to Desktop\MediaFiles.csv" -ForegroundColor Green
        }
    }
    else {
        Write-Host "No media files found." -ForegroundColor Green
    }
    pause
}

# Function 8: Disable services
function Disable-UnnecessaryServices {
    Write-Host "`nDisabling unnecessary services..." -ForegroundColor Yellow
    
    $servicesToDisable = @(
        'RemoteRegistry',
        'WerSvc',
        'WMPNetworkSvc',
        'bthserv',
        'MapsBroker',
        'Fax'
    )
    
    # Add client-specific services if not a server
    if (-not $isServer) {
        $servicesToDisable += @('XboxNetApiSvc', 'XblAuthManager', 'XblGameSave')
    }
    
    foreach ($service in $servicesToDisable) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Host "Disabled: $service" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "Could not disable: $service" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`nUnnecessary services disabled." -ForegroundColor Green
    pause
}

# Function 9: Enable UAC
function Enable-UAC {
    Write-Host "`nEnabling User Account Control (UAC)..." -ForegroundColor Yellow
    
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
        Write-Host "UAC enabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Error enabling UAC: $_" -ForegroundColor Red
    }
    pause
}

# Function 10: Remote Desktop Config
function Set-RemoteDesktop {
    Write-Host "`nConfiguring Remote Desktop..." -ForegroundColor Yellow
    
    $answer = Read-Host "Disable Remote Desktop? [y/n]"
    if ($answer -eq 'y') {
        try {
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
            Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
            Write-Host "Remote Desktop disabled." -ForegroundColor Green
        }
        catch {
            Write-Host "Error configuring Remote Desktop: $_" -ForegroundColor Red
        }
    }
    pause
}

# Function 11: Enable auto update
function Enable-AutoUpdate {
    Write-Host "`nConfiguring Automatic Updates..." -ForegroundColor Yellow
    
    try {
        # Server 2022 uses the same update mechanism as Win10/11
        Set-Service -Name wuauserv -StartupType Automatic
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
        
        Set-Service -Name bits -StartupType Automatic
        Start-Service -Name bits -ErrorAction SilentlyContinue
        
        # Configure update settings via registry
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (-not (Test-Path $wuPath)) {
            New-Item -Path $wuPath -Force | Out-Null
        }
        Set-ItemProperty -Path $wuPath -Name "NoAutoUpdate" -Value 0 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $wuPath -Name "AUOptions" -Value 4 -ErrorAction SilentlyContinue
        
        Write-Host "Automatic Updates enabled successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error enabling auto updates: $_" -ForegroundColor Red
    }
    pause
}

# Function 12: Security options
function Set-SecurityOptions {
    Write-Host "`nConfiguring security options..." -ForegroundColor Yellow
    
    try {
        $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        if (-not (Test-Path $winlogonPath)) {
            New-Item -Path $winlogonPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $winlogonPath -Name "AllocateCDRoms" -Value 1 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon" -Value 0 -ErrorAction SilentlyContinue
        
        $body = Read-Host "Enter logon message text"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -Value $body
        
        $subject = Read-Host "Enter logon message title"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -Value $subject
        
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1
        Set-ItemProperty -Path $winlogonPath -Name "AllocateFloppies" -Value 1 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "auditbaseobjects" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "fullprivilegeauditing" -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "dontdisplaylastusername" -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "undockwithoutlogon" -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymous" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymoussam" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" -Name "autodisconnect" -Value 45
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "disabledomaincreds" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "everyoneincludesanonymous" -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "UseMachineId" -Value 0
        
        bcdedit.exe /set '{current}' nx AlwaysOn | Out-Null
        
        Write-Host "Security options configured successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error configuring security options: $_" -ForegroundColor Red
    }
    pause
}

# Function 13: Audit the machine
function Enable-Auditing {
    Write-Host "`nEnabling auditing..." -ForegroundColor Yellow
    
    try {
        auditpol /set /category:* /success:enable /failure:enable
        Write-Host "Auditing enabled successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error enabling auditing: $_" -ForegroundColor Red
    }
    pause
}

# Function 14: Edit groups
function Edit-Groups {
    Write-Host "`nLocal Groups:" -ForegroundColor Cyan
    Get-LocalGroup | Format-Table Name, Description
    
    Write-Host "`nManage groups using:" -ForegroundColor Yellow
    Write-Host "Add-LocalGroupMember -Group 'GroupName' -Member 'Username'" -ForegroundColor Cyan
    Write-Host "Remove-LocalGroupMember -Group 'GroupName' -Member 'Username'" -ForegroundColor Cyan
    pause
}

# Function 15: Advanced Security
function Set-AdvancedSecurity {
    Write-Host "`nConfiguring Advanced Security..." -ForegroundColor Yellow
    
    try {
        Write-Host "`n[1/4] Configuring Remote Desktop..." -ForegroundColor Cyan
        $rdpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        if (-not (Test-Path $rdpPath)) {
            New-Item -Path $rdpPath -Force | Out-Null
        }
        Set-ItemProperty -Path $rdpPath -Name "fDenyTSConnections" -Value 1
        Write-Host "Remote Desktop hardened" -ForegroundColor Green
        
        Write-Host "`n[2/4] Configuring logon security..." -ForegroundColor Cyan
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0
        Write-Host "CTRL+ALT+DEL required" -ForegroundColor Green
        
        Write-Host "`n[3/4] Configuring WinRM..." -ForegroundColor Cyan
        $winrmPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        if (-not (Test-Path $winrmPath)) {
            New-Item -Path $winrmPath -Force | Out-Null
        }
        Set-ItemProperty -Path $winrmPath -Name "AllowUnencryptedTraffic" -Value 0
        Write-Host "WinRM unencrypted traffic disabled" -ForegroundColor Green
        
        Write-Host "`n[4/4] Enabling signed communications..." -ForegroundColor Cyan
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        Set-ItemProperty -Path $lsaPath -Name "RequireSecuritySignature" -Value 1
        Set-ItemProperty -Path $lsaPath -Name "EnableSecuritySignature" -Value 1
        Write-Host "Digitally signed communications enabled" -ForegroundColor Green
        
        Write-Host "`nAdvanced security configured!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }
    pause
}

# Function 16: Apache/IIS Security
function Set-WebServerSecurity {
    Write-Host "`nConfiguring Web Server Security..." -ForegroundColor Yellow
    
    $apacheConfigPath = "C:\Apache24\conf\httpd.conf"
    
    # Check IIS using Server 2022 compatible method
    $iisInstalled = $false
    if ($isServer) {
        $iisFeature = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
        $iisInstalled = $iisFeature -and $iisFeature.Installed
    } else {
        $iisInstalled = (Get-Service -Name W3SVC -ErrorAction SilentlyContinue) -ne $null
    }
    
    if (Test-Path $apacheConfigPath) {
        Write-Host "`nApache detected - Configuring..." -ForegroundColor Cyan
        try {
            $content = Get-Content $apacheConfigPath
            
            for ($i = 0; $i -lt $content.Count; $i++) {
                if ($content[$i] -match "^\s*ServerSignature\s+On") {
                    $content[$i] = "ServerSignature Off"
                    Write-Host "Set ServerSignature Off" -ForegroundColor Green
                }
                if ($content[$i] -match "^\s*ServerTokens\s+") {
                    $content[$i] = "ServerTokens Prod"
                    Write-Host "Set ServerTokens Prod" -ForegroundColor Green
                }
            }
            
            Copy-Item $apacheConfigPath "$apacheConfigPath.backup" -Force
            $content | Set-Content $apacheConfigPath
            Write-Host "Apache configuration updated!" -ForegroundColor Green
        }
        catch {
            Write-Host "Error configuring Apache: $_" -ForegroundColor Red
        }
    }
    elseif ($iisInstalled) {
        Write-Host "`nIIS detected - Configuring..." -ForegroundColor Cyan
        try {
            Import-Module WebAdministration -ErrorAction Stop
            
            Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/requestFiltering" -Name "removeServerHeader" -Value $true
            Write-Host "Removed IIS version header" -ForegroundColor Green
            
            Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/directoryBrowse" -Name "enabled" -Value $false
            Write-Host "Disabled directory browsing" -ForegroundColor Green
            
            Clear-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']" -ErrorAction SilentlyContinue
            Write-Host "Removed X-Powered-By header" -ForegroundColor Green
            
            Write-Host "IIS security configured!" -ForegroundColor Green
        }
        catch {
            Write-Host "Error configuring IIS: $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "No web server detected" -ForegroundColor Yellow
    }
    pause
}

# Function 17: Server Manager Config
function Set-ServerManagerConfig {
    Write-Host "`nConfiguring Server Manager..." -ForegroundColor Yellow
    
    if (-not $isServer) {
        Write-Host "Only available on Windows Server" -ForegroundColor Red
        pause
        return
    }
    
    try {
        Write-Host "Disabling Server Manager auto-start..." -ForegroundColor Cyan
        Get-ScheduledTask -TaskName ServerManager -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue
        Write-Host "Server Manager auto-start disabled" -ForegroundColor Green
        
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            Write-Host "`nConfiguring Windows Defender..." -ForegroundColor Cyan
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
            Write-Host "Windows Defender enabled" -ForegroundColor Green
        }
        
        Write-Host "`nDisabling unnecessary features..." -ForegroundColor Cyan
        $featuresToDisable = @('FS-SMB1', 'PowerShell-V2')
        
        foreach ($feature in $featuresToDisable) {
            $feat = Get-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
            if ($feat -and $feat.Installed) {
                Uninstall-WindowsFeature -Name $feature -ErrorAction SilentlyContinue | Out-Null
                Write-Host "Disabled: $feature" -ForegroundColor Green
            }
        }
        
        Write-Host "`nServer Manager configured!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }
    pause
}

# Function 18: SMB Security
function Set-SMBSecurity {
    Write-Host "`nConfiguring SMB Security..." -ForegroundColor Yellow
    
    try {
        Write-Host "`n[1/5] Disabling SMBv1..." -ForegroundColor Cyan
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
        
        if ($isServer) {
            Uninstall-WindowsFeature -Name FS-SMB1 -ErrorAction SilentlyContinue | Out-Null
        } else {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
        }
        Write-Host "SMBv1 disabled" -ForegroundColor Green
        
        Write-Host "`n[2/5] Enabling SMB encryption..." -ForegroundColor Cyan
        Set-SmbServerConfiguration -EncryptData $true -Force -ErrorAction SilentlyContinue
        Write-Host "SMB encryption enabled" -ForegroundColor Green
        
        Write-Host "`n[3/5] Enabling SMB signing..." -ForegroundColor Cyan
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
        Write-Host "SMB signing enabled" -ForegroundColor Green
        
        Write-Host "`n[4/5] Disabling anonymous access..." -ForegroundColor Cyan
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1
        Write-Host "Anonymous SMB access disabled" -ForegroundColor Green
        
        Write-Host "`n[5/5] Setting idle timeout..." -ForegroundColor Cyan
        Set-SmbServerConfiguration -AutoDisconnectTimeout 15 -Force -ErrorAction SilentlyContinue
        Write-Host "SMB idle timeout set" -ForegroundColor Green
        
        Write-Host "`nSMB security configured!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }
    pause
}

# Main loop
do {
    Show-Menu
    $choice = Read-Host "`nChoose an option"
    
    switch ($choice) {
        '1'  { Set-UserProperties }
        '2'  { Set-AllPasswords }
        '3'  { Disable-GuestAdmin }
        '4'  { Set-PasswordPolicy }
        '5'  { Set-LockoutPolicy }
        '6'  { Enable-WindowsFirewall }
        '7'  { Search-MediaFiles }
        '8'  { Disable-UnnecessaryServices }
        '9'  { Enable-UAC }
        '10' { Set-RemoteDesktop }
        '11' { Enable-AutoUpdate }
        '12' { Set-SecurityOptions }
        '13' { Enable-Auditing }
        '14' { Edit-Groups }
        '15' { Set-AdvancedSecurity }
        '16' { Set-WebServerSecurity }
        '17' { 
            if ($isServer) { 
                Set-ServerManagerConfig 
            } else { 
                Write-Host "Only available on Windows Server" -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
        '18' { 
            if ($isServer) { 
                Set-SMBSecurity 
            } else { 
                Write-Host "Only available on Windows Server" -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
        '69' { exit }
        '70' { Restart-Computer -Force }
        default { 
            Write-Host "Invalid option" -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
} while ($true)
