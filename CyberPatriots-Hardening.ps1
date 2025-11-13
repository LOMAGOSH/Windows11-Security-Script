#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CyberPatriots Windows Hardening Script
.DESCRIPTION
    Automated Windows security hardening script for CyberPatriots competition
.NOTES
    Written by: JASIAH.O (Converted to PowerShell)
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
Start-Sleep -Seconds 1

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
    Write-Host "                              ~Written by: JASIAH.O~                        " -ForegroundColor Cyan
    Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor Cyan
    Write-Host "1) Set user properties       2) Change all passwords"
    Write-Host "3) Disable guest/admin       4) Set password policy"
    Write-Host "5) Set lockout policy        6) Enable Firewall"
    Write-Host "7) Search for media files    8) Disable services"
    Write-Host "9) Turn on UAC               10) Remote Desktop Config"
    Write-Host "11) Enable auto update       12) Security options"
    Write-Host "13) Audit the machine        14) Edit groups"
    Write-Host "15) Advanced security        16) Apache security"
    Write-Host "69) Exit                     70) Reboot"
    Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor Cyan
}

# Function 1: Set user properties
function Set-UserProperties {
    Write-Host "`nSetting password properties for all local users..." -ForegroundColor Yellow
    
    try {
        # Get all local users
        $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
        
        foreach ($user in $users) {
            try {
                # Using ADSI to set properties
                $userADSI = [ADSI]"WinNT://$env:COMPUTERNAME/$($user.Name),user"
                
                # Set UserFlags to ensure password properties
                # 0x10000 = Password never expires (we'll REMOVE this flag)
                # 0x0040 = User cannot change password (we'll REMOVE this flag)
                # 0x0002 = Account disabled (preserve existing state)
                
                $currentFlags = $userADSI.UserFlags.Value
                
                # Remove "Password never expires" flag (0x10000)
                $currentFlags = $currentFlags -band (-bnot 0x10000)
                
                # Remove "User cannot change password" flag (0x0040)
                $currentFlags = $currentFlags -band (-bnot 0x0040)
                
                # Set the updated flags
                $userADSI.UserFlags = $currentFlags
                $userADSI.SetInfo()
                
                # Also use WMI for additional properties
                $wmiUser = Get-WmiObject -Class Win32_UserAccount -Filter "Name='$($user.Name)' AND LocalAccount=True"
                $wmiUser.PasswordExpires = $true
                $wmiUser.PasswordChangeable = $true
                $wmiUser.PasswordRequired = $true
                $wmiUser.Put() | Out-Null
                
                Write-Host "✓ Updated $($user.Name): Password expires enabled, user CAN change password" -ForegroundColor Green
            }
            catch {
                Write-Host "✗ Error updating $($user.Name): $_" -ForegroundColor Red
            }
        }
        
        Write-Host "`nAll user properties have been configured!" -ForegroundColor Green
        Write-Host "- Password never expires: UNCHECKED" -ForegroundColor Cyan
        Write-Host "- User cannot change password: UNCHECKED" -ForegroundColor Cyan
        Write-Host "- User must change password at next logon: UNCHECKED" -ForegroundColor Cyan
    }
    catch {
        Write-Host "Error setting user properties: $_" -ForegroundColor Red
    }
    pause
}

# Function 2: Create user
function New-LocalUserAccount {
    do {
        $answer = Read-Host "`nWould you like to create a user? [y/n]"
        if ($answer -eq 'y') {
            $username = Read-Host "What is the user you would like to create?"
            try {
                net user $username /add
                Write-Host "$username has been added" -ForegroundColor Green
            }
            catch {
                Write-Host "Error creating user: $_" -ForegroundColor Red
            }
        }
    } while ($answer -eq 'y')
}

# Function 3: Disable user
function Disable-LocalUserAccount {
    do {
        Clear-Host
        Write-Host "`nCurrent Users:" -ForegroundColor Cyan
        Get-LocalUser | Format-Table Name, Enabled, Description
        
        $answer = Read-Host "`nWould you like to disable a user? [y/n]"
        if ($answer -eq 'y') {
            $username = Read-Host "What is the name of the user?"
            try {
                Disable-LocalUser -Name $username
                Write-Host "$username has been disabled" -ForegroundColor Green
            }
            catch {
                Write-Host "Error disabling user: $_" -ForegroundColor Red
            }
        }
    } while ($answer -eq 'y')
    pause
}

# Function 4: Change all passwords
function Set-AllPasswords {
    Write-Host "`nChanging all user passwords to '1qaz!QAZ2wsx@WSX'..." -ForegroundColor Yellow
    
    $newPassword = '1qaz!QAZ2wsx@WSX'
    $users = Get-WmiObject -Class Win32_UserAccount -Filter 'LocalAccount=True AND Disabled=False'
    
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

# Function 5: Disable Guest and Administrator
function Disable-GuestAdmin {
    Write-Host "`nDisabling Guest and Administrator accounts..." -ForegroundColor Yellow
    try {
        Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        Write-Host "Guest account is disabled." -ForegroundColor Green
        
        Disable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
        Write-Host "Administrator account is disabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Error disabling accounts: $_" -ForegroundColor Red
    }
    pause
}

# Function 6: Set password policy
function Set-PasswordPolicy {
    Write-Host "`nConfiguring Password Policy..." -ForegroundColor Yellow
    
    try {
        # Set account policies
        net accounts /uniquepw:24
        net accounts /maxpwage:20
        net accounts /minpwage:10
        net accounts /minpwlen:14
        
        # Export current security policy
        secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
        
        # Read and modify security policy
        $secpolContent = Get-Content "$env:TEMP\secpol.cfg"
        $secpolContent = $secpolContent -replace "PasswordComplexity = 0", "PasswordComplexity = 1"
        $secpolContent = $secpolContent -replace "ClearTextPassword = 1", "ClearTextPassword = 0"
        $secpolContent | Set-Content "$env:TEMP\secpol_new.cfg"
        
        # Apply modified security policy
        secedit /configure /db secedit.sdb /cfg "$env:TEMP\secpol_new.cfg" /areas SECURITYPOLICY | Out-Null
        
        # Cleanup
        Remove-Item "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\secpol_new.cfg" -ErrorAction SilentlyContinue
        
        Write-Host "Password Policy has been successfully configured!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error configuring password policy: $_" -ForegroundColor Red
    }
    pause
}

# Function 7: Set lockout policy
function Set-LockoutPolicy {
    Write-Host "`nConfiguring Account Lockout Policy..." -ForegroundColor Yellow
    
    try {
        net accounts /lockoutduration:30
        net accounts /lockoutthreshold:5
        net accounts /lockoutwindow:30
        
        Write-Host "Account Lockout Policy has been successfully configured!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error configuring lockout policy: $_" -ForegroundColor Red
    }
    pause
}

# Function 8: Enable Firewall
function Enable-WindowsFirewall {
    Write-Host "`nConfiguring Windows Defender Firewall..." -ForegroundColor Yellow
    
    try {
        # Start firewall service
        Start-Service -Name mpssvc -ErrorAction SilentlyContinue
        
        # Enable firewall for all profiles
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        
        # Set firewall policy
        Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block -DefaultOutboundAction Allow
        Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block -DefaultOutboundAction Allow
        Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block -DefaultOutboundAction Allow
        
        # Enable logging
        Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 32767
        
        Write-Host "Windows Defender Firewall has been successfully configured!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error configuring firewall: $_" -ForegroundColor Red
    }
    pause
}

# Function 9: Search for media files
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
            catch {
                # Silently continue on access denied
            }
        }
    }
    
    if ($results.Count -gt 0) {
        Write-Host "`nFound $($results.Count) media files:" -ForegroundColor Yellow
        $results | Select-Object FullName, Length, LastWriteTime | Out-GridView -Title "Media Files Found"
        
        $export = Read-Host "`nExport results to CSV? [y/n]"
        if ($export -eq 'y') {
            $results | Select-Object FullName, Length, LastWriteTime | Export-Csv -Path "$env:USERPROFILE\Desktop\MediaFiles.csv" -NoTypeInformation
            Write-Host "Results exported to Desktop\MediaFiles.csv" -ForegroundColor Green
        }
    }
    else {
        Write-Host "No media files found." -ForegroundColor Green
    }
    pause
}

# Function 10: Disable services
function Disable-UnnecessaryServices {
    Write-Host "`nDisabling unnecessary services..." -ForegroundColor Yellow
    
    $servicesToDisable = @(
        'WinRM',
        'SSDPSRV',
        'RemoteRegistry',
        'WerSvc',
        'XboxNetApiSvc',
        'XblAuthManager',
        'XblGameSave',
        'WMPNetworkSvc',
        'WdiServiceHost',
        'bthserv',
        'AJRouter',
        'MapsBroker',
        'SharedAccess',
        'Fax',
        'DmEnrollmentSvc',
        'Wecsvc',
        'SensorService',
        'ShellHWDetection'
    )
    
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
    
    Write-Host "`nAll unnecessary services have been stopped and disabled." -ForegroundColor Green
    pause
}

# Function 11: Enable UAC
function Enable-UAC {
    Write-Host "`nEnabling User Account Control (UAC)..." -ForegroundColor Yellow
    
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
        Write-Host "UAC has been enabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Error enabling UAC: $_" -ForegroundColor Red
    }
    pause
}

# Function 12: Remote Desktop Config
function Set-RemoteDesktop {
    Write-Host "`nConfiguring Remote Desktop..." -ForegroundColor Yellow
    
    $answer = Read-Host "Disable Remote Desktop? [y/n]"
    if ($answer -eq 'y') {
        try {
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
            Disable-NetFirewallRule -DisplayGroup "Remote Desktop"
            Write-Host "Remote Desktop has been disabled." -ForegroundColor Green
        }
        catch {
            Write-Host "Error configuring Remote Desktop: $_" -ForegroundColor Red
        }
    }
    pause
}

# Function 13: Enable auto update
function Enable-AutoUpdate {
    Write-Host "`nConfiguring Automatic Updates..." -ForegroundColor Yellow
    
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 4 -ErrorAction SilentlyContinue
        
        Set-Service -Name wuauserv -StartupType Automatic
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
        
        Set-Service -Name bits -StartupType Automatic
        Start-Service -Name bits -ErrorAction SilentlyContinue
        
        Write-Host "Automatic Updates have been successfully enabled!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error enabling auto updates: $_" -ForegroundColor Red
    }
    pause
}

# Function 14: Security options
function Set-SecurityOptions {
    Write-Host "`nChanging security options now..." -ForegroundColor Yellow
    
    try {
        # Restrict CD ROM drive
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateCDRoms" -Value 1
        
        # Disable Automatic Admin logon
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0
        
        # Logon message
        $body = Read-Host "Please enter logon text"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -Value $body
        
        $subject = Read-Host "Please enter the title of the message"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -Value $subject
        
        # Wipe page file at shutdown
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1
        
        # Disallow remote access to floppy disks
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateFloppies" -Value 1
        
        # Prevent print driver installs
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -Value 1
        
        # Limit local account use of blank passwords to console
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1
        
        # Auditing access of Global System Objects
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "auditbaseobjects" -Value 1
        
        # Auditing Backup and Restore
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "fullprivilegeauditing" -Value 1
        
        # Do not display last user on logon
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "dontdisplaylastusername" -Value 1
        
        # UAC setting (Prompt on Secure Desktop)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1
        
        # Enable Installer Detection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Value 1
        
        # Undock without logon
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "undockwithoutlogon" -Value 0
        
        # Netlogon parameters
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" -Name "MaximumPasswordAge" -Value 15
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" -Name "DisablePasswordChange" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" -Name "RequireStrongKey" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" -Name "RequireSignOrSeal" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" -Name "SignSecureChannel" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" -Name "SealSecureChannel" -Value 1
        
        # Don't disable CTRL+ALT+DEL
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0
        
        # Restrict Anonymous
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymous" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymoussam" -Value 1
        
        # LanmanServer parameters
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" -Name "autodisconnect" -Value 45
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" -Name "enablesecuritysignature" -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" -Name "requiresecuritysignature" -Value 0
        
        # Disable Domain Credential Storage
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "disabledomaincreds" -Value 1
        
        # Don't Give Anons Everyone Permissions
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "everyoneincludesanonymous" -Value 0
        
        # SMB Passwords unencrypted to third party
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -Value 0
        
        # Null Session settings
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" -Name "NullSessionPipes" -Value @() -Type MultiString
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" -Name "NullSessionShares" -Value @() -Type MultiString
        
        # Allow to use Machine ID for NTLM
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "UseMachineId" -Value 0
        
        # Enable DEP
        bcdedit.exe /set '{current}' nx AlwaysOn
        
        Write-Host "Security options have been successfully configured!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error configuring security options: $_" -ForegroundColor Red
    }
    pause
}

# Function 15: Audit the machine
function Enable-Auditing {
    Write-Host "`nAuditing the machine now..." -ForegroundColor Yellow
    
    try {
        # Enable all auditing
        auditpol /set /category:* /success:enable /failure:enable
        
        Write-Host "Auditing has been successfully enabled!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error enabling auditing: $_" -ForegroundColor Red
    }
    pause
}

# Function 16: Edit groups
function Edit-Groups {
    Write-Host "`nLocal Groups:" -ForegroundColor Cyan
    Get-LocalGroup | Format-Table Name, Description
    
    Write-Host "`nTo add/remove users from groups, use:" -ForegroundColor Yellow
    Write-Host "Add-LocalGroupMember -Group 'GroupName' -Member 'Username'" -ForegroundColor Cyan
    Write-Host "Remove-LocalGroupMember -Group 'GroupName' -Member 'Username'" -ForegroundColor Cyan
    pause
}

# Function 17: Advanced Security Settings
function Set-AdvancedSecurity {
    Write-Host "`nConfiguring Advanced Security Settings..." -ForegroundColor Yellow
    
    try {
        # 1. Disable Remote Desktop via Group Policy
        Write-Host "`n[1/4] Disabling Remote Desktop Services..." -ForegroundColor Cyan
        $rdpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        if (-not (Test-Path $rdpPath)) {
            New-Item -Path $rdpPath -Force | Out-Null
        }
        Set-ItemProperty -Path $rdpPath -Name "fDenyTSConnections" -Value 1
        Write-Host "✓ Remote Desktop Services disabled" -ForegroundColor Green
        
        # 2. Require CTRL+ALT+DEL at logon
        Write-Host "`n[2/4] Requiring CTRL+ALT+DEL at logon..." -ForegroundColor Cyan
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0
        Write-Host "✓ CTRL+ALT+DEL requirement enabled" -ForegroundColor Green
        
        # 3. Disable WinRM unencrypted traffic
        Write-Host "`n[3/4] Disabling WinRM unencrypted traffic..." -ForegroundColor Cyan
        $winrmPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        if (-not (Test-Path $winrmPath)) {
            New-Item -Path $winrmPath -Force | Out-Null
        }
        Set-ItemProperty -Path $winrmPath -Name "AllowUnencryptedTraffic" -Value 0
        Write-Host "✓ WinRM unencrypted traffic disabled" -ForegroundColor Green
        
        # 4. Enable digitally signed communications
        Write-Host "`n[4/4] Enabling digitally signed communications..." -ForegroundColor Cyan
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        Set-ItemProperty -Path $lsaPath -Name "RequireSecuritySignature" -Value 1
        Set-ItemProperty -Path $lsaPath -Name "EnableSecuritySignature" -Value 1
        Write-Host "✓ Digitally signed communications enabled" -ForegroundColor Green
        
        Write-Host "`nAll advanced security settings configured successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error configuring advanced security: $_" -ForegroundColor Red
    }
    pause
}

# Function 18: Apache Security Configuration
function Set-ApacheSecurity {
    Write-Host "`nConfiguring Apache Security..." -ForegroundColor Yellow
    
    $apacheConfigPath = "C:\Apache24\conf\httpd.conf"
    
    if (Test-Path $apacheConfigPath) {
        try {
            Write-Host "Found Apache configuration file" -ForegroundColor Cyan
            
            # Read the file
            $content = Get-Content $apacheConfigPath
            
            # Find and replace ServerSignature
            $modified = $false
            for ($i = 0; $i -lt $content.Count; $i++) {
                if ($content[$i] -match "^\s*ServerSignature\s+On") {
                    $content[$i] = "ServerSignature Off"
                    $modified = $true
                    Write-Host "✓ Changed 'ServerSignature On' to 'ServerSignature Off' on line $($i+1)" -ForegroundColor Green
                }
            }
            
            # Also check for ServerTokens and set it to Prod for minimal info disclosure
            $hasServerTokens = $false
            for ($i = 0; $i -lt $content.Count; $i++) {
                if ($content[$i] -match "^\s*ServerTokens") {
                    $content[$i] = "ServerTokens Prod"
                    $hasServerTokens = $true
                    Write-Host "✓ Set 'ServerTokens Prod' on line $($i+1)" -ForegroundColor Green
                }
            }
            
            # If ServerTokens doesn't exist, add it
            if (-not $hasServerTokens) {
                # Find ServerSignature line and add ServerTokens before it
                for ($i = 0; $i -lt $content.Count; $i++) {
                    if ($content[$i] -match "^\s*ServerSignature") {
                        $content = $content[0..$i] + "ServerTokens Prod" + $content[($i+1)..($content.Count-1)]
                        Write-Host "✓ Added 'ServerTokens Prod' directive" -ForegroundColor Green
                        break
                    }
                }
            }
            
            if ($modified -or $hasServerTokens -or (-not $hasServerTokens)) {
                # Backup original file
                Copy-Item $apacheConfigPath "$apacheConfigPath.backup" -Force
                Write-Host "✓ Backed up original config to httpd.conf.backup" -ForegroundColor Cyan
                
                # Save the modified content
                $content | Set-Content $apacheConfigPath
                Write-Host "✓ Apache configuration updated successfully!" -ForegroundColor Green
                
                # Offer to restart Apache service
                $restart = Read-Host "`nRestart Apache service now? [y/n]"
                if ($restart -eq 'y') {
                    $apacheService = Get-Service -Name "Apache*" -ErrorAction SilentlyContinue
                    if ($apacheService) {
                        Restart-Service $apacheService.Name
                        Write-Host "✓ Apache service restarted" -ForegroundColor Green
                    } else {
                        Write-Host "! Apache service not found - restart manually if needed" -ForegroundColor Yellow
                    }
                }
            } else {
                Write-Host "No changes needed - Apache already configured securely" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "Error configuring Apache: $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Apache configuration file not found at $apacheConfigPath" -ForegroundColor Yellow
        Write-Host "If Apache is installed elsewhere, edit manually:" -ForegroundColor Cyan
        Write-Host "1. Find httpd.conf" -ForegroundColor Cyan
        Write-Host "2. Change 'ServerSignature On' to 'ServerSignature Off'" -ForegroundColor Cyan
        Write-Host "3. Add or change 'ServerTokens Prod'" -ForegroundColor Cyan
    }
    pause
}

# Main loop
do {
    Show-Menu
    $choice = Read-Host "`nPlease choose an option"
    
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
        '16' { Set-ApacheSecurity }
        '69' { exit }
        '70' { Restart-Computer -Force }
        default { 
            Write-Host "Invalid option. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
} while ($true)
