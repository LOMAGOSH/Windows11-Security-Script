<#
.SYNOPSIS
    CyberPatriot Windows 11 Hardening Toolkit (CIS Level 1 aligned)
.DESCRIPTION
    Merged and rewritten version of the original menu scripts.
    - Self-elevates and always runs under Windows PowerShell 5.1 (works on Windows 11)
    - CIS Microsoft Windows 11 Benchmark (Level 1) aligned settings
    - Force-install Windows Updates, Defender signatures, winget apps and Microsoft Store apps
    - Interactive user/group manager, recon helpers, Apache hardening, "run everything" mode
.NOTES
    Original author: JASIAH.O
    Run:  powershell.exe -ExecutionPolicy Bypass -File .\CyberPatriot-Win11-Hardening.ps1
    ALWAYS read the competition README first. Hardening can break required services.
#>

#Requires -Version 5.1

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Error 'This toolkit requires Windows. No changes were made.'
    exit 1
}

# =====================================================================
# SETTINGS - edit these to match the README / your preferences
# =====================================================================
$DefaultNewPassword = '1qaz!QAZ2wsx@WSX'   # used only if you press Enter at the password prompt
$PwHistory     = 24
$PwMaxAge      = 60     # CIS: 365 or fewer, not 0. CyberPatriot usually wants 30-90
$PwMinAge      = 1      # CIS: 1 or more
$PwMinLen      = 14
$LockThreshold = 5      # CIS: 5 or fewer, not 0
$LockDuration  = 30     # CIS: 15 or more
$LockWindow    = 30     # CIS: 15 or more (must be <= duration)

# =====================================================================
# Self-elevation + force Windows PowerShell 5.1
# =====================================================================
function Test-AdminRights {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-Popup {
    param(
        [string]$Text,
        [string]$Title = 'CyberPatriot Hardening',
        [string]$Buttons = 'OK',
        [string]$Icon = 'Warning'
    )
    try {
        Add-Type -AssemblyName System.Windows.Forms
        return [System.Windows.Forms.MessageBox]::Show($Text, $Title,
            [System.Windows.Forms.MessageBoxButtons]::$Buttons,
            [System.Windows.Forms.MessageBoxIcon]::$Icon)
    }
    catch {
        Write-Host $Text -ForegroundColor Yellow
        return 'Yes'
    }
}

if (-not $PSCommandPath) {
    Show-Popup -Text "Save this script as a .ps1 file and run it from there." -Title 'Cannot run' -Icon 'Error' | Out-Null
    exit 1
}

# Request elevation directly through Windows UAC. Never bypass consent.
$windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $windowsPowerShell = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
}
$launchArguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath
if (-not (Test-AdminRights)) {
    try {
        Start-Process -FilePath $windowsPowerShell -ArgumentList $launchArguments -WorkingDirectory (Split-Path -Parent $PSCommandPath) -Verb RunAs -ErrorAction Stop | Out-Null
    }
    catch {
        Show-Popup -Title 'Administrator required' -Icon 'Error' -Text 'The administrator request was cancelled or failed. No hardening actions were performed.' | Out-Null
        exit 1
    }
    exit 0
}
if ($PSVersionTable.PSEdition -eq 'Core' -or -not [Environment]::Is64BitProcess) {
    try {
        $child = Start-Process -FilePath $windowsPowerShell -ArgumentList $launchArguments -WorkingDirectory (Split-Path -Parent $PSCommandPath) -Wait -PassThru -ErrorAction Stop
        exit $child.ExitCode
    }
    catch {
        Show-Popup -Title 'Launch failed' -Icon 'Error' -Text 'Could not start Windows PowerShell. No hardening actions were performed.' | Out-Null
        exit 1
    }
}

$ErrorActionPreference = 'Continue'
$script:Auto = $false
$script:RegFail = 0
$script:FailureCount = 0
$script:CurrentUserName = [Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]

$desktop = [Environment]::GetFolderPath('Desktop')
$script:LogDir = if ($desktop -and (Test-Path $desktop)) { $desktop } else { $env:TEMP }
$script:Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
try { Start-Transcript -Path (Join-Path $script:LogDir "CyberPatriot-Hardening-$($script:Stamp).log") -Append | Out-Null } catch {}

Write-Host "Admin rights granted!" -ForegroundColor Green
Start-Sleep -Seconds 1

# =====================================================================
# Helpers
# =====================================================================
function Write-Section { param([string]$Text) Write-Host "`n=== $Text ===" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Text) Write-Host $Text -ForegroundColor Green }
function Write-Warn { param([string]$Text) Write-Host $Text -ForegroundColor Yellow }
function Write-Bad  { param([string]$Text) $script:FailureCount++; Write-Host $Text -ForegroundColor Red }

function Wait-Key {
    if (-not $script:Auto) { Read-Host "`nPress Enter to continue" | Out-Null }
}

function Confirm-Action {
    param([string]$Prompt, [bool]$Default = $false)
    $hint = if ($Default) { '[Y/n]' } else { '[y/N]' }
    $a = Read-Host "$Prompt $hint"
    if ([string]::IsNullOrWhiteSpace($a)) { return $Default }
    return ($a -match '^[yY]')
}

# Use a full command name: the built-in R alias resolves to Invoke-History.
function Set-RegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory = $true, Position = 1)][ValidateNotNullOrEmpty()][string]$Name,
        [Parameter(Mandatory = $true, Position = 2)][AllowNull()][AllowEmptyString()][AllowEmptyCollection()]$Value,
        [Parameter(Position = 3)][ValidateSet('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')][string]$Type = 'DWord'
    )
    try {
        if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
        if ($Type -eq 'MultiString') {
            $k = $Path -replace '^HKLM:\\?', 'HKEY_LOCAL_MACHINE\' -replace '^HKCU:\\?', 'HKEY_CURRENT_USER\'
            [Microsoft.Win32.Registry]::SetValue($k, $Name, [string[]]@($Value | Where-Object { $_ }), [Microsoft.Win32.RegistryValueKind]::MultiString)
        }
        else {
            New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
        }
    }
    catch {
        $script:RegFail++
        Write-Bad "  [!] $Path\$Name -> $($_.Exception.Message)"
    }
}

function Write-RegistryResult {
    param([int]$Before, [string]$SuccessMessage)
    $failed = $script:RegFail - $Before
    if ($failed -gt 0) { Write-Bad "Incomplete: $failed registry write(s) failed in this step. See the errors above and the transcript." }
    else { Write-Ok $SuccessMessage }
}

# Native programs do not throw on failure in Windows PowerShell 5.1.
function Invoke-NativeCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @()
    )
    $output = & $FilePath @ArgumentList 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$FilePath failed (exit code $exitCode): $($output -join [Environment]::NewLine)"
    }
    $output
}

function Remove-RegValue {
    param([string]$Path, [string]$Name)
    try { if (Test-Path -LiteralPath $Path) { Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue } } catch {}
}

function Get-OSLabel {
    try { (Get-CimInstance Win32_OperatingSystem).Caption + ' build ' + [Environment]::OSVersion.Version.Build } catch { 'Windows' }
}

# =====================================================================
# 1  User properties
# =====================================================================
function Set-UserProperties {
    Write-Section "1) Setting password properties for all enabled local users"
    foreach ($u in (Get-LocalUser | Where-Object { $_.Enabled })) {
        try {
            Set-LocalUser -Name $u.Name -PasswordNeverExpires $false -UserMayChangePassword $true -ErrorAction Stop
            $adsi = [ADSI]"WinNT://$env:COMPUTERNAME/$($u.Name),user"
            $flags = [int]$adsi.UserFlags.Value
            $flags = $flags -band (-bnot 0x10000)   # password never expires
            $flags = $flags -band (-bnot 0x0040)    # user cannot change password
            $flags = $flags -band (-bnot 0x0020)    # password not required
            $adsi.UserFlags = $flags
            $adsi.Put('PasswordExpired', 0)         # must change at next logon: unchecked
            $adsi.SetInfo()
            Write-Ok "Updated $($u.Name): expires=yes, can change=yes, required=yes, must-change-at-logon=no"
        }
        catch { Write-Bad "Error updating $($u.Name): $_" }
    }
    Wait-Key
}

# =====================================================================
# 2  Change all passwords
# =====================================================================
function Set-AllPasswords {
    Write-Section "2) Change all passwords"
    Write-Host "Type a new password for every ENABLED local account."
    Write-Host "Press Enter with nothing typed to use the default set in the script settings."
    $in = Read-Host "New password" -AsSecureString
    if ($in.Length -eq 0) { $sec = ConvertTo-SecureString $DefaultNewPassword -AsPlainText -Force } else { $sec = $in }
    $skipSelf = -not (Confirm-Action "Also change the password of YOUR current account ($($script:CurrentUserName))?" $false)
    foreach ($u in (Get-LocalUser | Where-Object { $_.Enabled })) {
        if ($skipSelf -and $u.Name -eq $script:CurrentUserName) { Write-Warn "Skipped current account $($u.Name)"; continue }
        try {
            Set-LocalUser -Name $u.Name -Password $sec -ErrorAction Stop
            Write-Ok "Password changed for $($u.Name)"
        }
        catch { Write-Bad "Failed for $($u.Name): $($_.Exception.Message)" }
    }
    Wait-Key
}

# =====================================================================
# 3  Disable Guest / built-in Administrator
# =====================================================================
function Disable-GuestAdmin {
    $regBefore = $script:RegFail
    Write-Section "3) Disable Guest and built-in Administrator"
    $guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }
    $admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
    if ($guest) { Disable-LocalUser -Name $guest.Name -ErrorAction SilentlyContinue; Write-Ok "Guest account ($($guest.Name)) disabled." }
    if ($admin) {
        if ($admin.Name -eq $script:CurrentUserName) {
            Write-Warn "You are logged in as the built-in Administrator ($($admin.Name)). Skipping so you don't lock yourself out."
        }
        else { Disable-LocalUser -Name $admin.Name -ErrorAction SilentlyContinue; Write-Ok "Built-in Administrator ($($admin.Name)) disabled." }
    }
    # CIS 2.3.1.x
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse' 1
    Write-RegistryResult -Before $regBefore -SuccessMessage 'Blank-password restrictions applied.'
    Wait-Key
}

# =====================================================================
# 4  Password policy   (CIS 1.1)
# =====================================================================
function Set-PasswordPolicy {
    $regBefore = $script:RegFail
    Write-Section "4) Password policy (CIS 1.1)"
    $cfg = $null
    try {
        Invoke-NativeCommand -FilePath net.exe -ArgumentList @('accounts', "/uniquepw:$PwHistory") | Out-Null
        Invoke-NativeCommand -FilePath net.exe -ArgumentList @('accounts', "/maxpwage:$PwMaxAge") | Out-Null
        Invoke-NativeCommand -FilePath net.exe -ArgumentList @('accounts', "/minpwage:$PwMinAge") | Out-Null
        Invoke-NativeCommand -FilePath net.exe -ArgumentList @('accounts', "/minpwlen:$PwMinLen") | Out-Null

        $cfg = Join-Path $env:TEMP 'cp-pwpol.inf'
        $inf = @"
[Unicode]
Unicode=yes
[System Access]
PasswordComplexity = 1
ClearTextPassword = 0
LSAAnonymousNameLookup = 0
MinimumPasswordAge = $PwMinAge
MaximumPasswordAge = $PwMaxAge
MinimumPasswordLength = $PwMinLen
PasswordHistorySize = $PwHistory
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
        Set-Content -Path $cfg -Value $inf -Encoding Unicode -ErrorAction Stop
        Invoke-NativeCommand -FilePath secedit.exe -ArgumentList @('/configure', '/db', (Join-Path $env:TEMP 'cp-pwpol.sdb'), '/cfg', $cfg, '/areas', 'SECURITYPOLICY', '/quiet') | Out-Null
        Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' 1
        Write-RegistryResult -Before $regBefore -SuccessMessage "Password policy configured: history $PwHistory, max $PwMaxAge d, min $PwMinAge d, length $PwMinLen, complexity on, no reversible encryption."
    }
    catch { Write-Bad "Error configuring password policy: $_" }
    finally { if ($cfg) { Remove-Item -LiteralPath $cfg -ErrorAction SilentlyContinue } }
    Wait-Key
}

# =====================================================================
# 5  Lockout policy   (CIS 1.2)
# =====================================================================
function Set-LockoutPolicy {
    Write-Section "5) Account lockout policy (CIS 1.2)"
    try {
        Invoke-NativeCommand -FilePath net.exe -ArgumentList @('accounts', "/lockoutthreshold:$LockThreshold") | Out-Null
        Invoke-NativeCommand -FilePath net.exe -ArgumentList @('accounts', "/lockoutduration:$LockDuration") | Out-Null
        Invoke-NativeCommand -FilePath net.exe -ArgumentList @('accounts', "/lockoutwindow:$LockWindow") | Out-Null
        Write-Ok "Lockout: $LockThreshold attempts, $LockDuration min duration, $LockWindow min reset window."
    }
    catch { Write-Bad "Error configuring lockout policy: $_" }
    Wait-Key
}

# =====================================================================
# 6  Firewall   (CIS 9)
# =====================================================================
function Enable-WindowsFirewall {
    Write-Section "6) Windows Defender Firewall (CIS 9)"
    try {
        Set-Service -Name mpssvc -StartupType Automatic -ErrorAction SilentlyContinue
        Set-Service -Name BFE -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name BFE -ErrorAction SilentlyContinue
        Start-Service -Name mpssvc -ErrorAction SilentlyContinue

        foreach ($p in 'Domain', 'Private', 'Public') {
            Set-NetFirewallProfile -Profile $p -Enabled True `
                -DefaultInboundAction Block -DefaultOutboundAction Allow `
                -NotifyOnListen $(if ($p -eq 'Public') { 'False' } else { 'True' }) `
                -LogFileName "%SystemRoot%\System32\logfiles\firewall\$($p.ToLower())fw.log" `
                -LogMaxSizeKilobytes 16384 -LogBlocked True -LogAllowed True
        }
        # Common risky inbound rule groups
        foreach ($g in 'Remote Assistance', 'Windows Remote Management', 'Windows Remote Management (Compatibility)', 'Telnet Server') {
            Disable-NetFirewallRule -DisplayGroup $g -ErrorAction SilentlyContinue
        }
        Write-Ok "Firewall on for Domain/Private/Public: inbound blocked, logging enabled."
    }
    catch { Write-Bad "Error configuring firewall: $_" }
    Wait-Key
}

# =====================================================================
# 7  Search for media / prohibited files
# =====================================================================
function Search-MediaFiles {
    Write-Section "7) Searching for media files"
    Write-Warn "This can take several minutes."
    $exts = '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.wav', '.flac', '.aac', '.ogg', '.m4a', '.wma', '.mpg', '.mpeg', '.jpg', '.jpeg', '.png', '.gif', '.bmp'
    $include = $exts | ForEach-Object { "*$_" }
    $skip = 'Windows', 'Program Files', 'Program Files (x86)', 'System Volume Information', '$Recycle.Bin'
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($d in (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Za-z]:\\$' })) {
        Write-Host "Scanning drive $($d.Root)" -ForegroundColor Cyan
        Get-ChildItem -Path $d.Root -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $exts -contains $_.Extension.ToLower() } | ForEach-Object { $results.Add($_) }
        foreach ($dir in (Get-ChildItem -Path $d.Root -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $skip -notcontains $_.Name })) {
            Get-ChildItem -Path $dir.FullName -Recurse -Force -File -Include $include -ErrorAction SilentlyContinue |
                ForEach-Object { $results.Add($_) }
        }
    }

    if ($results.Count -gt 0) {
        Write-Warn "`nFound $($results.Count) media files. First 100:"
        $results | Select-Object -First 100 FullName, @{n = 'MB'; e = { [math]::Round($_.Length / 1MB, 2) } }, LastWriteTime | Format-Table -AutoSize
        if (Confirm-Action "Export full list to Desktop\MediaFiles.csv?" $true) {
            $out = Join-Path $script:LogDir 'MediaFiles.csv'
            $results | Select-Object FullName, Length, LastWriteTime | Export-Csv -Path $out -NoTypeInformation
            Write-Ok "Exported to $out"
        }
    }
    else { Write-Ok "No media files found." }
    Wait-Key
}

# =====================================================================
# 8  Disable services   (CIS 5)
# =====================================================================
function Disable-UnnecessaryServices {
    Write-Section "8) Disable unnecessary services (CIS 5)"
    $core = @('RemoteRegistry', 'SSDPSRV', 'upnphost', 'WerSvc', 'XboxNetApiSvc', 'XblAuthManager', 'XblGameSave', 'XboxGipSvc',
        'WMPNetworkSvc', 'bthserv', 'BTAGService', 'AJRouter', 'MapsBroker', 'lfsvc', 'SharedAccess', 'Fax', 'Wecsvc', 'irmon',
        'lltdsvc', 'MSiSCSI', 'PNRPsvc', 'p2psvc', 'p2pimsvc', 'PNRPAutoReg', 'RpcLocator', 'RemoteAccess', 'SCardSvr',
        'ScDeviceEnum', 'SCPolicySvc', 'SNMP', 'sacsvr', 'icssvc', 'PushToInstall', 'TlntSvr', 'simptcp', 'NetTcpPortSharing')
    $optional = @('Spooler', 'TermService', 'SessionEnv', 'UmRdpService', 'WinRM', 'W3SVC', 'IISADMIN', 'FTPSVC', 'sshd',
        'LxssManager', 'DmEnrollmentSvc', 'SensorService', 'WdiServiceHost', 'ShellHWDetection')

    function Stop-AndDisable([string]$n) {
        $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($svc) {
            try {
                Stop-Service -Name $n -Force -ErrorAction SilentlyContinue
                Set-Service -Name $n -StartupType Disabled -ErrorAction Stop
                Write-Ok "Disabled: $n"
            }
            catch { Write-Warn "Could not disable: $n" }
        }
    }

    foreach ($s in $core) { Stop-AndDisable $s }

    $present = $optional | Where-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue }
    if ($present) {
        Write-Warn "`nOptional services present (only disable what the README does NOT require):"
        Get-Service -Name $present | Format-Table Name, DisplayName, Status, StartType -AutoSize
        $mode = Read-Host "Disable [A]ll of these, go [O]ne by one, or [N]one? (default N)"
        switch -Regex ($mode) {
            '^[aA]' { foreach ($s in $present) { Stop-AndDisable $s } }
            '^[oO]' { foreach ($s in $present) { if (Confirm-Action "Disable $s ?" $false) { Stop-AndDisable $s } } }
            default { Write-Host "Optional services left alone." }
        }
    }
    Wait-Key
}

# =====================================================================
# 9  UAC   (CIS 2.3.17)
# =====================================================================
function Enable-UAC {
    $regBefore = $script:RegFail
    Write-Section "9) User Account Control (CIS 2.3.17)"
    $S = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-RegistryValue $S 'EnableLUA' 1
    Set-RegistryValue $S 'FilterAdministratorToken' 1
    Set-RegistryValue $S 'ConsentPromptBehaviorAdmin' 2
    Set-RegistryValue $S 'ConsentPromptBehaviorUser' 0
    Set-RegistryValue $S 'EnableInstallerDetection' 1
    Set-RegistryValue $S 'EnableSecureUIAPaths' 1
    Set-RegistryValue $S 'PromptOnSecureDesktop' 1
    Set-RegistryValue $S 'EnableVirtualization' 1
    Set-RegistryValue $S 'ValidateAdminCodeSignatures' 0
    Set-RegistryValue $S 'LocalAccountTokenFilterPolicy' 0
    Write-RegistryResult -Before $regBefore -SuccessMessage "UAC configured (a reboot is required for EnableLUA changes)."
    Wait-Key
}

# =====================================================================
# 10  Remote Desktop
# =====================================================================
function Set-RemoteDesktop {
    $regBefore = $script:RegFail
    Write-Section "10) Remote Desktop configuration"
    $TS = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $TSP = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $a = Read-Host "[D]isable Remote Desktop, [H]arden it but keep it ON (README requires RDP), or [S]kip? (D/H/S)"
    if ($a -match '^[dD]') {
        Set-RegistryValue $TS 'fDenyTSConnections' 1
        Set-RegistryValue $TSP 'fDenyTSConnections' 1
        Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
        Write-Host "Remote Desktop disable settings requested."
    }
    elseif ($a -match '^[hH]') {
        Set-RegistryValue $TS 'fDenyTSConnections' 0
        Set-RegistryValue "$TS\WinStations\RDP-Tcp" 'UserAuthentication' 1      # NLA
        Set-RegistryValue "$TS\WinStations\RDP-Tcp" 'SecurityLayer' 2
        Set-RegistryValue "$TS\WinStations\RDP-Tcp" 'MinEncryptionLevel' 3
        Set-RegistryValue $TSP 'fDenyTSConnections' 0
        Set-RegistryValue $TSP 'UserAuthentication' 1
        Set-RegistryValue $TSP 'SecurityLayer' 2
        Set-RegistryValue $TSP 'MinEncryptionLevel' 3
        Set-RegistryValue $TSP 'DisablePasswordSaving' 1
        Set-RegistryValue $TSP 'fDisableCdm' 1
        Set-RegistryValue $TSP 'fPromptForPassword' 1
        Set-RegistryValue $TSP 'fEncryptRPCTraffic' 1
        Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
        Write-Host "Remote Desktop hardening settings requested: NLA, high encryption, no password saving, drive redirection off."
    }
    else { Write-Warn 'Remote Desktop configuration skipped.'; Wait-Key; return }
    # Remote Assistance off either way (CIS 18.8.36)
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowUnsolicited' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowToGetHelp' 0
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp' 0
    Write-RegistryResult -Before $regBefore -SuccessMessage 'Remote Desktop and Remote Assistance registry settings applied.'
    Wait-Key
}

# =====================================================================
# 11  Automatic updates configuration
# =====================================================================
function Enable-AutoUpdate {
    $regBefore = $script:RegFail
    Write-Section "11) Configure automatic updates"
    $AU = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    Set-RegistryValue $AU 'NoAutoUpdate' 0
    Set-RegistryValue $AU 'AUOptions' 4
    Set-RegistryValue $AU 'ScheduledInstallDay' 0
    Set-RegistryValue $AU 'ScheduledInstallTime' 3
    Set-RegistryValue $AU 'NoAutoRebootWithLoggedOnUsers' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' 'AUOptions' 4
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'AllowMUUpdateService' 1    # other Microsoft products
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'ManagePreviewBuildsPolicyValue' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'BranchReadinessLevel' 16
    foreach ($n in 'wuauserv', 'bits', 'cryptsvc', 'UsoSvc') {
        try { Set-Service -Name $n -StartupType Automatic -ErrorAction Stop; Start-Service -Name $n -ErrorAction SilentlyContinue } catch {}
    }
    Write-RegistryResult -Before $regBefore -SuccessMessage "Automatic updates enabled (download + install automatically, Microsoft Update included)."
    Wait-Key
}

# =====================================================================
# 12  Security options   (CIS 2.3)
# =====================================================================
function Set-SecurityOptions {
    $regBefore = $script:RegFail
    Write-Section "12) Local security options (CIS 2.3)"
    $S = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $L = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $V = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $W = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

    $body = Read-Host "Logon banner text (Enter = default)"
    if ([string]::IsNullOrWhiteSpace($body)) { $body = 'Authorized users only. Activity may be monitored and recorded.' }
    $subject = Read-Host "Logon banner title (Enter = default)"
    if ([string]::IsNullOrWhiteSpace($subject)) { $subject = 'Authorized Use Only' }

    # Accounts
    Set-RegistryValue $S 'NoConnectedUser' 3                         # block Microsoft accounts
    Set-RegistryValue $L 'LimitBlankPasswordUse' 1
    Set-RegistryValue $L 'ForceGuest' 0                              # classic local account sharing
    # Audit
    Set-RegistryValue $L 'SCENoApplyLegacyAuditPolicy' 1
    Set-RegistryValue $L 'CrashOnAuditFail' 0
    Set-RegistryValue $L 'auditbaseobjects' 0
    Set-RegistryValue $L 'fullprivilegeauditing' ([byte[]]@(0)) 'Binary'
    # Devices
    Set-RegistryValue $W 'AllocateDASD' '0' 'String'
    Set-RegistryValue $W 'AllocateCDRoms' '1' 'String'
    Set-RegistryValue $W 'AllocateFloppies' '1' 'String'
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' 'AddPrinterDrivers' 1
    # Domain member / Netlogon
    $N = "$V\Netlogon\Parameters"
    Set-RegistryValue $N 'RequireSignOrSeal' 1
    Set-RegistryValue $N 'SealSecureChannel' 1
    Set-RegistryValue $N 'SignSecureChannel' 1
    Set-RegistryValue $N 'DisablePasswordChange' 0
    Set-RegistryValue $N 'MaximumPasswordAge' 30
    Set-RegistryValue $N 'RequireStrongKey' 1
    # Interactive logon
    Set-RegistryValue $S 'DisableCAD' 0
    Set-RegistryValue $S 'DontDisplayLastUserName' 1
    Set-RegistryValue $S 'InactivityTimeoutSecs' 900
    Set-RegistryValue $S 'legalnoticetext' $body 'String'
    Set-RegistryValue $S 'legalnoticecaption' $subject 'String'
    Set-RegistryValue $S 'undockwithoutlogon' 0
    Set-RegistryValue $S 'ShutdownWithoutLogon' 0
    Set-RegistryValue $W 'CachedLogonsCount' '4' 'String'
    Set-RegistryValue $W 'PasswordExpiryWarning' 14
    Set-RegistryValue $W 'ScRemoveOption' '1' 'String'
    Set-RegistryValue $W 'AutoAdminLogon' '0' 'String'
    # Microsoft network client / server
    Set-RegistryValue "$V\LanmanWorkstation\Parameters" 'RequireSecuritySignature' 1
    Set-RegistryValue "$V\LanmanWorkstation\Parameters" 'EnableSecuritySignature' 1
    Set-RegistryValue "$V\LanmanWorkstation\Parameters" 'EnablePlainTextPassword' 0
    Set-RegistryValue "$V\LanmanServer\Parameters" 'RequireSecuritySignature' 1
    Set-RegistryValue "$V\LanmanServer\Parameters" 'EnableSecuritySignature' 1
    Set-RegistryValue "$V\LanmanServer\Parameters" 'autodisconnect' 15
    Set-RegistryValue "$V\LanmanServer\Parameters" 'enableforcedlogoff' 1
    Set-RegistryValue "$V\LanmanServer\Parameters" 'SMBServerNameHardeningLevel' 1
    # Network access
    Set-RegistryValue $L 'RestrictAnonymousSAM' 1
    Set-RegistryValue $L 'RestrictAnonymous' 1
    Set-RegistryValue $L 'DisableDomainCreds' 1
    Set-RegistryValue $L 'EveryoneIncludesAnonymous' 0
    Set-RegistryValue $L 'RestrictRemoteSAM' 'O:BAG:BAD:(A;;RC;;;BA)' 'String'
    Set-RegistryValue "$V\LanmanServer\Parameters" 'NullSessionPipes' @() 'MultiString'
    Set-RegistryValue "$V\LanmanServer\Parameters" 'NullSessionShares' @() 'MultiString'
    Set-RegistryValue "$V\LanmanServer\Parameters" 'RestrictNullSessAccess' 1
    # Network security
    Set-RegistryValue $L 'UseMachineId' 1
    Set-RegistryValue "$L\MSV1_0" 'AllowNullSessionFallback' 0
    Set-RegistryValue "$L\pku2u" 'AllowOnlineID' 0
    Set-RegistryValue "$V\Kerberos\Parameters" 'SupportedEncryptionTypes' 2147483640
    Set-RegistryValue $L 'LmCompatibilityLevel' 5
    Set-RegistryValue $L 'NoLMHash' 1
    Set-RegistryValue "$V\LDAP" 'LDAPClientIntegrity' 1
    Set-RegistryValue "$L\MSV1_0" 'NTLMMinClientSec' 537395200
    Set-RegistryValue "$L\MSV1_0" 'NTLMMinServerSec' 537395200
    # Shutdown / system objects
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'ClearPageFileAtShutdown' 1
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel' 'ObCaseInsensitive' 1
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'ProtectionMode' 1
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'SafeDllSearchMode' 1
    # UAC (also covered in option 9)
    Set-RegistryValue $S 'EnableLUA' 1
    Set-RegistryValue $S 'FilterAdministratorToken' 1
    Set-RegistryValue $S 'ConsentPromptBehaviorAdmin' 2
    Set-RegistryValue $S 'ConsentPromptBehaviorUser' 0
    Set-RegistryValue $S 'PromptOnSecureDesktop' 1
    Set-RegistryValue $S 'EnableInstallerDetection' 1
    # DEP
    try { Invoke-NativeCommand -FilePath bcdedit.exe -ArgumentList @('/set', '{current}', 'nx', 'AlwaysOn') | Out-Null } catch { Write-Bad "DEP was not configured: $($_.Exception.Message)" }

    Write-RegistryResult -Before $regBefore -SuccessMessage "Security-option registry settings applied. Review any separate DEP error above."
    Wait-Key
}

# =====================================================================
# 13  Audit policy   (CIS 17)
# =====================================================================
function Enable-Auditing {
    $regBefore = $script:RegFail
    Write-Section "13) Advanced audit policy (CIS 17)"
    try {
        Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1
        Invoke-NativeCommand -FilePath auditpol.exe -ArgumentList @('/set', '/category:*', '/success:enable', '/failure:enable') | Out-Null
        Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
        Write-RegistryResult -Before $regBefore -SuccessMessage "Success+Failure auditing enabled for every audit category (superset of the CIS audit list)."
    }
    catch { Write-Bad "Error enabling auditing: $_" }
    Wait-Key
}

# =====================================================================
# 14  Users & groups manager
# =====================================================================
function Edit-Groups {
    $builtin = 'Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount'
    do {
        Clear-Host
        Write-Section "14) Users & groups manager"
        Write-Host "1) List users and administrators      2) Disable users NOT on an authorized list"
        Write-Host "3) Fix Administrators group           4) Create user"
        Write-Host "5) Disable user (confirm)             6) Disable user (confirm)"
        Write-Host "7) Add user to group                  8) Remove user from group"
        Write-Host "0) Back"
        $c = Read-Host "`nChoice"
        switch ($c) {
            '1' {
                Get-LocalUser | Format-Table Name, Enabled, PasswordRequired, PasswordLastSet, LastLogon -AutoSize
                Write-Host "Administrators:" -ForegroundColor Cyan
                Get-LocalGroupMember -Group 'Administrators' | Format-Table Name, ObjectClass, PrincipalSource -AutoSize
                Wait-Key
            }
            '2' {
                $list = (Read-Host "Authorized usernames, comma separated (include yourself)") -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                foreach ($u in (Get-LocalUser)) {
                    if ($builtin -contains $u.Name -or $list -contains $u.Name -or $u.Name -eq $script:CurrentUserName) { continue }
                    if (Confirm-Action "Disable unauthorized user '$($u.Name)'?" $false) {
                        try { Disable-LocalUser -Name $u.Name -ErrorAction Stop; Write-Ok "Disabled $($u.Name)" } catch { Write-Bad "Failed: $_" }
                    }
                }
                Wait-Key
            }
            '3' {
                $list = (Read-Host "Authorized ADMIN usernames, comma separated (include yourself)") -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                foreach ($m in (Get-LocalGroupMember -Group 'Administrators')) {
                    $short = $m.Name.Split('\')[-1]
                    if ($list -contains $short -or $short -eq $script:CurrentUserName -or $m.SID.Value -like '*-500') { continue }
                    if (Confirm-Action "Remove '$($m.Name)' from Administrators?" $false) {
                        try { Remove-LocalGroupMember -Group 'Administrators' -Member $m.Name -ErrorAction Stop; Write-Ok "Removed $($m.Name)" } catch { Write-Bad "Failed: $_" }
                    }
                }
                foreach ($name in $list) {
                    $u = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
                    if ($u -and -not (Get-LocalGroupMember -Group 'Administrators' | Where-Object { $_.Name.Split('\')[-1] -eq $name })) {
                        if (Confirm-Action "'$name' is authorized as admin but is not in Administrators. Add?" $false) {
                            Add-LocalGroupMember -Group 'Administrators' -Member $name -ErrorAction SilentlyContinue
                        }
                    }
                }
                Wait-Key
            }
            '4' {
                $n = Read-Host "New username"
                $p = Read-Host "Password" -AsSecureString
                try { New-LocalUser -Name $n -Password $p -PasswordNeverExpires:$false -ErrorAction Stop | Out-Null; Add-LocalGroupMember -Group 'Users' -Member $n; Write-Ok "Created $n" } catch { Write-Bad "Failed: $_" }
                Wait-Key
            }
            '5' {
                $n = Read-Host "Username to disable"
                if ($n -and (Confirm-Action "Really disable '$n'?" $false)) { try { Disable-LocalUser -Name $n -ErrorAction Stop; Write-Ok "Disabled" } catch { Write-Bad "Failed: $_" } }
                Wait-Key
            }
            '6' {
                $n = Read-Host "Username to disable"
                if ($n -and (Confirm-Action "Disable account '$n'?" $false)) { try { Disable-LocalUser -Name $n -ErrorAction Stop; Write-Ok "Disabled" } catch { Write-Bad "Failed: $_" } }
                Wait-Key
            }
            '7' {
                $g = Read-Host "Group"; $n = Read-Host "Username"
                try { Add-LocalGroupMember -Group $g -Member $n -ErrorAction Stop; Write-Ok "Added" } catch { Write-Bad "Failed: $_" }
                Wait-Key
            }
            '8' {
                $g = Read-Host "Group"; $n = Read-Host "Username"
                try { Remove-LocalGroupMember -Group $g -Member $n -ErrorAction Stop; Write-Ok "Removed" } catch { Write-Bad "Failed: $_" }
                Wait-Key
            }
        }
    } while ($c -ne '0')
}

# =====================================================================
# 15  Advanced security   (CIS 18 - Administrative Templates)
# =====================================================================
function Set-AdvancedSecurity {
    $regBefore = $script:RegFail
    Write-Section "15) Advanced security - CIS 18 administrative templates"
    $POL = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
    $WNT = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT'
    $PSYS = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $PEXP = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $SM = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $TCP = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    $TCP6 = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'

    # --- Lock screen / personalization / input
    Set-RegistryValue "$POL\Personalization" 'NoLockScreenCamera' 1
    Set-RegistryValue "$POL\Personalization" 'NoLockScreenSlideshow' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' 'AllowInputPersonalization' 0

    # --- MS Security Guide / MSS
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' 4
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0
    Set-RegistryValue "$SM\kernel" 'DisableExceptionChainValidation' 0
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'NodeType' 2
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'NoNameReleaseOnDemand' 1
    Set-RegistryValue $TCP 'DisableIPSourceRouting' 2
    Set-RegistryValue $TCP6 'DisableIPSourceRouting' 2
    Set-RegistryValue $TCP 'EnableICMPRedirect' 0
    Set-RegistryValue $TCP 'PerformRouterDiscovery' 0
    Set-RegistryValue $TCP 'TcpMaxDataRetransmissions' 3
    Set-RegistryValue $TCP6 'TcpMaxDataRetransmissions' 3
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'ScreenSaverGracePeriod' '5' 'String'
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security' 'WarningLevel' 90

    # --- Network
    Set-RegistryValue "$WNT\DNSClient" 'EnableMulticast' 0
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS' 0
    Set-RegistryValue "$POL\LanmanWorkstation" 'AllowInsecureGuestAuth' 0
    Set-RegistryValue "$POL\Network Connections" 'NC_ShowSharedAccessUI' 0
    Set-RegistryValue "$POL\Network Connections" 'NC_StdDomainUserSetLocation' 1
    Set-RegistryValue "$POL\NetworkProvider\HardenedPaths" '\\*\NETLOGON' 'RequireMutualAuthentication=1,RequireIntegrity=1' 'String'
    Set-RegistryValue "$POL\NetworkProvider\HardenedPaths" '\\*\SYSVOL' 'RequireMutualAuthentication=1,RequireIntegrity=1' 'String'
    Set-RegistryValue "$POL\WCN\UI" 'DisableWcnUi' 1
    Set-RegistryValue "$POL\WCN\Registrars" 'EnableRegistrars' 0
    Set-RegistryValue "$POL\WcmSvc\GroupPolicy" 'fMinimizeConnections' 1
    Set-RegistryValue "$POL\WcmSvc\GroupPolicy" 'fBlockNonDomain' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' 'AutoConnectAllowedOEM' 0

    # --- Printers
    Set-RegistryValue "$WNT\Printers" 'RegisterSpoolerRemoteRpcEndPoint' 2
    Set-RegistryValue "$WNT\Printers" 'DisableWebPnPDownload' 1
    Set-RegistryValue "$WNT\Printers" 'DisableHTTPPrinting' 1
    Set-RegistryValue "$WNT\Printers" 'CopyFilesPolicy' 1
    Set-RegistryValue "$WNT\Printers" 'RedirectionguardPolicy' 1
    Set-RegistryValue "$WNT\Printers\RPC" 'RpcUseNamedPipeProtocol' 1
    Set-RegistryValue "$WNT\Printers\PointAndPrint" 'RestrictDriverInstallationToAdministrators' 1
    Set-RegistryValue "$WNT\Printers\PointAndPrint" 'NoWarningNoElevationOnInstall' 0
    Set-RegistryValue "$WNT\Printers\PointAndPrint" 'UpdatePromptSettings' 0

    # --- System / logon / credentials
    Set-RegistryValue "$PSYS\Audit" 'ProcessCreationIncludeCmdLine_Enabled' 1
    Set-RegistryValue "$PSYS\CredSSP\Parameters" 'AllowEncryptionOracle' 0
    Set-RegistryValue "$POL\Device Metadata" 'PreventDeviceMetadataFromNetwork' 1
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' 'DriverLoadPolicy' 3
    Set-RegistryValue "$POL\System" 'BlockUserFromShowingAccountDetailsOnSignin' 1
    Set-RegistryValue "$POL\System" 'DontDisplayNetworkSelectionUI' 1
    Set-RegistryValue "$POL\System" 'DontEnumerateConnectedUsers' 1
    Set-RegistryValue "$POL\System" 'EnumerateLocalUsers' 0
    Set-RegistryValue "$POL\System" 'DisableLockScreenAppNotifications' 1
    Set-RegistryValue "$POL\System" 'AllowDomainPINLogon' 0
    Set-RegistryValue "$POL\System" 'AllowCrossDeviceClipboard' 0
    Set-RegistryValue "$POL\System" 'UploadUserActivities' 0
    Set-RegistryValue "$POL\System" 'EnableSmartScreen' 1
    Set-RegistryValue "$POL\System" 'ShellSmartScreenLevel' 'Block' 'String'
    Set-RegistryValue $PSYS 'DisableAutomaticRestartSignOn' 1
    Set-RegistryValue $PSYS 'MSAOptional' 1
    Set-RegistryValue $PSYS 'NoLocalPasswordResetQuestions' 1
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 1
    Set-RegistryValue "$POL\CredUI" 'DisablePasswordReveal' 1
    Set-RegistryValue "$POL\CredUI" 'EnumerateAdministrators' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' 'ACSettingIndex' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' 'DCSettingIndex' 1
    Set-RegistryValue "$WNT\Rpc" 'EnableAuthEpResolution' 1
    Set-RegistryValue "$WNT\Rpc" 'RestrictRemoteClients' 1

    # --- Internet communication / telemetry
    Set-RegistryValue "$POL\TabletPC" 'PreventHandwritingDataSharing' 1
    Set-RegistryValue "$POL\HandwritingErrorReports" 'PreventHandwritingErrorReports' 1
    Set-RegistryValue "$POL\Registration Wizard Control" 'NoRegistration' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Connection Wizard' 'ExitOnMSICW' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion' 'DisableContentFileUpdates' 1
    Set-RegistryValue "$PEXP" 'NoWebServices' 1
    Set-RegistryValue "$PEXP" 'NoOnlinePrintsWizard' 1
    Set-RegistryValue "$PEXP" 'NoPublishingWizard' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' 'CEIPEnable' 0
    Set-RegistryValue "$POL\Windows Error Reporting" 'Disabled' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' 'Disabled' 1
    Set-RegistryValue "$POL\DataCollection" 'AllowTelemetry' 1
    Set-RegistryValue "$POL\DataCollection" 'DisableEnterpriseAuthProxy' 1
    Set-RegistryValue "$POL\DataCollection" 'DisableOneSettingsDownloads' 1
    Set-RegistryValue "$POL\DataCollection" 'DoNotShowFeedbackNotifications' 1
    Set-RegistryValue "$POL\DataCollection" 'EnableOneSettingsAuditing' 1
    Set-RegistryValue "$POL\DataCollection" 'LimitDiagnosticLogCollection' 1
    Set-RegistryValue "$POL\DataCollection" 'LimitDumpCollection' 1
    Set-RegistryValue "$POL\DataCollection" 'AllowDeviceNameInTelemetry' 0
    Set-RegistryValue "$POL\DeliveryOptimization" 'DODownloadMode' 0

    # --- App privacy / runtime / cloud content / consumer features
    Set-RegistryValue "$POL\AppPrivacy" 'LetAppsActivateWithVoiceAboveLock' 2
    Set-RegistryValue "$POL\CloudContent" 'DisableWindowsConsumerFeatures' 1
    Set-RegistryValue "$POL\CloudContent" 'DisableCloudOptimizedContent' 1
    Set-RegistryValue "$POL\Connect" 'RequirePinForPairing' 1
    Set-RegistryValue "$POL\MicrosoftAccount" 'DisableUserAuth' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' 'EnhancedAntiSpoofing' 1

    # --- AutoPlay / Explorer
    Set-RegistryValue "$POL\Explorer" 'NoAutoplayfornonVolume' 1
    Set-RegistryValue $PEXP 'NoAutorun' 1
    Set-RegistryValue $PEXP 'NoDriveTypeAutoRun' 255
    Set-RegistryValue $PEXP 'NoDataExecutionPrevention' 0
    Set-RegistryValue $PEXP 'NoHeapTerminationOnCorruption' 0
    Set-RegistryValue $PEXP 'PreXPSP2ShellProtocolBehavior' 0

    # --- Event logs
    foreach ($log in @(@('Application', 32768), @('Security', 196608), @('Setup', 32768), @('System', 32768))) {
        Set-RegistryValue "$POL\EventLog\$($log[0])" 'MaxSize' $log[1]
        Set-RegistryValue "$POL\EventLog\$($log[0])" 'Retention' '0' 'String'
    }

    # --- Remote Desktop client-side hardening
    Set-RegistryValue "$WNT\Terminal Services" 'DisablePasswordSaving' 1
    Set-RegistryValue "$WNT\Terminal Services" 'fDisableCdm' 1
    Set-RegistryValue "$WNT\Terminal Services" 'fPromptForPassword' 1
    Set-RegistryValue "$WNT\Terminal Services" 'fEncryptRPCTraffic' 1
    Set-RegistryValue "$WNT\Terminal Services" 'MinEncryptionLevel' 3

    # --- Misc: RSS, search, game DVR, ink, installer, PowerShell, WinRM
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' 'DisableEnclosureDownload' 1
    Set-RegistryValue "$POL\Windows Search" 'AllowIndexingEncryptedStoresOrItems' 0
    Set-RegistryValue "$POL\GameDVR" 'AllowGameDVR' 0
    Set-RegistryValue "$POL\WindowsInkWorkspace" 'AllowWindowsInkWorkspace' 1
    Set-RegistryValue "$POL\WindowsInkWorkspace" 'AllowSuggestedAppsInWindowsInkWorkspace' 0
    Set-RegistryValue "$POL\Installer" 'EnableUserControl' 0
    Set-RegistryValue "$POL\Installer" 'AlwaysInstallElevated' 0
    Set-RegistryValue "$POL\PowerShell\ScriptBlockLogging" 'EnableScriptBlockLogging' 1
    Set-RegistryValue "$POL\WinRM\Client" 'AllowBasic' 0
    Set-RegistryValue "$POL\WinRM\Client" 'AllowUnencryptedTraffic' 0
    Set-RegistryValue "$POL\WinRM\Client" 'AllowDigest' 0
    Set-RegistryValue "$POL\WinRM\Service" 'AllowBasic' 0
    Set-RegistryValue "$POL\WinRM\Service" 'AllowUnencryptedTraffic' 0
    Set-RegistryValue "$POL\WinRM\Service" 'DisableRunAs' 1

    # --- Windows 11 specific
    Set-RegistryValue "$POL\WindowsAI" 'DisableAIDataAnalysis' 1      # Recall snapshots
    Set-RegistryValue "$POL\WindowsAI" 'AllowRecallEnablement' 0
    Set-RegistryValue "$POL\WindowsCopilot" 'TurnOffWindowsCopilot' 1

    # --- Windows Update must stay enabled
    Set-RegistryValue "$POL\WindowsUpdate\AU" 'NoAutoUpdate' 0

    Write-RegistryResult -Before $regBefore -SuccessMessage "Administrative-template registry settings applied."
    Wait-Key
}

# =====================================================================
# 16  Apache
# =====================================================================
function Set-ApacheSecurity {
    Write-Section "16) Apache security"
    $cands = @('C:\Apache24\conf\httpd.conf', 'C:\Apache2\conf\httpd.conf', 'C:\xampp\apache\conf\httpd.conf',
        'C:\Program Files\Apache Group\Apache2\conf\httpd.conf', 'C:\Program Files (x86)\Apache Group\Apache2\conf\httpd.conf')
    $conf = $cands | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $conf) {
        $conf = Read-Host "httpd.conf not found automatically. Full path (blank to skip)"
        if ([string]::IsNullOrWhiteSpace($conf) -or -not (Test-Path $conf)) { Write-Warn "Skipped."; Wait-Key; return }
    }
    Write-Host "Using $conf" -ForegroundColor Cyan
    Copy-Item $conf "$conf.bak-$($script:Stamp)" -Force
    $lines = New-Object System.Collections.Generic.List[string]
    Get-Content $conf | ForEach-Object { $lines.Add($_) }
    $wanted = [ordered]@{ ServerTokens = 'Prod'; ServerSignature = 'Off'; TraceEnable = 'Off' }
    foreach ($k in $wanted.Keys) {
        $found = $false
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match "^\s*$k\s+") { $lines[$i] = "$k $($wanted[$k])"; $found = $true }
        }
        if (-not $found) { $lines.Add("$k $($wanted[$k])") }
        Write-Ok "$k $($wanted[$k])"
    }
    Set-Content -Path $conf -Value $lines -Encoding ASCII
    $exe = Join-Path (Split-Path (Split-Path $conf)) 'bin\httpd.exe'
    if (Test-Path $exe) { Write-Host "Config test:" -ForegroundColor Cyan; & $exe -t 2>&1 | ForEach-Object { Write-Host $_ } }
    if (Confirm-Action "Restart Apache service now?" $false) {
        $svc = Get-Service -Name 'Apache*' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($svc) { Restart-Service $svc.Name; Write-Ok "Restarted $($svc.Name)" } else { Write-Warn "Apache service not found - restart manually." }
    }
    Wait-Key
}

# =====================================================================
# 17  Force Windows Updates
# =====================================================================
function Invoke-WindowsUpdateForce {
    $regBefore = $script:RegFail
    Write-Section "17) Force Windows updates (OS + Microsoft products + Defender signatures)"
    Write-Host (Get-OSLabel)

    # Remove anything that blocks or pauses updating
    $wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    foreach ($n in 'DisableWindowsUpdateAccess', 'WUServer', 'WUStatusServer', 'SetDisableUXWUAccess', 'DoNotConnectToWindowsUpdateInternetLocations',
        'DeferFeatureUpdates', 'DeferQualityUpdates', 'DeferFeatureUpdatesPeriodInDays', 'DeferQualityUpdatesPeriodInDays',
        'PauseFeatureUpdatesStartTime', 'PauseQualityUpdatesStartTime') { Remove-RegValue $wu $n }
    Remove-RegValue "$wu\AU" 'UseWUServer'
    Set-RegistryValue "$wu\AU" 'NoAutoUpdate' 0
    if ($script:RegFail -gt $regBefore) { Write-Bad 'Update policy could not be written; resolve the registry errors before forcing updates.'; Wait-Key; return }
    foreach ($n in 'PauseFeatureUpdatesStartTime', 'PauseFeatureUpdatesEndTime', 'PauseQualityUpdatesStartTime', 'PauseQualityUpdatesEndTime', 'PauseUpdatesStartTime', 'PauseUpdatesExpiryTime') {
        Remove-RegValue 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' $n
    }
    foreach ($n in 'wuauserv', 'bits', 'cryptsvc', 'UsoSvc') {
        try { Set-Service -Name $n -StartupType Automatic -ErrorAction Stop; Start-Service -Name $n -ErrorAction SilentlyContinue } catch {}
    }

    if (-not (Test-NetConnection -ComputerName 'www.microsoft.com' -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
        Write-Bad "No internet connection to Microsoft detected. Updates cannot download."
        if (-not (Confirm-Action "Try anyway?" $false)) { Wait-Key; return }
    }

    $ok = $false
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Host "Installing PSWindowsUpdate module from PSGallery..." -ForegroundColor Cyan
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            Install-Module -Name PSWindowsUpdate -Force -Scope AllUsers -AllowClobber -ErrorAction Stop
        }
        Import-Module PSWindowsUpdate -Force -ErrorAction Stop
        Add-WUServiceManager -ServiceID '7971f918-a847-4430-9279-4a52d1efe18d' -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Host "Scanning, downloading and installing all available updates (this can take a long time)..." -ForegroundColor Cyan
        Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -IgnoreReboot -Verbose -ErrorAction Stop
        $ok = $true
    }
    catch { Write-Warn "PSWindowsUpdate route failed: $($_.Exception.Message)" }

    if (-not $ok) {
        Write-Host "Falling back to the built-in Update Orchestrator (UsoClient)..." -ForegroundColor Cyan
        try {
            Start-Process UsoClient.exe -ArgumentList 'StartScan' -Wait -NoNewWindow; Start-Sleep -Seconds 15
            Start-Process UsoClient.exe -ArgumentList 'StartDownload' -Wait -NoNewWindow; Start-Sleep -Seconds 30
            Start-Process UsoClient.exe -ArgumentList 'StartInstall' -Wait -NoNewWindow
            Write-Warn "UsoClient has no progress output. Check Settings > Windows Update to confirm."
        }
        catch { Write-Bad "UsoClient fallback failed: $_" }
    }

    # Defender definitions
    try { Update-MpSignature -ErrorAction Stop; Write-Ok "Defender signatures updated." } catch { Write-Warn "Defender signature update failed: $($_.Exception.Message)" }

    try {
        if (Get-Command Get-WURebootStatus -ErrorAction SilentlyContinue) {
            if (Get-WURebootStatus -Silent) { Write-Warn "A reboot is required to finish installing updates." }
        }
    } catch {}
    if ($ok) { Write-Ok "Windows update pass finished. Re-run this option after rebooting until no updates remain." }
    else { Write-Warn "Update installation is unverified. Check Settings > Windows Update; the fallback only requests background work." }
    Wait-Key
}

# =====================================================================
# 18  Update apps (winget + Microsoft Store)
# =====================================================================
function Update-AllApps {
    Write-Section "18) Update apps (winget + Microsoft Store)"
    # Microsoft Store apps
    try {
        Get-CimInstance -Namespace 'root\cimv2\mdm\dmmap' -ClassName 'MDM_EnterpriseModernAppManagement_AppManagement01' -ErrorAction Stop |
            Invoke-CimMethod -MethodName UpdateScanMethod | Out-Null
        Write-Ok "Microsoft Store app update scan triggered (runs in the background)."
    }
    catch { Write-Warn "Store update trigger not available: $($_.Exception.Message)" }

    # winget
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        Write-Warn "winget not found. Trying to install App Installer..."
        try {
            $tmp = Join-Path $env:TEMP 'AppInstaller.msixbundle'
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri 'https://aka.ms/getwinget' -OutFile $tmp -UseBasicParsing
            Add-AppxPackage -Path $tmp
            $env:Path += ";$env:LOCALAPPDATA\Microsoft\WindowsApps"
            $winget = Get-Command winget -ErrorAction SilentlyContinue
        }
        catch { Write-Bad "Could not install winget: $($_.Exception.Message)" }
    }
    if ($winget) {
        Invoke-NativeCommand -FilePath $winget.Source -ArgumentList @('source', 'update', '--disable-interactivity') | Out-Null
        Write-Host "`nUpgradable apps:" -ForegroundColor Cyan
        winget upgrade --include-unknown --accept-source-agreements
        Write-Host "`nUpgrading everything..." -ForegroundColor Cyan
        $upgradeOutput = & $winget.Source upgrade --all --silent --include-unknown --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1
        $upgradeExit = $LASTEXITCODE
        $upgradeOutput | ForEach-Object { Write-Host $_ }
        if ($upgradeExit -eq 0) { Write-Ok "winget upgrade pass finished." }
        elseif ($upgradeExit -eq -1978335189 -or $upgradeExit -eq 2316632107) { Write-Ok 'No applicable winget updates.' }
        else { Write-Bad "winget upgrade failed (exit code $upgradeExit). Review its output above." }
    }
    else { Write-Warn "winget unavailable - update apps from the Microsoft Store (Library > Get updates)." }
    Wait-Key
}

# =====================================================================
# 19  Defender hardening
# =====================================================================
function Set-DefenderHardening {
    $regBefore = $script:RegFail
    Write-Section "19) Microsoft Defender hardening"
    try { Set-Service -Name WinDefend -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service -Name WinDefend -ErrorAction SilentlyContinue } catch {}
    $dp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    Remove-RegValue $dp 'DisableAntiSpyware'
    Remove-RegValue $dp 'DisableAntiVirus'
    foreach ($n in 'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableOnAccessProtection', 'DisableScanOnRealtimeEnable') {
        Remove-RegValue "$dp\Real-Time Protection" $n
    }
    Set-RegistryValue "$dp\MpEngine" 'MpEnablePus' 1
    Set-RegistryValue "$dp\Spynet" 'LocalSettingOverrideSpynetReporting' 0
    Set-RegistryValue "$dp\Windows Defender Exploit Guard\Network Protection" 'EnableNetworkProtection' 1

    Write-RegistryResult -Before $regBefore -SuccessMessage 'Defender registry policies applied.'

    $asr = @('26190899-1602-49e8-8b27-eb1d0a1ce869', '3b576869-a4ec-4529-8536-b80a7769e899', '56a863a9-875e-4185-98a7-b882c64b5ce5',
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc', '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84', '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c',
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b', '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', 'c1db55ab-c21a-4637-bb3f-a12568109d35', 'd1e49aac-8f56-4280-b9ba-993a6d77406c',
        'd3e037e1-3eb8-44c8-a917-57927947596d', 'd4f940ab-401b-4efc-aadc-ad5f3c50688a', 'e6db77e5-3df2-4cf1-b95a-636979351e5b')
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false `
            -DisableScriptScanning $false -DisableBlockAtFirstSeen $false -DisableRemovableDriveScanning $false `
            -DisableEmailScanning $false -DisableArchiveScanning $false -PUAProtection Enabled -MAPSReporting Advanced `
            -SubmitSamplesConsent SendSafeSamples -EnableNetworkProtection Enabled -CloudBlockLevel High -ErrorAction Stop
        Add-MpPreference -AttackSurfaceReductionRules_Ids $asr -AttackSurfaceReductionRules_Actions (@('Enabled') * $asr.Count) -ErrorAction Stop
        Write-Ok "Defender real-time, cloud, PUA, network protection and ASR rules enabled."
    }
    catch { Write-Warn "Some Defender settings were refused (Tamper Protection can block this): $($_.Exception.Message)" }

    try { Update-MpSignature -ErrorAction Stop; Write-Ok "Signatures updated." } catch { Write-Warn "Signature update failed." }
    if (Confirm-Action "Start a Defender quick scan now?" $false) { try { Start-MpScan -ScanType QuickScan; Write-Ok "Scan finished." } catch { Write-Bad "$_" } }
    Wait-Key
}

# =====================================================================
# 20  Network / optional features hardening
# =====================================================================
function Set-NetworkHardening {
    $regBefore = $script:RegFail
    Write-Section "20) Network protocols, optional features and shares"
    try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -EnableSecuritySignature $true -Force -ErrorAction Stop; Write-Ok "SMBv1 off, SMB signing required (server)." } catch { Write-Warn "SMB server config: $($_.Exception.Message)" }
    try { Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop; Write-Ok "SMB signing required (client)." } catch { Write-Warn "SMB client config: $($_.Exception.Message)" }

    try {
        Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | ForEach-Object {
            Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } | Out-Null
        }
        Write-Ok "NetBIOS over TCP/IP disabled on active adapters."
    }
    catch { Write-Warn "NetBIOS: $($_.Exception.Message)" }

    $sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    foreach ($p in 'SSL 2.0', 'SSL 3.0') {
        foreach ($side in 'Server', 'Client') {
            Set-RegistryValue "$sch\$p\$side" 'Enabled' 0
            Set-RegistryValue "$sch\$p\$side" 'DisabledByDefault' 1
        }
    }
    Write-RegistryResult -Before $regBefore -SuccessMessage "SSL 2.0 / 3.0 registry settings applied."

    foreach ($f in 'SMB1Protocol', 'SMB1Protocol-Client', 'SMB1Protocol-Server', 'TelnetClient', 'TFTP', 'MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2') {
        try {
            $feat = Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction Stop
            if ($feat.State -eq 'Enabled') {
                Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction Stop | Out-Null
                Write-Ok "Disabled feature: $f"
            }
        }
        catch {}
    }

    Write-Host "`nNon-default network shares:" -ForegroundColor Cyan
    $shares = Get-SmbShare -Special $false -ErrorAction SilentlyContinue
    if ($shares) {
        $shares | Format-Table Name, Path, Description -AutoSize
        foreach ($s in $shares) {
            if (Confirm-Action "Remove share '$($s.Name)' ($($s.Path))?" $false) { Remove-SmbShare -Name $s.Name -Force -ErrorAction SilentlyContinue; Write-Ok "Removed $($s.Name)" }
        }
    }
    else { Write-Ok "No non-default shares." }
    Wait-Key
}

# =====================================================================
# 21  User rights assignment   (CIS 2.2)
# =====================================================================
function Set-UserRights {
    Write-Section "21) User rights assignment (CIS 2.2)"
    Write-Warn "This can break services that run as non-default accounts (IIS, SQL Server, backup agents...)."
    if (-not (Confirm-Action "Apply CIS user rights assignments?" $false)) { return }

    $backup = Join-Path $script:LogDir "secpol-backup-$($script:Stamp).inf"
    try { Invoke-NativeCommand -FilePath secedit.exe -ArgumentList @('/export', '/cfg', $backup, '/quiet') | Out-Null }
    catch { Write-Bad "Policy backup failed; user rights were not changed: $_"; Wait-Key; return }
    Write-Host "Current policy backed up to $backup" -ForegroundColor Cyan

    $cfg = Join-Path $env:TEMP 'cp-rights.inf'
    $inf = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeTrustedCredManAccessPrivilege =
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeTcbPrivilege =
SeMachineAccountPrivilege =
SeIncreaseQuotaPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeBackupPrivilege = *S-1-5-32-544
SeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19
SeTimeZonePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-32-545
SeCreatePagefilePrivilege = *S-1-5-32-544
SeCreateTokenPrivilege =
SeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6
SeCreatePermanentPrivilege =
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDebugPrivilege = *S-1-5-32-544
SeDenyNetworkLogonRight = *S-1-5-32-546,*S-1-5-113
SeDenyBatchLogonRight = *S-1-5-32-546
SeDenyServiceLogonRight = *S-1-5-32-546
SeDenyInteractiveLogonRight = *S-1-5-32-546
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546,*S-1-5-113
SeEnableDelegationPrivilege =
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544,*S-1-5-90-0
SeLoadDriverPrivilege = *S-1-5-32-544
SeLockMemoryPrivilege =
SeSecurityPrivilege = *S-1-5-32-544
SeRelabelPrivilege =
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeManageVolumePrivilege = *S-1-5-32-544
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeRestorePrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545
SeTakeOwnershipPrivilege = *S-1-5-32-544
'@
    try {
        Set-Content -Path $cfg -Value $inf -Encoding Unicode -ErrorAction Stop
        Invoke-NativeCommand -FilePath secedit.exe -ArgumentList @('/configure', '/db', (Join-Path $env:TEMP 'cp-rights.sdb'), '/cfg', $cfg, '/areas', 'USER_RIGHTS', '/quiet') | Out-Null
        Write-Ok "User rights assignments applied."
    }
    catch { Write-Bad "User rights were not fully applied: $_. Backup: $backup" }
    finally { Remove-Item -LiteralPath $cfg -ErrorAction SilentlyContinue }
    Wait-Key
}

# =====================================================================
# 22  Recon helpers
# =====================================================================
function Invoke-Recon {
    do {
        Clear-Host
        Write-Section "22) Recon / forensics helpers"
        Write-Host "1) Users, admins          2) Installed software"
        Write-Host "3) Listening ports        4) Non-Microsoft scheduled tasks"
        Write-Host "5) Startup items          6) Shares and hosts file"
        Write-Host "7) Non-system services    8) Hunt for hacking-tool file names"
        Write-Host "9) Defender and firewall status    0) Back"
        $c = Read-Host "`nChoice"
        switch ($c) {
            '1' {
                Get-LocalUser | Format-Table Name, Enabled, PasswordRequired, PasswordLastSet, LastLogon -AutoSize
                Get-LocalGroupMember -Group 'Administrators' | Format-Table Name, ObjectClass, PrincipalSource -AutoSize
                Wait-Key
            }
            '2' {
                $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Sort-Object DisplayName |
                    Format-Table DisplayName, DisplayVersion, Publisher -AutoSize
                Wait-Key
            }
            '3' {
                Get-NetTCPConnection -State Listen | Sort-Object LocalPort |
                    Select-Object LocalAddress, LocalPort, OwningProcess, @{n = 'Process'; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } } | Format-Table -AutoSize
                Wait-Key
            }
            '4' {
                Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } | Format-Table TaskName, TaskPath, State -AutoSize
                Wait-Key
            }
            '5' {
                Get-CimInstance Win32_StartupCommand | Format-Table Name, Command, Location, User -AutoSize
                foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run') {
                    Write-Host $k -ForegroundColor Cyan; Get-ItemProperty $k -ErrorAction SilentlyContinue | Format-List
                }
                Wait-Key
            }
            '6' {
                Get-SmbShare | Format-Table Name, Path, Description -AutoSize
                Write-Host "hosts file (non-comment lines):" -ForegroundColor Cyan
                Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' }
                Wait-Key
            }
            '7' {
                Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' -and $_.PathName -notmatch 'system32|SysWOW64|Windows Defender|Microsoft' } |
                    Format-Table Name, DisplayName, StartMode, PathName -AutoSize
                Wait-Key
            }
            '8' {
                $pat = '*mimikatz*', '*keylog*', '*hydra*', '*john*', '*cain*', '*nmap*', '*netcat*', '*nc.exe', '*wireshark*', '*crack*', '*backdoor*', '*rootkit*', '*metasploit*'
                foreach ($root in "$env:SystemDrive\Users", "$env:SystemDrive\ProgramData", "$env:SystemDrive\Program Files", "$env:SystemDrive\Program Files (x86)", "$env:SystemDrive\Temp") {
                    if (Test-Path $root) { Get-ChildItem -Path $root -Recurse -Force -Include $pat -ErrorAction SilentlyContinue | Select-Object FullName, Length | Format-Table -AutoSize }
                }
                Wait-Key
            }
            '9' {
                try { Get-MpComputerStatus | Format-List AMServiceEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated, QuickScanEndTime } catch { Write-Warn "Defender status unavailable." }
                Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -AutoSize
                Wait-Key
            }
        }
    } while ($c -ne '0')
}

# =====================================================================
# 23  README audit (authorized users / administrators)
# =====================================================================
function Get-ReadmeText {
    param([string]$Path)
    if ($Path -match '\.url$') {
        # Desktop shortcut to the README: read the target
        $target = (Get-Content -LiteralPath $Path | Where-Object { $_ -match '^URL=' } | Select-Object -First 1) -replace '^URL=', ''
        if ($target -match '^file:') { $Path = ([Uri]$target).LocalPath }
        elseif ($target -match '^https?:') {
            $raw = (Invoke-WebRequest -Uri $target -UseBasicParsing).Content
            $Path = $null
        }
        else { throw "Unsupported shortcut target: $target" }
    }
    if ($Path) { $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop }
    $t = $raw -replace '(?is)<(script|style).*?</\1>', ''
    $t = $t -replace '(?i)<br\s*/?>|</p>|</div>|</li>|</tr>|</h\d>|</pre>', "`n"
    $t = $t -replace '<[^>]+>', ''
    $t = [System.Net.WebUtility]::HtmlDecode($t)
    return ($t -replace "`r", '')
}

function Find-ReadmeFile {
    $dirs = @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('CommonDesktopDirectory'))
    $dirs += Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'Desktop' }
    $dirs = $dirs | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
    $found = @()
    foreach ($d in $dirs) {
        $found += Get-ChildItem -Path $d -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'read\s*me' -and $_.Extension -match '^\.(html?|txt|md|url)$' }
    }
    return $found
}

function Read-AuthorizedLists {
    param([string]$Text)
    $admins = New-Object System.Collections.Generic.List[string]
    $users = New-Object System.Collections.Generic.List[string]
    $mode = $null
    foreach ($line in ($Text -split "`n")) {
        $l = $line.Trim()
        if ($l -match '^Authorized Administrators?\s*:') { $mode = 'admin'; continue }
        if ($l -match '^Authorized Users?\s*:') { $mode = 'user'; continue }
        if (-not $mode -or -not $l) { continue }
        if ($l -match '^(password|pass|pw)\s*:') { continue }
        if ($l -match '^([A-Za-z0-9._\-\$]+)(\s*\((you|me|this account)\))?\s*$') {
            if ($mode -eq 'admin') { $admins.Add($Matches[1]) } else { $users.Add($Matches[1]) }
        }
        else { $mode = $null }   # a prose line means the list has ended
    }
    return [pscustomobject]@{ Admins = @($admins); Users = @($users) }
}

function Invoke-ReadmeAudit {
    Write-Section "23) README audit - authorized users and administrators"
    $file = $null
    $cands = @(Find-ReadmeFile)
    if ($cands.Count -eq 1) { $file = $cands[0].FullName; Write-Host "Found README: $file" -ForegroundColor Cyan }
    elseif ($cands.Count -gt 1) {
        for ($i = 0; $i -lt $cands.Count; $i++) { Write-Host ("{0}) {1}" -f ($i + 1), $cands[$i].FullName) }
        $n = Read-Host "Pick a README number (Enter to type a path instead)"
        if ($n -match '^\d+$' -and [int]$n -ge 1 -and [int]$n -le $cands.Count) { $file = $cands[[int]$n - 1].FullName }
    }
    if (-not $file) {
        $p = Read-Host "Full path to the README file (Enter to type the names by hand)"
        if ($p -and (Test-Path -LiteralPath $p)) { $file = $p }
    }

    $adminList = @(); $userList = @()
    if ($file) {
        try {
            $parsed = Read-AuthorizedLists -Text (Get-ReadmeText -Path $file)
            $adminList = @($parsed.Admins); $userList = @($parsed.Users)
        }
        catch { Write-Bad "Could not read README: $($_.Exception.Message)" }
    }
    if ($adminList.Count -gt 0 -or $userList.Count -gt 0) {
        Write-Host "`nParsed from README:" -ForegroundColor Cyan
        Write-Host ("  Authorized administrators: " + ($adminList -join ', '))
        Write-Host ("  Authorized users:          " + ($userList -join ', '))
        if (-not (Confirm-Action "Do these lists look right?" $true)) { $adminList = @(); $userList = @() }
    }
    if ($adminList.Count -eq 0 -and $userList.Count -eq 0) {
        $adminList = @((Read-Host "Authorized ADMIN usernames, comma separated") -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $userList = @((Read-Host "Authorized standard USER usernames, comma separated") -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($adminList.Count -eq 0 -and $userList.Count -eq 0) { Write-Warn "No lists provided."; Wait-Key; return }
    }

    $authAdmin = @($adminList | ForEach-Object { $_.ToLower() })
    $authAll = @($authAdmin) + @($userList | ForEach-Object { $_.ToLower() })
    $me = $script:CurrentUserName.ToLower()
    $rep = New-Object System.Collections.Generic.List[string]
    $say = { param($t, $c = 'White') Write-Host $t -ForegroundColor $c; $rep.Add($t) }

    if ($authAll -notcontains $me) { & $say "WARNING: you ($($script:CurrentUserName)) are not in the README lists. This tool never changes your own account." 'Yellow' }

    $local = @(Get-LocalUser)
    $localNames = @($local | ForEach-Object { $_.Name.ToLower() })
    $admMembers = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue)
    $admShort = @($admMembers | ForEach-Object { $_.Name.Split('\')[-1].ToLower() })

    $unauth = @($local | Where-Object { $_.SID.Value -notmatch '-(500|501|503|504)$' -and $authAll -notcontains $_.Name.ToLower() })
    $adminBad = @($admMembers | Where-Object { $_.ObjectClass -eq 'User' -and $_.SID.Value -notmatch '-500$' -and $authAdmin -notcontains $_.Name.Split('\')[-1].ToLower() })
    $adminMissing = @($authAdmin | Where-Object { $localNames -contains $_ -and $admShort -notcontains $_ })
    $noAccount = @($authAll | Where-Object { $localNames -notcontains $_ })

    & $say "`n=== README AUDIT REPORT ===" 'Cyan'
    & $say "Currently in the Administrators group:" 'Cyan'
    foreach ($m in $admMembers) {
        $short = $m.Name.Split('\')[-1].ToLower()
        if ($m.ObjectClass -ne 'User') { & $say "  $($m.Name)  [$($m.ObjectClass)]  -> review manually" 'Yellow' }
        elseif ($m.SID.Value -match '-500$') { & $say "  $($m.Name)  [built-in Administrator - use option 3 to disable]" 'Gray' }
        elseif ($authAdmin -contains $short) { & $say "  $($m.Name)  OK - authorized administrator" 'Green' }
        elseif ($authAll -contains $short) { & $say "  $($m.Name)  REMOVE - authorized user, but NOT an authorized administrator" 'Red' }
        else { & $say "  $($m.Name)  REMOVE - not in the README at all" 'Red' }
    }
    & $say "`nUnauthorized local users (not in README):" 'Cyan'
    if ($unauth.Count -eq 0) { & $say "  none" 'Green' }
    else { foreach ($u in $unauth) { & $say ("  {0}  (enabled: {1})" -f $u.Name, $u.Enabled) 'Red' } }
    & $say "`nAuthorized administrators missing from the Administrators group:" 'Cyan'
    if ($adminMissing.Count -eq 0) { & $say "  none" 'Green' } else { foreach ($n in $adminMissing) { & $say "  $n" 'Yellow' } }
    & $say "`nREADME names with no local account:" 'Cyan'
    if ($noAccount.Count -eq 0) { & $say "  none" 'Green' } else { foreach ($n in $noAccount) { & $say "  $n" 'Yellow' } }

    $reportPath = Join-Path $script:LogDir "README-Audit-$($script:Stamp).txt"
    $rep | Set-Content -Path $reportPath -Encoding UTF8
    Write-Host "`nReport saved to $reportPath" -ForegroundColor Cyan

    if ($adminBad.Count -eq 0 -and $unauth.Count -eq 0 -and $adminMissing.Count -eq 0) { Write-Ok "Nothing to change."; Wait-Key; return }

    $act = Read-Host "Apply changes? [R]eport only / [A]sk for each (default) / [Y] apply all"
    if ($act -match '^[rR]') { Wait-Key; return }
    $auto = ($act -match '^[yY]')
    Write-Host "Unauthorized accounts will only be disabled, never deleted."

    foreach ($m in $adminBad) {
        $short = $m.Name.Split('\')[-1]
        if ($short.ToLower() -eq $me) { Write-Warn "Skipping your own account ($short)."; continue }
        if ($auto -or (Confirm-Action "Remove '$($m.Name)' from Administrators?" $true)) {
            try { Remove-LocalGroupMember -Group 'Administrators' -Member $m.Name -ErrorAction Stop; Write-Ok "Removed $($m.Name) from Administrators" }
            catch { Write-Bad "Failed: $($_.Exception.Message)" }
        }
    }
    foreach ($u in $unauth) {
        if ($u.Name.ToLower() -eq $me) { Write-Warn "Skipping your own account ($($u.Name))."; continue }
        $verb = 'Disable'
        if ($auto -or (Confirm-Action "$verb unauthorized user '$($u.Name)'?" $true)) {
            try {
                Disable-LocalUser -Name $u.Name -ErrorAction Stop
                Write-Ok "$verb done: $($u.Name)"
            }
            catch { Write-Bad "Failed: $($_.Exception.Message)" }
        }
    }
    foreach ($n in $adminMissing) {
        if (Confirm-Action "'$n' is an authorized admin but not in Administrators. Add?" $false) {
            try { Add-LocalGroupMember -Group 'Administrators' -Member $n -ErrorAction Stop; Write-Ok "Added $n to Administrators" }
            catch { Write-Bad "Failed: $($_.Exception.Message)" }
        }
    }
    Wait-Key
}

# =====================================================================
# 88  Run everything
# =====================================================================
function Invoke-Everything {
    Write-Section "RUN EVERYTHING"
    if (-not (Confirm-Action "Have you read the README and noted required users, services and software?" $false)) { return }
    if (-not (Confirm-Action "Apply ALL hardening steps now?" $false)) { return }
    $doUpd = Confirm-Action "Also force Windows updates and app updates at the end (slow)?" $true
    $script:Auto = $true
    $failureBefore = $script:FailureCount
    try {
        Set-UserProperties
        Set-AllPasswords
        Disable-GuestAdmin
        Invoke-ReadmeAudit
        Set-PasswordPolicy
        Set-LockoutPolicy
        Enable-WindowsFirewall
        Disable-UnnecessaryServices
        Enable-UAC
        Set-RemoteDesktop
        Enable-AutoUpdate
        Set-SecurityOptions
        Set-AdvancedSecurity
        Enable-Auditing
        Set-DefenderHardening
        Set-NetworkHardening
        Set-UserRights
        if ($doUpd) { Invoke-WindowsUpdateForce; Update-AllApps }
    }
    finally { $script:Auto = $false }
    if ($script:FailureCount -gt $failureBefore) { Write-Bad "Selected steps finished with errors. Review the transcript and rerun the failed options." }
    else { Write-Host "Selected steps finished. Review all warnings and finish media search (7), Apache (16), and README items manually." }
    if (Confirm-Action "Reboot now to apply everything?" $false) { Stop-Transcript | Out-Null; Restart-Computer -Force }
}

# =====================================================================
# Menu
# =====================================================================
function Show-Menu {
    Clear-Host
    $line = '~' * 79
    Write-Host $line -ForegroundColor Cyan
    Write-Host "   #####   ##   ##  #######  ###    ##  ####### " -ForegroundColor Cyan
    Write-Host "  ##       ##   ##  ##       ####   ##     ##   " -ForegroundColor Cyan
    Write-Host "  ##  ###  #######  #####    ## ##  ##     ##   " -ForegroundColor Cyan
    Write-Host "  ##   ##  ##   ##  ##       ##  ## ##     ##   " -ForegroundColor Cyan
    Write-Host "   #####   ##   ##  #######  ##   ####     ##   " -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host "                         ~Written by: JASIAH.O~" -ForegroundColor Cyan
    Write-Host "   $(Get-OSLabel)   |   CIS Level 1 aligned" -ForegroundColor DarkCyan
    Write-Host $line -ForegroundColor Cyan
    $rows = @(
        @('1) Set user properties', '2) Change all passwords'),
        @('3) Disable guest/admin', '4) Set password policy'),
        @('5) Set lockout policy', '6) Enable Firewall (CIS 9)'),
        @('7) Search for media files', '8) Disable services'),
        @('9) Turn on UAC', '10) Remote Desktop config'),
        @('11) Configure auto update', '12) Security options (CIS 2.3)'),
        @('13) Audit the machine', '14) Users & groups manager'),
        @('15) Advanced security (CIS 18)', '16) Apache security'),
        @('17) FORCE Windows updates', '18) Update apps (winget/Store)'),
        @('19) Defender hardening', '20) Network/features/shares'),
        @('21) User rights (CIS 2.2)', '22) Recon / forensics helpers'),
        @('88) RUN EVERYTHING', '70) Reboot'),
        @('23) README user/admin audit', '69) Exit')
    )
    foreach ($r in $rows) { Write-Host ("{0,-38}{1}" -f $r[0], $r[1]) }
    Write-Host $line -ForegroundColor Cyan
}

# Initial prompt
Clear-Host
$answer = Read-Host "Have you answered all the forensics questions? [y/n]"
if ($answer -ne 'y') {
    Write-Warn "Please go and answer them."
    pause
    try { Stop-Transcript | Out-Null } catch {}
    exit
}

do {
    Show-Menu
    $choice = Read-Host "`nPlease choose an option"
    try {
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
            '17' { Invoke-WindowsUpdateForce }
            '18' { Update-AllApps }
            '19' { Set-DefenderHardening }
            '20' { Set-NetworkHardening }
            '21' { Set-UserRights }
            '22' { Invoke-Recon }
            '23' { Invoke-ReadmeAudit }
            '88' { Invoke-Everything }
            '69' { try { Stop-Transcript | Out-Null } catch {}; exit }
            '70' { try { Stop-Transcript | Out-Null } catch {}; Restart-Computer -Force }
            default {
                Write-Bad "Invalid option. Please try again."
                Start-Sleep -Seconds 2
            }
        }
    }
    catch { Write-Bad "Option $choice failed: $($_.Exception.Message)"; Wait-Key }
} while ($true)
