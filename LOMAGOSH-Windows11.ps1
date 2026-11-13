<#
.SYNOPSIS
    LOMAGOSH by Jasiah O - standalone Windows security toolkit.
.DESCRIPTION
    One file contains elevation, menus, policy APIs, forensic helpers and role-aware
    service/AD/DNS/DHCP tools. No launchers, modules or files from old/ are needed.
    Requires elevated 64-bit Windows PowerShell 5.1 and the selected Windows edition.
    Windows management cmdlets depend on the corresponding installed OS roles.
.NOTES
    Author: Jasiah O | LOMAGOSH
    Run this file with Windows PowerShell and approve the Windows UAC prompt.
    Main menu: 2 default passwords; 4/5 policy verification; 6 firewall; 8 services
    enable/disable; 12 default warning banner; 13 system audit; 23 README/account
    review; 24 guided tasks/forensics; 25 global object auditing; 26 server roles.
    Server workflow: load THIS image's README in 26 > R, review required services,
    then 8 > 5 for local reachability and 8 > 6 for the README SSH port. Verify
    reachability/login from a separate client too. Server 88 preserves roles/WSUS.
    Disabled role-based users stay disabled and join Graveyard when required.
    Unknown roles are reviewed; info/will attributes and primary login are preserved.
    Accounts are never deleted. Finish forensics first. Actions may be refused by
    domain policy, permissions or platform capabilities; failures are reported.
    Native Windows operations still require validation on a disposable Windows VM.
#>

#Requires -Version 5.1
$ToolkitTarget = 'Windows11'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Error 'This toolkit requires Windows. No changes were made.'
    exit 1
}

# =====================================================================
# SETTINGS - edit these to match the README / your preferences
# =====================================================================
$DefaultNewPassword = '1qaz!QAZ2wsx@WSX'   # used automatically by password-change and user-creation tasks
$DefaultLogonCaption = 'WARNING - AUTHORIZED USERS ONLY'
$DefaultLogonText = 'This computer is for authorized users only. If you do not have explicit permission, you are not allowed to access or use this PC. Activity may be monitored and recorded. Unauthorized access or misuse may result in disciplinary action and/or legal action. Disconnect immediately if you are not authorized.'
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
        [string]$Title = 'LOMAGOSH by Jasiah O',
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
$script:CurrentUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

$desktop = [Environment]::GetFolderPath('Desktop')
$script:LogDir = if ($desktop -and (Test-Path $desktop)) { $desktop } else { $env:TEMP }
$script:Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
try { Start-Transcript -Path (Join-Path $script:LogDir "LOMAGOSH-$($script:Stamp).log") -Append | Out-Null } catch {}

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

function Get-DefaultAccountPassword {
    if ([string]::IsNullOrEmpty($DefaultNewPassword)) { throw 'DefaultNewPassword is empty; configure it in the settings block.' }
    ConvertTo-SecureString -String $DefaultNewPassword -AsPlainText -Force
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

function Read-SystemAuditPolicy {
    param([string]$Path)
    # auditpol localizes CSV headers; the seven-column schema is fixed.
    $headers = 'Machine Name', 'Policy Target', 'Subcategory', 'Subcategory GUID', 'Inclusion Setting', 'Exclusion Setting', 'Setting Value'
    $rows = @(Get-Content -LiteralPath $Path -ErrorAction Stop | Select-Object -Skip 1 | ConvertFrom-Csv -Header $headers | Where-Object { $_.'Policy Target' -eq 'System' })
    if ($rows.Count -eq 0) { throw "No system audit subcategories found in $Path. Policy was not verified." }
    $seen = @{}
    foreach ($row in $rows) {
        $guid = [guid]::Empty
        if (-not [guid]::TryParse($row.'Subcategory GUID', [ref]$guid) -or
            $row.'Setting Value' -notmatch '^[0-3]$' -or $seen.ContainsKey($guid.ToString())) {
            throw "Invalid or duplicate audit policy row in $Path."
        }
        $seen[$guid.ToString()] = $true
    }
    $rows
}

function Assert-AuditPolicy {
    param([object[]]$Expected, [object[]]$Actual, [string]$Store)
    if (-not $Expected.Count -or -not $Actual.Count) { throw "Empty audit policy in $Store." }
    foreach ($row in $Expected) {
        $found = @($Actual | Where-Object { [guid]$_.'Subcategory GUID' -eq [guid]$row.'Subcategory GUID' })
        if ($found.Count -ne 1 -or $found[0].'Setting Value' -ne $row.'Setting Value') {
            throw "Audit verification failed in ${Store}: $($row.Subcategory) ($($row.'Subcategory GUID')). Another policy may override local settings."
        }
    }
}

function Assert-FirewallProfiles {
    param([object[]]$Profiles, [string]$Store)
    foreach ($name in 'Domain', 'Private', 'Public') {
        $profile = @($Profiles | Where-Object { $_.Name -eq $name })
        if ($profile.Count -ne 1 -or [string]$profile[0].Enabled -ne 'True' -or
            [string]$profile[0].DefaultInboundAction -ne 'Block' -or
            [string]$profile[0].DefaultOutboundAction -ne 'Allow' -or
            [string]$profile[0].LogBlocked -ne 'True' -or [string]$profile[0].LogAllowed -ne 'True' -or
            $profile[0].LogMaxSizeKilobytes -lt 16384) {
            throw "Firewall verification failed for $name in $Store. Another Group Policy may override local settings."
        }
    }
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
    Assert-LocalAccountWorkflow
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
    if(Test-ToolkitDomainController){Reset-ApprovedServerPasswords;return}
    Assert-LocalAccountWorkflow
    Write-Section "2) Change all passwords"
    Write-Host 'Using the configured default password for enabled local accounts. No password entry is needed.'
    $sec = Get-DefaultAccountPassword
    $skipSelf = -not (Confirm-Action "Also change the password of YOUR current account ($($script:CurrentUserName))?" $true)
    foreach ($u in (Get-LocalUser | Where-Object { $_.Enabled })) {
        if(Test-PasswordProtectedAccount $u.Name){Write-Warn "Skipped protected auto-login account $($u.Name).";continue}
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
    if(Test-ToolkitDomainController){Disable-ServerBuiltinAccounts;return}
    Assert-LocalAccountWorkflow
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
    if(Test-ToolkitDomainController){Set-ServerDomainAccountPolicy -Part Password;return}
    Write-Section "4) Apply and verify password policy"
    $regBefore=$script:RegFail
    try {
        if($PwMinLen -lt 1 -or $PwMinLen -gt 128 -or $PwMinAge -lt 0 -or $PwMaxAge -le $PwMinAge -or $PwHistory -lt 0 -or $PwHistory -gt 24) {
            throw 'Invalid password settings: use length 1-128, maximum age greater than minimum age, and history 0-24.'
        }
        $work=Join-Path $script:LogDir ('PasswordPolicy-'+[guid]::NewGuid())
        $null=[IO.Directory]::CreateDirectory($work)
        Write-Host "Password policy work/backup folder: $work"
        Invoke-NativeCommand secedit.exe @('/export','/mergedpolicy','/cfg',(Join-Path $work 'before.inf'),'/areas','SECURITYPOLICY','/quiet') | Out-Null
        $desired=[ordered]@{MinimumPasswordAge=$PwMinAge;MaximumPasswordAge=$PwMaxAge;MinimumPasswordLength=$PwMinLen;PasswordHistorySize=$PwHistory;PasswordComplexity=1;ClearTextPassword=0}
        Set-AccountPolicyValues -Values $desired -Work $work
        Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' NoLMHash 1
        Confirm-AccountPolicy -Desired $desired -Work $work
        Confirm-EnabledAccountPasswordFlags
        Write-RegistryResult -Before $regBefore -SuccessMessage "Verified password policy: history $PwHistory, max $PwMaxAge d, min $PwMinAge d, length $PwMinLen, complexity on, reversible encryption off; enabled-account password flags verified."
        Write-Host "Policy backup and read-back files: $work"
    }
    catch { Write-Bad "Password policy was not fully verified: $($_.Exception.Message)" }
    Wait-Key
}

# =====================================================================
# 5  Lockout policy   (CIS 1.2)
# =====================================================================
function Set-LockoutPolicy {
    if(Test-ToolkitDomainController){Set-ServerDomainAccountPolicy -Part Lockout;return}
    Write-Section "5) Apply and verify account lockout policy"
    try {
        if($LockThreshold -lt 1 -or $LockThreshold -gt 999 -or $LockWindow -lt 1 -or $LockDuration -lt $LockWindow -or $LockDuration -gt 99999) {
            throw 'Invalid lockout settings: threshold 1-999, window at least 1 minute, duration at least the window and at most 99999 minutes.'
        }
        $work=Join-Path $script:LogDir ('LockoutPolicy-'+[guid]::NewGuid())
        $null=[IO.Directory]::CreateDirectory($work)
        Write-Host "Lockout policy work/backup folder: $work"
        Invoke-NativeCommand secedit.exe @('/export','/mergedpolicy','/cfg',(Join-Path $work 'before.inf'),'/areas','SECURITYPOLICY','/quiet') | Out-Null
        $desired=[ordered]@{LockoutBadCount=$LockThreshold;LockoutDuration=$LockDuration;ResetLockoutCount=$LockWindow}
        Set-AccountPolicyValues -Values $desired -Work $work
        Confirm-AccountPolicy -Desired $desired -Work $work
        Write-Ok "Verified lockout: $LockThreshold attempts, $LockDuration min duration, $LockWindow min reset window."
        Write-Host "Policy backup and read-back files: $work"
    }
    catch { Write-Bad "Lockout policy was not fully verified: $($_.Exception.Message)" }
    Wait-Key
}

# =====================================================================
# 6  Firewall   (CIS 9)
# =====================================================================
function Enable-WindowsFirewall {
    if(Test-ToolkitServer){Enable-ServerFirewall;return}
    Write-Section "6) Windows Defender Firewall - local Group Policy and effective settings"
    try {
        foreach ($service in 'BFE', 'mpssvc') {
            $state = Get-Service -Name $service -ErrorAction Stop
            if ($state.StartType -eq 'Disabled') {
                Set-Service -Name $service -StartupType Automatic -ErrorAction Stop
            }
            if ($state.Status -ne 'Running') {
                Start-Service -Name $service -ErrorAction Stop
            }
        }
        $backup = Join-Path $script:LogDir ('FirewallPolicy-' + [guid]::NewGuid() + '.clixml')
        Get-NetFirewallProfile -PolicyStore localhost -ErrorAction Stop | Export-Clixml -LiteralPath $backup -ErrorAction Stop
        Write-Host "Previous local GPO firewall profiles backed up to $backup"
        # localhost writes the Local Group Policy Object displayed by gpedit;
        # PersistentStore also configures the local non-GPO firewall settings.
        foreach ($store in 'localhost', 'PersistentStore') {
            foreach ($name in 'Domain', 'Private', 'Public') {
                Set-NetFirewallProfile -PolicyStore $store -Profile $name -Enabled True `
                    -DefaultInboundAction Block -DefaultOutboundAction Allow `
                    -NotifyOnListen $(if ($name -eq 'Public') { 'False' } else { 'True' }) `
                    -LogFileName "%SystemRoot%\System32\logfiles\firewall\$($name.ToLower())fw.log" `
                    -LogMaxSizeKilobytes 16384 -LogBlocked True -LogAllowed True -ErrorAction Stop
            }
        }
        Invoke-NativeCommand -FilePath gpupdate.exe -ArgumentList @('/target:computer', '/force', '/wait:60') | Out-Null
        Assert-FirewallProfiles -Profiles @(Get-NetFirewallProfile -PolicyStore localhost -ErrorAction Stop) -Store 'Local Group Policy'
        Assert-FirewallProfiles -Profiles @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop) -Store 'effective policy'
        if(-not (Test-ToolkitServer)){
        foreach ($group in 'Remote Assistance', 'Windows Remote Management', 'Windows Remote Management (Compatibility)', 'Telnet Server') {
            Disable-NetFirewallRule -DisplayGroup $group -ErrorAction SilentlyContinue
        }
        }
        Write-Ok 'Verified local GPO and effective firewall profiles: Domain/Private/Public ON, inbound Block, outbound Allow, logging enabled.'
        Write-Host 'Close and reopen the Local Group Policy editor to refresh its displayed values.'
    }
    catch { Write-Bad "Firewall configuration or verification failed: $_" }
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
    if(Test-ToolkitServer){Invoke-ServiceManager;return}
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
                Assert-ServiceCanStop $n
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
        $blocked=Get-ServerServiceBlockReason TermService
        if($blocked){throw "RDP disable blocked: $blocked"}
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
    Set-RegistryValue $AU 'NoAutoRebootWithLoggedOnUsers' $(if(Test-ToolkitServer){1}else{0})
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' 'AUOptions' 4
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'AllowMUUpdateService' 1    # other Microsoft products
    if(-not (Test-ToolkitServer)){
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'ManagePreviewBuildsPolicyValue' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'BranchReadinessLevel' 16
    }
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
    if(Test-ToolkitServer){Set-ServerRegistryBaseline;return}
    $regBefore = $script:RegFail
    Write-Section "12) Local security options (CIS 2.3)"
    $S = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $L = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $V = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $W = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

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
    Set-RegistryValue $S 'legalnoticetext' $DefaultLogonText 'String'
    Set-RegistryValue $S 'legalnoticecaption' $DefaultLogonCaption 'String'
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
    param([guid[]]$SubcategoryGuid = @())
    $regBefore=$script:RegFail
    Write-Section '13) System audit policy - built-in Windows tools'
    try {
        $work=Join-Path $script:LogDir ('AuditPolicy-'+[guid]::NewGuid())
        $null=[IO.Directory]::CreateDirectory($work)
        Write-Host "Audit policy work/backup folder: $work"
        $before=Join-Path $work 'audit-before.csv'
        Invoke-NativeCommand auditpol.exe @('/backup',"/file:$before") | Out-Null
        $current=@(Read-SystemAuditPolicy -Path $before)
        foreach($guid in $SubcategoryGuid) {
            if(@($current | Where-Object {[guid]$_.'Subcategory GUID' -eq $guid}).Count -ne 1){throw "Windows did not report subcategory $guid; no audit policy was changed."}
        }
        $desired=@($current | ForEach-Object {
            $selected=$SubcategoryGuid.Count -eq 0 -or $SubcategoryGuid -contains [guid]$_.'Subcategory GUID'
            [pscustomobject][ordered]@{
                'Machine Name'='';'Policy Target'='System';'Subcategory'=$_.Subcategory;'Subcategory GUID'=$_.'Subcategory GUID'
                'Inclusion Setting'=if($selected){'Success and Failure'}else{$_.'Inclusion Setting'}
                'Exclusion Setting'=$_.'Exclusion Setting';'Setting Value'=if($selected){'3'}else{$_.'Setting Value'}
            }
        })
        $csv=Join-Path $work 'audit-desired.csv'
        $desired | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding Unicode -ErrorAction Stop
        # The Windows API saves Registry.pol and registers the installed audit CSE.
        # It updates Group Policy revisions itself; no download or hand-edited GPT.ini.
        $persisted=Save-LocalAuditPolicy -Csv $csv -Work $work -Legacy:($SubcategoryGuid.Count -eq 0)
        if($SubcategoryGuid.Count -eq 0) {
            $legacy=Join-Path $work 'legacy-effective.inf'
            New-SecurityPolicyInf -Section 'Event Audit' -Values (Get-LegacyAuditValues) | Set-Content -LiteralPath $legacy -Encoding Unicode -ErrorAction Stop
            Invoke-NativeCommand secedit.exe @('/configure','/db',(Join-Path $work 'audit.sdb'),'/cfg',$legacy,'/areas','SECURITYPOLICY','/quiet') | Out-Null
        }
        Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy 1
        Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' ProcessCreationIncludeCmdLine_Enabled 1
        if($script:RegFail -gt $regBefore){throw 'Required audit registry values were refused.'}
        $targets=if($SubcategoryGuid.Count){$SubcategoryGuid}else{@('*')}
        foreach($target in $targets) {
            Invoke-NativeCommand auditpol.exe @('/set',"/subcategory:$target",'/success:enable','/failure:enable') | Out-Null
        }
        Invoke-NativeCommand gpupdate.exe @('/target:computer','/force','/wait:60') | Out-Null
        Assert-AuditPolicy -Expected $desired -Actual @(Read-SystemAuditPolicy -Path $persisted) -Store 'Local Group Policy'
        $effective=Join-Path $work 'audit-effective.csv'
        Invoke-NativeCommand auditpol.exe @('/backup',"/file:$effective") | Out-Null
        Assert-AuditPolicy -Expected $desired -Actual @(Read-SystemAuditPolicy -Path $effective) -Store 'effective audit policy'
        foreach($setting in @(
            @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','SCENoApplyLegacyAuditPolicy'),
            @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit','ProcessCreationIncludeCmdLine_Enabled')
        )) {
            if((Get-ItemProperty -LiteralPath $setting[0] -Name $setting[1] -ErrorAction Stop).($setting[1]) -ne 1){throw "Audit registry setting overridden: $($setting[1])"}
        }
        if(-not $SubcategoryGuid.Count) {
            $legacyState=Join-Path $work 'legacy-verified.inf'
            Invoke-NativeCommand secedit.exe @('/export','/cfg',$legacyState,'/areas','SECURITYPOLICY','/quiet') | Out-Null
            $actual=Read-PolicyInfSection -Text (Get-Content -LiteralPath $legacyState -Raw -ErrorAction Stop) -Section 'Event Audit'
            $legacyValues=Get-LegacyAuditValues
            foreach($key in $legacyValues.Keys){if(-not $actual.ContainsKey($key) -or $actual[$key] -ne '3'){throw "Legacy audit category not verified: $key"}}
        }
        $count=if($SubcategoryGuid.Count){$SubcategoryGuid.Count}else{$desired.Count}
        Write-Ok "Verified $count advanced audit subcategories in local GPO and effective policy: Success and Failure."
        Write-Host "Backups and verification files: $work"
        Write-Host 'Reopen secpol.msc/gpedit.msc to refresh the display. Global object SACLs remain a separate opt-in setup.'
    }
    catch { Write-Bad "System audit policy was not fully verified: $($_.Exception.Message)" }
    Wait-Key
}

# =====================================================================
# 14  Users & groups manager
# =====================================================================
function Edit-Groups {
    if(Test-ToolkitDomainController){Invoke-ServerRoleManager;return}
    Assert-LocalAccountWorkflow
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
                $p = Get-DefaultAccountPassword
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
    if(Test-ToolkitServer){Set-ServerRegistryBaseline;Write-Host 'Use option 26 for reviewed server-role settings. Workstation-only templates were not applied.';return}
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
    if(Test-ToolkitServer){Invoke-ServerWindowsUpdate;return}
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
    if((Test-ToolkitServer) -and -not (Get-Command winget.exe -ErrorAction SilentlyContinue)){Show-ServerInstalledSoftware;Write-Warn 'Microsoft Store/automatic App Installer deployment is not used on Server 2022. Update required apps using their signed vendor installers.';Wait-Key;return}
    Write-Section "18) Update apps (winget + Microsoft Store)"
    # Microsoft Store apps are a workstation workflow.
    if(-not (Test-ToolkitServer)){
    try {
        Get-CimInstance -Namespace 'root\cimv2\mdm\dmmap' -ClassName 'MDM_EnterpriseModernAppManagement_AppManagement01' -ErrorAction Stop |
            Invoke-CimMethod -MethodName UpdateScanMethod | Out-Null
        Write-Ok "Microsoft Store app update scan triggered (runs in the background)."
    }
    catch { Write-Warn "Store update trigger not available: $($_.Exception.Message)" }

    }
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
    if(Test-ToolkitServer){
        if(-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)){Write-Warn 'Defender management is unavailable on this server; review installed antivirus/Defender roles.';return}
        if(-not (Confirm-Action 'Apply Defender/ASR settings after checking required server apps and remote management?' $false)){return}
    }
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

    if(-not (Test-ToolkitServer)){
    try {
        Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | ForEach-Object {
            Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } | Out-Null
        }
        Write-Ok "NetBIOS over TCP/IP disabled on active adapters."
    }
    catch { Write-Warn "NetBIOS: $($_.Exception.Message)" }

    } else {Write-Host 'Server NetBIOS/network adapter settings are preserved for role-specific review.'}
    $sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    foreach ($p in 'SSL 2.0', 'SSL 3.0') {
        foreach ($side in 'Server', 'Client') {
            Set-RegistryValue "$sch\$p\$side" 'Enabled' 0
            Set-RegistryValue "$sch\$p\$side" 'DisabledByDefault' 1
        }
    }
    Write-RegistryResult -Before $regBefore -SuccessMessage "SSL 2.0 / 3.0 registry settings applied."

    Disable-ToolkitLegacyFeatures

    Write-Host "`nNon-default network shares:" -ForegroundColor Cyan
    $shares = Get-SmbShare -Special $false -ErrorAction SilentlyContinue
    if ($shares) {
        $shares | Format-Table Name, Path, Description -AutoSize
        foreach ($s in $shares) {
            if($s.Name -in 'SYSVOL','NETLOGON'){Write-Host "Preserving required domain share $($s.Name).";continue}
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
    if(Test-ToolkitServer){Remove-ServerDomainUsersBackupRight;return}
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
                if(Test-ToolkitDomainController){
                    $domain=Get-CurrentAdDomain
                    Get-ADUser -Filter * -Properties PasswordNeverExpires -ErrorAction Stop | Select-Object SamAccountName,Enabled,PasswordNeverExpires | Format-Table -AutoSize | Out-Host
                    $group=Get-ADGroup -Identity ($domain.DomainSID.Value+'-512') -ErrorAction Stop
                    Get-ADGroupMember -Identity $group -ErrorAction Stop | Select-Object Name,SamAccountName,objectClass | Format-Table -AutoSize | Out-Host
                }
                else {
                    Get-LocalUser | Format-Table Name, Enabled, PasswordRequired, PasswordLastSet, LastLogon -AutoSize
                    Get-LocalGroupMember -Group 'Administrators' | Format-Table Name, ObjectClass, PrincipalSource -AutoSize
                }
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
    if(Test-ToolkitDomainController){Import-ServerImageRules;if($script:ServerImageRules){Invoke-ServerAdAccountAudit};return}
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

    $script:WarriorReadmePlan = [pscustomobject]@{Source=$file; Admins=@($adminList); Users=@($adminList)+@($userList)}
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
    if(Test-ToolkitServer){Invoke-ServerBaseline;return}
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
    $line='~'*79
    Write-Host $line -ForegroundColor Cyan
    Write-Host 'LOMAGOSH by Jasiah O' -ForegroundColor Cyan
    Write-Host "   $ToolkitTarget | $(Get-OSLabel)" -ForegroundColor DarkCyan
    Write-Host $line -ForegroundColor Cyan
    $rows = @(
        @('1) Set user properties', '2) Change all passwords'),
        @('3) Disable guest/admin', '4) Set password policy'),
        @('5) Set lockout policy', '6) Enable Firewall (CIS 9)'),
        @('7) Search for media files', '8) Services enable/disable'),
        @('9) Turn on UAC', '10) Remote Desktop config'),
        @('11) Configure auto update', '12) Security options (CIS 2.3)'),
        @('13) Audit the machine', '14) Users & groups manager'),
        @('15) Advanced security (CIS 18)', '16) Apache security'),
        @('17) FORCE Windows updates', '18) Update apps (winget/Store)'),
        @('19) Defender hardening', '20) Network/features/shares'),
        @('21) User rights (CIS 2.2)', '22) Recon / forensics helpers'),
        @('88) RUN EVERYTHING', '70) Reboot'),
        @('23) README user/admin audit', '24) Windows Warrior walkthrough'),
        @('25) Global object auditing (opt-in)', '26) Server roles / Active Directory'),
        @('70) Reboot', '69) Exit')
    )
    foreach ($r in $rows) { if(-not (Test-ToolkitServer) -and $r[1] -like '26)*'){$r[1]=''}; Write-Host ("{0,-38}{1}" -f $r[0], $r[1]) }
    Write-Host $line -ForegroundColor Cyan
}

#Requires -Version 5.1
<# Built-in Windows policy support. Importing this file does not change policy. #>
function Initialize-WindowsPolicyApi {
    if ('CyberPatriot.WindowsPolicyApi' -as [type]) { return }
    # Interface order and constants follow Microsoft's gpedit.h and lmaccess.h.
    # Only compiling this type is portable; its methods require elevated Windows.
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.ComponentModel;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace CyberPatriot {
 [ComImport, Guid("EA502723-A23D-11D1-A7D3-0000F87571E3"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
 interface IGroupPolicyObject {
  [PreserveSig] int New([MarshalAs(UnmanagedType.LPWStr)] string domain, [MarshalAs(UnmanagedType.LPWStr)] string name, uint flags);
  [PreserveSig] int OpenDSGPO([MarshalAs(UnmanagedType.LPWStr)] string path, uint flags);
  [PreserveSig] int OpenLocalMachineGPO(uint flags);
  [PreserveSig] int OpenRemoteMachineGPO([MarshalAs(UnmanagedType.LPWStr)] string name, uint flags);
  [PreserveSig] int Save([MarshalAs(UnmanagedType.Bool)] bool machine, [MarshalAs(UnmanagedType.Bool)] bool add, ref Guid extension, ref Guid editor);
  [PreserveSig] int Delete();
  [PreserveSig] int GetName([MarshalAs(UnmanagedType.LPWStr)] StringBuilder name, int size);
  [PreserveSig] int GetDisplayName([MarshalAs(UnmanagedType.LPWStr)] StringBuilder name, int size);
  [PreserveSig] int SetDisplayName([MarshalAs(UnmanagedType.LPWStr)] string name);
  [PreserveSig] int GetPath([MarshalAs(UnmanagedType.LPWStr)] StringBuilder path, int size);
  [PreserveSig] int GetDSPath(uint section, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder path, int size);
  [PreserveSig] int GetFileSysPath(uint section, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder path, int size);
  [PreserveSig] int GetRegistryKey(uint section, out IntPtr key);
 }
 public static class WindowsPolicyApi {
  static readonly Guid GpoClass = new Guid("EA502722-A23D-11D1-A7D3-0000F87571E3");
  // This tool's own editor identity; not an invented Microsoft extension GUID.
  static readonly Guid Editor = new Guid("CB0E4DB0-DC6B-43C5-9A61-461DE3783264");
  static void Check(int hr) { if (hr < 0) Marshal.ThrowExceptionForHR(hr); }
  static IGroupPolicyObject Open() {
   if (Environment.OSVersion.Platform != PlatformID.Win32NT) throw new PlatformNotSupportedException("Windows policy APIs require Windows.");
   IGroupPolicyObject gpo = (IGroupPolicyObject)Activator.CreateInstance(Type.GetTypeFromCLSID(GpoClass));
   try { Check(gpo.OpenLocalMachineGPO(1)); return gpo; }
   catch { Marshal.FinalReleaseComObject(gpo); throw; }
  }
  static string MachinePath(IGroupPolicyObject gpo) {
   StringBuilder path = new StringBuilder(32768);
   Check(gpo.GetFileSysPath(2, path, path.Capacity)); return path.ToString();
  }
  public static string GetMachinePath() {
   IGroupPolicyObject gpo = Open();
   try { return MachinePath(gpo); } finally { Marshal.FinalReleaseComObject(gpo); }
  }
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern int RegCreateKeyEx(IntPtr root, string name, uint reserved, string cls, uint options, uint access, IntPtr security, out IntPtr key, out uint disposition);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern int RegSetValueEx(IntPtr key, string name, uint reserved, uint kind, ref uint value, uint length);
  [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
  static void Dword(IntPtr root, string path, string name, uint value) {
   IntPtr key; uint disposition;
   int error = RegCreateKeyEx(root, path, 0, null, 0, 0x0002, IntPtr.Zero, out key, out disposition);
   if (error != 0) throw new Win32Exception(error);
   try { error=RegSetValueEx(key,name,0,4,ref value,4); if(error!=0)throw new Win32Exception(error); }
   finally { RegCloseKey(key); }
  }
  static void Copy(string source, string target) {
   Directory.CreateDirectory(Path.GetDirectoryName(target)); File.Copy(source,target,true);
  }
  public static void SaveAudit(string csv, string legacyInf, Guid auditExtension, Guid securityExtension) {
   IGroupPolicyObject gpo = Open();
   try {
    string machine=MachinePath(gpo);
    Copy(csv,Path.Combine(machine,@"Microsoft\Windows NT\Audit\audit.csv"));
    if (!String.IsNullOrEmpty(legacyInf)) Copy(legacyInf,Path.Combine(machine,@"Microsoft\Windows NT\SecEdit\GptTmpl.inf"));
    IntPtr root; Check(gpo.GetRegistryKey(2,out root));
    try {
     Dword(root,@"SYSTEM\CurrentControlSet\Control\Lsa","SCENoApplyLegacyAuditPolicy",1);
     Dword(root,@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit","ProcessCreationIncludeCmdLine_Enabled",1);
    } finally { RegCloseKey(root); }
    Guid editor=Editor;
    Guid registry=new Guid("35378EAC-683F-11D2-A89A-00C04FBBCFA2");
    Check(gpo.Save(true,true,ref registry,ref editor));
    if(!String.IsNullOrEmpty(legacyInf)) Check(gpo.Save(true,true,ref securityExtension,ref editor));
    Check(gpo.Save(true,true,ref auditExtension,ref editor));
   } finally { Marshal.FinalReleaseComObject(gpo); }
  }
  [StructLayout(LayoutKind.Sequential)] struct Modals0 { public uint Length,MaximumAge,MinimumAge,ForceLogoff,History; }
  [StructLayout(LayoutKind.Sequential)] struct Modals3 { public uint Duration,Window,Threshold; }
  [DllImport("netapi32.dll",CharSet=CharSet.Unicode)] static extern int NetUserModalsGet(string server,uint level,out IntPtr data);
  [DllImport("netapi32.dll")] static extern int NetApiBufferFree(IntPtr data);
  [DllImport("netapi32.dll",CharSet=CharSet.Unicode)] static extern int NetUserModalsSet(string server,uint level,ref Modals0 data,out uint parameter);
  static int Days(uint value) { return value==UInt32.MaxValue ? 0 : checked((int)(value/86400)); }
  static int Minutes(uint value) { return value==UInt32.MaxValue ? 0 : checked((int)(value/60)); }
  public static Dictionary<string,int> ReadAccountPolicy() {
   IntPtr data=IntPtr.Zero; Modals0 password; Modals3 account;
   int error=NetUserModalsGet(null,0,out data); if(error!=0)throw new Win32Exception(error);
   try { password=(Modals0)Marshal.PtrToStructure(data,typeof(Modals0)); } finally { NetApiBufferFree(data); }
   error=NetUserModalsGet(null,3,out data); if(error!=0)throw new Win32Exception(error);
   try { account=(Modals3)Marshal.PtrToStructure(data,typeof(Modals3)); } finally { NetApiBufferFree(data); }
   return new Dictionary<string,int> {
    {"MinimumPasswordLength",checked((int)password.Length)}, {"MaximumPasswordAge",Days(password.MaximumAge)},
    {"MinimumPasswordAge",Days(password.MinimumAge)}, {"PasswordHistorySize",checked((int)password.History)},
    {"LockoutBadCount",checked((int)account.Threshold)}, {"LockoutDuration",Minutes(account.Duration)}, {"ResetLockoutCount",Minutes(account.Window)}
   };
  }
  public static void SetMinimumLength(uint length) {
   IntPtr data; int error=NetUserModalsGet(null,0,out data); if(error!=0)throw new Win32Exception(error);
   Modals0 policy; try { policy=(Modals0)Marshal.PtrToStructure(data,typeof(Modals0)); } finally { NetApiBufferFree(data); }
   policy.Length=length; uint parameter; error=NetUserModalsSet(null,0,ref policy,out parameter);
   if(error!=0)throw new Win32Exception(error,"Cannot set minimum password length (parameter "+parameter+"). For lengths above 14, configure the supported Relax minimum password length limits policy first.");
  }
 }
}
'@ -ErrorAction Stop
}

function Get-LocalGpoMachinePath {
    Initialize-WindowsPolicyApi
    [CyberPatriot.WindowsPolicyApi]::GetMachinePath()
}

function Get-PolicyExtensionGuid {
    param([ValidateSet('auditcse.dll','scecli.dll')][string]$Dll)
    $extensions = @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions' -ErrorAction Stop | Where-Object {
        $file = (Get-ItemProperty -LiteralPath $_.PSPath -Name DllName -ErrorAction SilentlyContinue).DllName
        $file -and ([IO.Path]::GetFileName([Environment]::ExpandEnvironmentVariables($file)) -ieq $Dll)
    })
    if ($extensions.Count -ne 1) { throw "Windows did not report exactly one $Dll Group Policy extension; no extension identifier was guessed." }
    [guid]$extensions[0].PSChildName
}

function Set-PolicyInfSection {
    param([string]$ExistingText = '', [string]$Section, [System.Collections.IDictionary]$Values)
    # Preserve unrelated sections and lines. Replace requested keys only.
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $inside=$false; $found=$false
    $remaining=@{}; foreach($key in $Values.Keys){$remaining[$key]=[string]$Values[$key]}
    foreach($line in ($ExistingText -split '\r?\n')) {
        if($line -match '^\s*\[([^\]]+)\]\s*$') {
            if($inside){foreach($key in @($remaining.Keys)){$lines.Add("$key = $($remaining[$key])");$remaining.Remove($key)}}
            $inside=($Matches[1] -ieq $Section); if($inside){$found=$true}
        }
        if($inside -and $line -match '^\s*([^;=]+?)\s*=') {
            $key=$Matches[1].Trim()
            if($Values.Contains($key)) { if($remaining.ContainsKey($key)){$lines.Add("$key = $($Values[$key])");$remaining.Remove($key)};continue }
        }
        $lines.Add($line)
    }
    if(-not $found){$lines.Add("[$Section]")}
    foreach($key in $remaining.Keys){$lines.Add("$key = $($remaining[$key])")}
    $lines -join "`r`n"
}

function Read-PolicyInfSection {
    param([string]$Text,[string]$Section)
    $values=@{}; $inside=$false
    foreach($line in ($Text -split '\r?\n')) {
        if($line -match '^\s*\[([^\]]+)\]\s*$'){$inside=($Matches[1] -ieq $Section);continue}
        if($inside -and $line -match '^\s*([^;=]+?)\s*=\s*(.*?)\s*$'){$values[$Matches[1].Trim()]=$Matches[2]}
    }
    $values
}

function Get-LegacyAuditValues {
    [ordered]@{AuditSystemEvents=3;AuditLogonEvents=3;AuditObjectAccess=3;AuditPrivilegeUse=3;AuditPolicyChange=3;AuditAccountManage=3;AuditProcessTracking=3;AuditDSAccess=3;AuditAccountLogon=3}
}

function New-SecurityPolicyInf {
    param([string]$Section,[System.Collections.IDictionary]$Values)
    Set-PolicyInfSection -ExistingText "[Unicode]`r`nUnicode=yes`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n" -Section $Section -Values $Values
}

function Invoke-NativeGpoAuditSave {
    param([string]$Csv,[string]$LegacyInf,[guid]$AuditExtension,[guid]$SecurityExtension)
    Initialize-WindowsPolicyApi
    [CyberPatriot.WindowsPolicyApi]::SaveAudit($Csv,$LegacyInf,$AuditExtension,$SecurityExtension)
}

function Save-LocalAuditPolicy {
    param([string]$Csv,[string]$Work,[switch]$Legacy)
    $machine=Get-LocalGpoMachinePath
    $root=Split-Path -Parent $machine
    if(Test-Path -LiteralPath $root){Copy-Item -LiteralPath $root -Destination (Join-Path $Work 'LocalGpoBackup') -Recurse -Force -ErrorAction Stop}
    $existingAudit=Join-Path $machine 'Microsoft\Windows NT\Audit\audit.csv'
    if(Test-Path -LiteralPath $existingAudit) {
        $headers='Machine Name','Policy Target','Subcategory','Subcategory GUID','Inclusion Setting','Exclusion Setting','Setting Value'
        $other=@(Get-Content -LiteralPath $existingAudit -ErrorAction Stop | Select-Object -Skip 1 | ConvertFrom-Csv -Header $headers | Where-Object {$_.'Policy Target' -ne 'System'})
        if($other.Count) {
            $rows=@(Import-Csv -LiteralPath $Csv -ErrorAction Stop)+$other
            $Csv=Join-Path $Work 'audit-with-existing-user-options.csv'
            $rows | Export-Csv -LiteralPath $Csv -NoTypeInformation -Encoding Unicode -ErrorAction Stop
        }
    }
    $audit=Get-PolicyExtensionGuid auditcse.dll
    $security=[guid]::Empty; $merged=$null
    if($Legacy) {
        $security=Get-PolicyExtensionGuid scecli.dll
        $existing=Join-Path $machine 'Microsoft\Windows NT\SecEdit\GptTmpl.inf'
        $text=if(Test-Path -LiteralPath $existing){Get-Content -LiteralPath $existing -Raw -ErrorAction Stop}else{New-SecurityPolicyInf -Section 'Event Audit' -Values @{}}
        $merged=Join-Path $Work 'legacy-gpo.inf'
        Set-PolicyInfSection -ExistingText $text -Section 'Event Audit' -Values (Get-LegacyAuditValues) | Set-Content -LiteralPath $merged -Encoding Unicode -ErrorAction Stop
    }
    Invoke-NativeGpoAuditSave -Csv $Csv -LegacyInf $merged -AuditExtension $audit -SecurityExtension $security
    Join-Path $machine 'Microsoft\Windows NT\Audit\audit.csv'
}

function Get-EffectiveAccountPolicy {
    param([string]$Work)
    $export=Join-Path $Work ('effective-'+[guid]::NewGuid()+'.inf')
    Invoke-NativeCommand secedit.exe @('/export','/mergedpolicy','/cfg',$export,'/areas','SECURITYPOLICY','/quiet') | Out-Null
    $values=Read-PolicyInfSection -Text (Get-Content -LiteralPath $export -Raw -ErrorAction Stop) -Section 'System Access'
    Initialize-WindowsPolicyApi
    # SAM numeric values are the effective local-account policy, not localized net.exe text.
    $sam=[CyberPatriot.WindowsPolicyApi]::ReadAccountPolicy()
    foreach($key in $sam.Keys){$values[$key]=[int]$sam[$key]}
    $values
}

function Set-AccountPolicyValues {
    param([System.Collections.IDictionary]$Values,[string]$Work)
    $cfg=Join-Path $Work ('desired-'+[guid]::NewGuid()+'.inf')
    New-SecurityPolicyInf -Section 'System Access' -Values $Values | Set-Content -LiteralPath $cfg -Encoding Unicode -ErrorAction Stop
    # Preserve current unrelated SAM settings when setting a longer minimum.
    if($Values.Contains('MinimumPasswordLength') -and [int]$Values['MinimumPasswordLength'] -le 14) {
        Initialize-WindowsPolicyApi
        [CyberPatriot.WindowsPolicyApi]::SetMinimumLength([uint32]$Values['MinimumPasswordLength'])
    }
    Invoke-NativeCommand secedit.exe @('/configure','/db',(Join-Path $Work 'policy.sdb'),'/cfg',$cfg,'/areas','SECURITYPOLICY','/quiet') | Out-Null
}

function Confirm-AccountPolicy {
    param([System.Collections.IDictionary]$Desired,[string]$Work)
    foreach($attempt in 0,1) {
        $actual=Get-EffectiveAccountPolicy -Work $Work
        $bad=@($Desired.Keys | Where-Object { -not $actual.Contains($_) -or [string]$actual[$_] -ne [string]$Desired[$_] })
        if(-not $bad.Count){return}
        if($attempt -eq 0) {
            Write-Warn ('Policy read-back differs; reapplying: '+($bad -join ', '))
            $repair=[ordered]@{};foreach($key in $bad){$repair[$key]=$Desired[$key]}
            Set-AccountPolicyValues -Values $repair -Work $Work
        }
        else { throw ('Effective account policy still differs: '+($bad -join ', ')+'. A domain policy or unsupported setting may override the local configuration.') }
    }
}

function Confirm-EnabledAccountPasswordFlags {
    $enabled=@(Get-LocalUser -ErrorAction Stop | Where-Object Enabled)
    foreach($attempt in 0,1) {
        $accounts=@(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
        $bad=New-Object 'System.Collections.Generic.List[object]'
        foreach($user in $enabled) {
            $state=@($accounts | Where-Object SID -eq $user.SID.Value)
            if($state.Count -ne 1 -or $null -eq $state[0].PasswordRequired -or $null -eq $state[0].PasswordExpires){throw "Cannot verify password flags for $($user.Name)."}
            if(-not $state[0].PasswordRequired -or -not $state[0].PasswordExpires){$bad.Add([pscustomobject]@{User=$user;State=$state[0]})}
        }
        if(-not $bad.Count){return}
        if($attempt -eq 1){throw ('Password-required/expiration flags remain incorrect: '+(($bad.User.Name) -join ', '))}
        foreach($item in $bad) {
            if(-not $item.State.PasswordExpires){Set-LocalUser -Name $item.User.Name -PasswordNeverExpires $false -ErrorAction Stop}
            if(-not $item.State.PasswordRequired){Invoke-NativeCommand net.exe @('user',$item.User.Name,'/passwordreq:yes') | Out-Null}
        }
    }
}


#Requires -Version 5.1
<#
Guided functions embedded in this standalone LOMAGOSH script.
Contains declarations only. Importing this file performs no hardening.
#>
function Get-WarriorTasks {
    # Id | title | illustrative command | explanation | GUI path
    $catalog = @'
1|Disable Guest|Disable-LocalUser -Name Guest|Disables the built-in Guest account, including renamed Guest accounts.|lusrmgr.msc > Users > Guest > Properties > Account is disabled
2|Disable built-in Administrator|Disable-LocalUser -Name Administrator|Disables the built-in administrator; protects the account running this tool.|lusrmgr.msc > Users > Administrator > Properties > Account is disabled
3|Disable unauthorized hacker account|Disable-LocalUser -Name hacker|Disables hacker and removes its administrator membership. Accounts are NEVER deleted, including in this tutorial.|lusrmgr.msc > Users > hacker > Properties > Account is disabled
4|Remove webdev from Administrators|Remove-LocalGroupMember -Group Administrators -Member webdev|Removes administrator privileges while preserving the webdev account.|lusrmgr.msc > Groups > Administrators > webdev > Remove
5|Require a password for intern|Set-LocalUser -Name intern -Password (Get-DefaultAccountPassword); net.exe user intern /passwordreq:yes|Uses the configured default password automatically and marks the selected account's password as required.|lusrmgr.msc > Users > selected account > Set Password; password-required flag uses net.exe
6|Make contractor password expire|Set-LocalUser -Name contractor -PasswordNeverExpires $false|Subjects contractor to the account password-expiration policy.|lusrmgr.msc > Users > contractor > Properties > clear Password never expires
7|Create standard user analyst|New-LocalUser -Name analyst -Password (Get-DefaultAccountPassword)|Creates the selected account with the configured default password if absent, adds it to Users and ensures it is not an administrator.|lusrmgr.msc > Users > New User; Groups > Users > Add selected account
8|Minimum password length at least 12|net.exe accounts /minpwlen:12|Uses at least 12 characters, retaining the stronger toolkit minimum when configured.|secpol.msc > Account Policies > Password Policy > Minimum password length
9|Enable password complexity|secedit.exe /configure /db policy.sdb /cfg complexity.inf /areas SECURITYPOLICY|Applies a backed-up security template enabling complexity and disabling reversible encryption.|secpol.msc > Account Policies > Password Policy > Password must meet complexity requirements
10|Maximum password age at most 90 days|net.exe accounts /maxpwage:90|Requires periodic password changes, retaining the stronger toolkit maximum age.|secpol.msc > Account Policies > Password Policy > Maximum password age
11|Minimum password age at least 1 day|net.exe accounts /minpwage:1|Prevents immediately cycling passwords to bypass password history.|secpol.msc > Account Policies > Password Policy > Minimum password age
12|Remember at least 10 passwords|net.exe accounts /uniquepw:10|Prevents reuse, retaining the toolkit's longer history where configured.|secpol.msc > Account Policies > Password Policy > Enforce password history
13|Lock out after at most 5 failures|net.exe accounts /lockoutthreshold:5|Enables a nonzero lockout threshold of at most five bad attempts.|secpol.msc > Account Policies > Account Lockout Policy > Account lockout threshold
14|Lockout duration at least 15 minutes|net.exe accounts /lockoutduration:30|Uses the toolkit duration, with a floor of 15 minutes.|secpol.msc > Account Policies > Account Lockout Policy > Account lockout duration
15|Reset lockout counter after at least 15 minutes|net.exe accounts /lockoutwindow:30|Sets a reset window of at least 15 minutes and a compatible lockout duration.|secpol.msc > Account Policies > Account Lockout Policy > Reset account lockout counter after
16|Start automatic Windows Update service|Set-Service wuauserv -StartupType Automatic; Start-Service wuauserv|Sets the Windows Update service to Automatic and starts it.|services.msc > Windows Update > Properties > Automatic > Start
17|Enable automatic updates|Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -Value 0|Enables the automatic-update policy; installing updates remains main-menu option 17.|gpedit.msc > Computer Configuration > Administrative Templates > Windows Components > Windows Update
18|Enable Defender real-time protection|Set-MpPreference -DisableRealtimeMonitoring $false|Sets DisableRealtimeMonitoring to 0 and enables live scanning; Tamper Protection can refuse changes.|Windows Security > Virus & threat protection > Manage settings > Real-time protection On
19|Enable unwanted-app blocking|Set-MpPreference -PUAProtection Enabled|Sets MpEnablePus=1 and enables Defender PUA blocking.|Windows Security > App & browser control > Reputation-based protection > Potentially unwanted app blocking
20|Enable cloud-delivered protection|Set-MpPreference -MAPSReporting Advanced|Sets SpynetReporting=2 and enables advanced cloud reporting.|Windows Security > Virus & threat protection > Manage settings > Cloud-delivered protection
21|Enable SmartScreen|Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -Value RequireAdmin|Requires administrator approval for SmartScreen warnings.|Windows Security > App & browser control > Reputation-based protection
22|Enable all firewall profiles|Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True|Uses main option 6 to configure and verify local GPO and effective firewall profiles, including logging.|wf.msc > Windows Defender Firewall Properties > each profile > Firewall state On
23|Block inbound traffic by default|Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block|Uses main option 6; inbound defaults to Block and outbound to Allow.|wf.msc > Properties > each profile > Inbound connections Block
24|Remove malicious EvilAllow firewall rule|Remove-NetFirewallRule -DisplayName EvilAllow|Backs up and removes only rules explicitly named EvilAllow from local stores.|wf.msc > Inbound Rules > EvilAllow > Delete
25|Disable Remote Registry|Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled|Stops and disables remote editing of this PC's registry.|services.msc > Remote Registry > Disabled > Stop
26|Disable Routing and Remote Access|Stop-Service RemoteAccess; Set-Service RemoteAccess -StartupType Disabled|Stops and disables the workstation's routing/VPN service.|services.msc > Routing and Remote Access > Disabled > Stop
27|Disable SSDP Discovery|Stop-Service SSDPSRV; Set-Service SSDPSRV -StartupType Disabled|Stops and disables SSDP/UPnP discovery.|services.msc > SSDP Discovery > Disabled > Stop
28|Remove backdoor service EvilSvc|sc.exe delete EvilSvc|Backs up service metadata, stops/disables EvilSvc, then deletes that service registration; no account is deleted.|services.msc > EvilSvc > Stop/Disable; full removal uses sc.exe delete
29|Disable Xbox Live Auth Manager|Stop-Service XblAuthManager; Set-Service XblAuthManager -StartupType Disabled|Stops and disables the unnecessary Xbox authentication service.|services.msc > Xbox Live Auth Manager > Disabled > Stop
30|Require Remote Desktop NLA|Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1|Requires authentication before an RDP session; does not turn Remote Desktop on.|sysdm.cpl > Remote > require Network Level Authentication
31|Disable SMBv1|Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force|Sets the SMB1 registry switch to 0 and disables SMBv1 on the server.|OptionalFeatures.exe > clear SMB 1.0/CIFS File Sharing Support
32|Disable Telnet Client|Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart|Disables Telnet Client if enabled and defers reboot.|OptionalFeatures.exe > clear Telnet Client
33|Disable LLMNR|Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0|Disables multicast name resolution to reduce credential-theft exposure.|gpedit.msc > Administrative Templates > Network > DNS Client > Turn off multicast name resolution Enabled
34|Disable Windows Script Host|Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name Enabled -Value 0|Blocks Windows Script Host .vbs/.js execution; confirm your README does not require it.|regedit > HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings > Enabled=0
35|Enable UAC|Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Value 1|Enables User Account Control; a reboot may be needed.|Start > Change User Account Control settings
36|Prompt for administrator consent|Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 5|Uses this tutorial's value 5: consent for non-Windows binaries. The main CIS-oriented option uses value 2.|secpol.msc > Local Policies > Security Options > UAC elevation prompt behavior for administrators
37|Disable AutoRun/AutoPlay|Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutoRun -Value 255|Disables AutoRun on all drive types.|gpedit.msc > Windows Components > AutoPlay Policies > Turn off AutoPlay All drives
38|Restrict anonymous enumeration|Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RestrictAnonymous -Value 1|Restricts anonymous enumeration of accounts and shares.|secpol.msc > Local Policies > Security Options > Network access anonymous restrictions
39|Do not store LM hashes|Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name NoLMHash -Value 1|Prevents storing the weak LM password hash on future password changes.|secpol.msc > Local Policies > Security Options > Network security: Do not store LAN Manager hash value Enabled
40|Disable WDigest cleartext credentials|Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -Name UseLogonCredential -Value 0|Stops WDigest retaining reusable cleartext credentials.|regedit > HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest > UseLogonCredential=0
41|Hide last signed-in username|Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DontDisplayLastUserName -Value 1|Hides the previous username on the sign-in screen.|secpol.msc > Local Policies > Security Options > Interactive logon: Don't display last signed-in Enabled
42|Limit blank passwords to console logon|Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LimitBlankPasswordUse -Value 1|Prevents network logons using local accounts with blank passwords.|secpol.msc > Local Policies > Security Options > Accounts: Limit local account use of blank passwords Enabled
43|Audit successful and failed logons|auditpol.exe /set /subcategory:Logon /success:enable /failure:enable|Uses the Logon GUID and saves local GPO as well as effective settings.|secpol.msc > Advanced Audit Policy Configuration > Logon/Logoff > Audit Logon
44|Audit user-account management|auditpol.exe /set /subcategory:"User Account Management" /success:enable /failure:enable|Uses the user-account-management GUID and persists it in local GPO.|secpol.msc > Advanced Audit Policy Configuration > Account Management > Audit User Account Management
45|Audit credential validation|auditpol.exe /set /subcategory:"Credential Validation" /success:enable /failure:enable|Uses the credential-validation GUID and persists it in local GPO.|secpol.msc > Advanced Audit Policy Configuration > Account Logon > Audit Credential Validation
46|Remove malicious scheduled task EvilUpdater|Unregister-ScheduledTask -TaskName EvilUpdater -Confirm:$false|Exports the task XML before removing only tasks named EvilUpdater.|taskschd.msc > Task Scheduler Library > EvilUpdater > Delete
47|Remove malicious Backdoor startup value|Remove-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name Backdoor|Backs up and removes only the Backdoor startup value. Leaves WinUpdater evidence for forensics.|regedit > HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run > Backdoor > Delete
48|Remove prohibited C:\Tools\nc.exe|Move-Item C:\Tools\nc.exe <quarantine>|Moves the file to evidence quarantine outside user folders, preserving its SHA256 and original path.|File Explorer > C:\Tools > nc.exe; this tool quarantines instead of destroying evidence
49|Remove prohibited MP3/MP4/AVI media|Get-ChildItem C:\Users -Recurse -Include *.mp3,*.mp4,*.avi|Previews matches, skips directory junctions, and asks before quarantining files outside C:\Users.|File Explorer > C:\Users > search *.mp3, *.mp4, *.avi; review required files first
50|Remove unauthorized Secret network share|Remove-SmbShare -Name $target -Force|Backs up share metadata and stops sharing Secret; leaves the underlying folder/files intact.|fsmgmt.msc > Shares > Secret > Stop Sharing
'@
    $rows = $catalog | ConvertFrom-Csv -Delimiter '|' -Header Id, Title, Command, Explanation, Gui
    $titles = @{3='Disable an unauthorized account';4='Remove an unauthorized administrator';5='Require a password on an authorized account';6='Require password expiration';7='Create an authorized standard account';24='Remove a malicious inbound firewall rule';28='Remove a confirmed malicious service';46='Remove a malicious scheduled task';47='Remove a malicious startup value';48='Quarantine a prohibited file';49='Review and quarantine prohibited media';50='Remove an unauthorized network share'}
    foreach ($row in $rows) {
        $row.Id = [int]$row.Id
        if ($titles.ContainsKey($row.Id)) { $row.Title = $titles[$row.Id] }
        $row
    }
}

function Get-WarriorTarget {
    param([string]$Prompt, [ValidateSet('Other','Unauthorized','Standard','Authorized')][string]$Role = 'Other')
    $target = (Read-Host "$Prompt (Enter cancels)").Trim()
    if ([string]::IsNullOrWhiteSpace($target)) { throw [OperationCanceledException]::new('No target selected.') }
    if ($target -match '[\r\n]') { throw 'A target must be a single name or path.' }
    if ($Role -ne 'Other' -and $script:WarriorReadmePlan) {
        if ($Role -eq 'Unauthorized' -and $script:WarriorReadmePlan.Users -contains $target) { throw "The current README authorizes $target; it cannot be treated as unauthorized." }
        if ($Role -eq 'Standard' -and $script:WarriorReadmePlan.Admins -contains $target) { throw "The current README authorizes $target as an administrator." }
        if ($Role -eq 'Authorized' -and $script:WarriorReadmePlan.Users -notcontains $target) { throw "$target is not in the current README's approved-account lists." }
    }
    if (-not (Confirm-Action "Use this exact target from the current image: '$target'?" $false)) { throw [OperationCanceledException]::new('Target not confirmed.') }
    $target
}

function Import-WarriorReadmePlan {
    $path = Read-Host "Path to THIS image's README (Enter cancels)"
    if ([string]::IsNullOrWhiteSpace($path)) { return }
    $text = Get-ReadmeText -Path $path
    $lists = Read-AuthorizedLists -Text $text
    if (-not $lists.Admins.Count -and -not $lists.Users.Count) { throw 'No supported authorized-user/admin headings found. Review the README manually; no plan was loaded.' }
    Write-Host ('Authorized admins: ' + ($lists.Admins -join ', '))
    Write-Host ('Authorized accounts: ' + ((@($lists.Admins) + @($lists.Users)) -join ', '))
    if (Confirm-Action 'Are these the complete approved-account lists for the current image?' $false) {
        $script:WarriorReadmePlan = [pscustomobject]@{Source=$path; Admins=@($lists.Admins); Users=@($lists.Admins)+@($lists.Users)}
        Write-Host 'Image account plan loaded. Other targets still require an explicit name/path and confirmation.'
    }
}

function Get-WarriorGroupName {
    param([string]$Sid)
    (Get-LocalGroup -SID $Sid -ErrorAction Stop).Name
}

function Remove-WarriorAdminMembership {
    param([string]$Name)
    if ($Name -eq $script:CurrentUserName) { throw 'This action cannot demote the account running the toolkit.' }
    $user = Get-LocalUser -Name $Name -ErrorAction Stop
    $group = Get-WarriorGroupName 'S-1-5-32-544'
    if (@(Get-LocalGroupMember -Group $group -ErrorAction Stop | Where-Object { $_.SID.Value -eq $user.SID.Value }).Count) {
        Remove-LocalGroupMember -Group $group -Member $user.Name -ErrorAction Stop
    }
}

function Disable-WarriorAccount {
    param([string]$Name, [string]$BuiltinRid)
    $user = if ($BuiltinRid) { Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match "-$BuiltinRid`$" } }
            else { Get-LocalUser -Name $Name -ErrorAction Stop }
    if (-not $user) { Write-Host 'Account is already absent.'; return }
    if ($user.Name -eq $script:CurrentUserName) { throw 'The account running the toolkit cannot be disabled.' }
    if ($user.Enabled) { Disable-LocalUser -Name $user.Name -ErrorAction Stop }
}

function Stop-WarriorService {
    param([string]$Name)
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service) { Write-Host "$Name is already absent."; return }
    Assert-ServiceCanStop $Name
    if ($service.Status -ne 'Stopped') { Stop-Service -Name $Name -Force -ErrorAction Stop }
    Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
}

function Set-WarriorComplexity {
    $work = Join-Path $script:LogDir ('Warrior-Complexity-' + [guid]::NewGuid())
    $null = [IO.Directory]::CreateDirectory($work)
    Invoke-NativeCommand -FilePath secedit.exe -ArgumentList @('/export', '/cfg', (Join-Path $work 'before.inf'), '/quiet') | Out-Null
    $inf = Join-Path $work 'complexity.inf'
    @'
[Unicode]
Unicode=yes
[System Access]
PasswordComplexity = 1
ClearTextPassword = 0
[Version]
signature="$CHICAGO$"
Revision=1
'@ | Set-Content -LiteralPath $inf -Encoding Unicode -ErrorAction Stop
    Invoke-NativeCommand -FilePath secedit.exe -ArgumentList @('/configure', '/db', (Join-Path $work 'policy.sdb'), '/cfg', $inf, '/areas', 'SECURITYPOLICY', '/quiet') | Out-Null
}

function Get-WarriorMediaFiles {
    param([string]$Root = (Join-Path $env:SystemDrive 'Users'))
    $directory = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Select a real directory, not a file or directory link.'
    }
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($Root)
    while ($pending.Count) {
        foreach ($item in (Get-ChildItem -LiteralPath $pending.Pop() -Force -ErrorAction SilentlyContinue)) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
            elseif ($item.Extension -in '.mp3', '.mp4', '.avi') { $item }
        }
    }
}

function Move-WarriorEvidenceFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Write-Host "$Path is already absent."; return }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing to quarantine a filesystem link.' }
    $quarantine = Join-Path $env:ProgramData 'CyberPatriot-Hardening\Quarantine'
    $null = [IO.Directory]::CreateDirectory($quarantine)
    $target = Join-Path $quarantine ([guid]::NewGuid().ToString() + '-' + $item.Name)
    $record = [pscustomobject]@{OriginalPath=$item.FullName; QuarantinedPath=$target; SHA256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash; TimeUTC=[datetime]::UtcNow.ToString('o')}
    Move-Item -LiteralPath $item.FullName -Destination $target -ErrorAction Stop
    $record | Export-Csv -LiteralPath (Join-Path $quarantine 'manifest.csv') -NoTypeInformation -Encoding UTF8 -Append -ErrorAction Stop
    Write-Host "Quarantined: $($record.OriginalPath) -> $target"
}

function Invoke-WarriorTaskAction {
    param([ValidateRange(1,50)][int]$Id)
    if((Test-ToolkitDomainController) -and ($Id -in 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)){throw 'Use option 26 for AD accounts/domain password policy on a domain controller.'}
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $system = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    switch ($Id) {
        1 { Disable-WarriorAccount -BuiltinRid '501' }
        2 { Disable-WarriorAccount -BuiltinRid '500' }
        3 { $name = Get-WarriorTarget 'Unauthorized local username to DISABLE' Unauthorized; Disable-WarriorAccount -Name $name; if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) { Remove-WarriorAdminMembership -Name $name } }
        4 { Remove-WarriorAdminMembership -Name (Get-WarriorTarget 'Standard user who should not be an administrator' Standard) }
        5 {
            $name = Get-WarriorTarget 'Authorized account requiring a new password' Authorized
            Set-LocalUser -Name $name -Password (Get-DefaultAccountPassword) -ErrorAction Stop
            Invoke-NativeCommand -FilePath net.exe -ArgumentList @('user', $name, '/passwordreq:yes') | Out-Null
        }
        6 { Set-LocalUser -Name (Get-WarriorTarget 'Authorized account whose password must expire' Authorized) -PasswordNeverExpires $false -ErrorAction Stop }
        7 {
            $name = Get-WarriorTarget 'Authorized standard account to create or reconcile' Authorized
            if ($name -eq $script:CurrentUserName -or ($script:WarriorReadmePlan -and $script:WarriorReadmePlan.Admins -contains $name)) {
                throw 'This account is the current user or an approved administrator; it cannot be reconciled as a standard user.'
            }
            if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) {
                New-LocalUser -Name $name -Password (Get-DefaultAccountPassword) -PasswordNeverExpires:$false -ErrorAction Stop | Out-Null
            }
            $group = Get-WarriorGroupName 'S-1-5-32-545'
            $user = Get-LocalUser -Name $name -ErrorAction Stop
            if (-not @(Get-LocalGroupMember -Group $group -ErrorAction Stop | Where-Object { $_.SID.Value -eq $user.SID.Value }).Count) {
                Add-LocalGroupMember -Group $group -Member $name -ErrorAction Stop
            }
            Remove-WarriorAdminMembership -Name $name
        }
        8 { Invoke-NativeCommand net.exe @('accounts', "/minpwlen:$([Math]::Max(12,$PwMinLen))") | Out-Null }
        9 { Set-WarriorComplexity }
        10 { Invoke-NativeCommand net.exe @('accounts', "/maxpwage:$(if($PwMaxAge -gt 0){[Math]::Min(90,$PwMaxAge)}else{90})") | Out-Null }
        11 { Invoke-NativeCommand net.exe @('accounts', "/minpwage:$([Math]::Max(1,$PwMinAge))") | Out-Null }
        12 { Invoke-NativeCommand net.exe @('accounts', "/uniquepw:$([Math]::Max(10,$PwHistory))") | Out-Null }
        13 { Invoke-NativeCommand net.exe @('accounts', "/lockoutthreshold:$(if($LockThreshold -gt 0){[Math]::Min(5,$LockThreshold)}else{5})") | Out-Null }
        14 { Invoke-NativeCommand net.exe @('accounts', "/lockoutduration:$([Math]::Max(15,$LockDuration))") | Out-Null }
        15 {
            $window = [Math]::Max(15,$LockWindow)
            Invoke-NativeCommand net.exe @('accounts', "/lockoutduration:$([Math]::Max($window,$LockDuration))") | Out-Null
            Invoke-NativeCommand net.exe @('accounts', "/lockoutwindow:$window") | Out-Null
        }
        16 { Set-Service wuauserv -StartupType Automatic -ErrorAction Stop; Start-Service wuauserv -ErrorAction Stop }
        17 { Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' NoAutoUpdate 0 }
        18 { Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' DisableRealtimeMonitoring 0; Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop }
        19 { Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine' MpEnablePus 1; Set-MpPreference -PUAProtection Enabled -ErrorAction Stop }
        20 { Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' SpynetReporting 2; Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop }
        21 { Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' SmartScreenEnabled RequireAdmin String }
        { $_ -in 22,23 } { Enable-WindowsFirewall }
        24 {
            $target = Get-WarriorTarget 'Exact display name of the malicious firewall rule'
            foreach ($store in 'PersistentStore', 'localhost') {
                $rules = @(Get-NetFirewallRule -PolicyStore $store -ErrorAction Stop | Where-Object DisplayName -eq $target)
                if ($rules.Count) {
                    $rules | Export-Clixml -LiteralPath (Join-Path $script:LogDir ("Removed-rule-$store-" + [guid]::NewGuid() + '.clixml')) -ErrorAction Stop
                    foreach ($rule in $rules) { Remove-NetFirewallRule -PolicyStore $store -Name $rule.Name -ErrorAction Stop }
                }
            }
        }
        25 { Stop-WarriorService RemoteRegistry }
        26 { Stop-WarriorService RemoteAccess }
        27 { Stop-WarriorService SSDPSRV }
        28 {
            $target = Get-WarriorTarget 'Exact service name (not display name) confirmed malicious'
            $service = Get-Service -ErrorAction Stop | Where-Object Name -eq $target
            if ($service) {
                Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object Name -eq $target | Export-Clixml -LiteralPath (Join-Path $script:LogDir ('Removed-service-' + [guid]::NewGuid() + '.clixml')) -ErrorAction Stop
                Stop-WarriorService $target
                Invoke-NativeCommand sc.exe @('delete', $target) | Out-Null
            }
        }
        29 { Stop-WarriorService XblAuthManager }
        30 { Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication 1 }
        31 { Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' SMB1 0; Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop }
        32 {
            if(Test-ToolkitServer){
                $feature=Get-WindowsFeature -Name Telnet-Client -ErrorAction Stop
                if($feature -and $feature.Installed){Uninstall-WindowsFeature -Name Telnet-Client -Restart:$false -ErrorAction Stop | Out-Host;if((Get-WindowsFeature -Name Telnet-Client -ErrorAction Stop).Installed){throw 'Telnet removal not verified.'}}
                break
            }
            if ((Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction Stop).State -eq 'Enabled') {
                Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart -ErrorAction Stop | Out-Null
            }
        }
        33 { Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast 0 }
        34 { Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' Enabled 0 }
        35 { Set-RegistryValue $system EnableLUA 1 }
        36 { Set-RegistryValue $system ConsentPromptBehaviorAdmin 5 }
        37 { Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoDriveTypeAutoRun 255 }
        38 { Set-RegistryValue $lsa RestrictAnonymous 1 }
        39 { Set-RegistryValue $lsa NoLMHash 1 }
        40 { Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 0 }
        41 { Set-RegistryValue $system DontDisplayLastUserName 1 }
        42 { Set-RegistryValue $lsa LimitBlankPasswordUse 1 }
        43 { Enable-Auditing -SubcategoryGuid '0cce9215-69ae-11d9-bed3-505054503030' }
        44 { Enable-Auditing -SubcategoryGuid '0cce9235-69ae-11d9-bed3-505054503030' }
        45 { Enable-Auditing -SubcategoryGuid '0cce923f-69ae-11d9-bed3-505054503030' }
        46 {
            $target = Get-WarriorTarget 'Exact scheduled task name confirmed malicious'
            $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object TaskName -eq $target)
            if ($tasks.Count -gt 1) {
                $tasks | Select-Object TaskName, TaskPath | Format-Table | Out-Host
                $taskPath = Get-WarriorTarget 'Exact TaskPath of the one task to remove'
                $tasks = @($tasks | Where-Object TaskPath -eq $taskPath)
            }
            foreach ($task in $tasks) {
                Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Set-Content -LiteralPath (Join-Path $script:LogDir ('Removed-task-' + [guid]::NewGuid() + '.xml')) -Encoding UTF8 -ErrorAction Stop
                Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
            }
        }
        47 {
            $target = Get-WarriorTarget 'Exact HKLM Run value name confirmed malicious'
            $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            $value = (Get-ItemProperty -LiteralPath $path -ErrorAction Stop).PSObject.Properties[$target]
            if ($value) {
                [pscustomobject]@{Path=$path; Name=$target; Value=$value.Value} | Export-Clixml -LiteralPath (Join-Path $script:LogDir ('Removed-startup-' + [guid]::NewGuid() + '.clixml')) -ErrorAction Stop
                Remove-ItemProperty -LiteralPath $path -Name $target -ErrorAction Stop
            }
        }
        48 { Move-WarriorEvidenceFile -Path (Get-WarriorTarget 'Full path to the prohibited file confirmed by the README') }
        49 {
            $root = Get-WarriorTarget 'Full folder path to search for prohibited MP3/MP4/AVI media'
            $files = @(Get-WarriorMediaFiles -Root $root)
            if ($files.Count) {
                $files | Select-Object FullName, Length | Format-Table -AutoSize | Out-Host
                if (Confirm-Action "Quarantine these $($files.Count) files? Required media must be excluded manually by choosing No." $false) {
                    foreach ($file in $files) { Move-WarriorEvidenceFile -Path $file.FullName }
                }
            }
            else { Write-Host 'No matching media files found.' }
        }
        50 {
            $target = Get-WarriorTarget 'Exact share name declared unauthorized by this image'
            if($target -in 'SYSVOL','NETLOGON'){throw 'Required domain shares cannot be removed by this workflow.'}
            $share = Get-SmbShare -ErrorAction Stop | Where-Object Name -eq $target
            if ($share) {
                $share | Export-Clixml -LiteralPath (Join-Path $script:LogDir ('Removed-share-' + [guid]::NewGuid() + '.clixml')) -ErrorAction Stop
                Remove-SmbShare -Name $target -Force -ErrorAction Stop
            }
        }
    }
}

function Invoke-WarriorTask {
    param([ValidateRange(1,50)][int]$Id, [switch]$ReportOnly)
    $task = Get-WarriorTasks | Where-Object Id -eq $Id
    Write-Section "Windows Warrior task $Id - $($task.Title)"
    Write-Host 'The commands below illustrate the Windows Warrior example. Actual image-specific names/paths are requested separately, with no default target.'
    Write-Host $task.Explanation
    Write-Host "PowerShell example: $($task.Command)" -ForegroundColor Cyan
    Write-Host "GUI: $($task.Gui)" -ForegroundColor Yellow
    if ($ReportOnly -or -not (Confirm-Action 'Apply this task now?' $false)) { return }
    $regBefore = $script:RegFail; $failureBefore = $script:FailureCount
    try {
        Invoke-WarriorTaskAction -Id $Id
        if ($script:RegFail -gt $regBefore -or $script:FailureCount -gt $failureBefore) {
            throw 'The action reported errors; review them above.'
        }
        Write-Ok 'Action finished. Check the Scoring Report after its next refresh; this tool does not award or guarantee points.'
    }
    catch [OperationCanceledException] { Write-Warn "Task $Id cancelled." }
    catch { Write-Bad "Task $Id failed: $($_.Exception.Message)" }
}

function Convert-ForensicCipher {
    param([string]$Text,[ValidateSet('ReverseRot13','Reverse','Rot13','Atbash')][string]$Method='ReverseRot13')
    $characters=$Text.ToCharArray()
    if($Method -in 'ReverseRot13','Reverse'){[Array]::Reverse($characters)}
    $output=New-Object Text.StringBuilder
    foreach($character in $characters) {
        $code=[int]$character
        $start=if($code -ge 65 -and $code -le 90){65}elseif($code -ge 97 -and $code -le 122){97}else{-1}
        if($start -ge 0 -and $Method -in 'ReverseRot13','Rot13'){$code=$start+(($code-$start+13)%26)}
        elseif($start -ge 0 -and $Method -eq 'Atbash'){$code=$start+25-($code-$start)}
        $null=$output.Append([char]$code)
    }
    $output.ToString()
}

function Read-NetstatListeners {
    param([string]$Text)
    foreach($line in ($Text -split '\r?\n')) {
        if($line -match '^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)\s*$') {
            [pscustomobject]@{LocalAddress=$Matches[1];LocalPort=[int]$Matches[2];OwningProcess=[uint32]$Matches[3]}
        }
    }
}

function Get-SystemListenerFinding {
    param([object[]]$Connections,[string]$Source='current live TCP listeners')
    $system=@($Connections | Where-Object {[uint32]$_.OwningProcess -eq 4})
    $all=@($system.LocalPort | Sort-Object -Unique)
    $other=@($all | Where-Object {$_ -ne 445})
    $answer='';$status='Review required'
    if($other.Count -eq 1){$answer=[string]$other[0];$status='Observed'}
    $detail="Source: $Source. Observed PID 4 TCP listener ports: $($all -join ', ')."
    if(-not $other.Count){$detail+=' No other port besides 445 was observed. Do not infer 139 or reconstruct the original image state from this output.'}
    elseif($other.Count -gt 1){$detail+=' Multiple other ports are present; match the evidence to the actual question.'}
    [pscustomobject]@{Topic='System TCP port besides 445';Status=$status;SuggestedAnswer=$answer;Evidence=$detail}
}

function Save-PreHardeningNetworkSnapshot {
    try {
        $connections=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object LocalAddress,LocalPort,OwningProcess)
        $script:PreHardeningNetworkSnapshot=[pscustomobject]@{CapturedAtUtc=[datetime]::UtcNow.ToString('o');Connections=$connections}
        $file=Join-Path $script:LogDir ('Network-before-this-run-'+[guid]::NewGuid()+'.json')
        $script:PreHardeningNetworkSnapshot | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $file -Encoding UTF8 -ErrorAction Stop
        Write-Host "Read-only network snapshot saved before this run's hardening: $file"
    }
    catch {Write-Warn "Could not capture pre-hardening TCP evidence: $($_.Exception.Message)"}
}

function Get-WarriorForensicFindings {
    param([string]$ScheduledTaskName = '', [string]$StartupValueName = '')
    $results = New-Object 'System.Collections.Generic.List[object]'
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $results.Add([pscustomobject]@{Topic='Windows build'; Status='Observed'; SuggestedAnswer=[string]$os.BuildNumber; Evidence="Win32_OperatingSystem: $($os.Caption), build $($os.BuildNumber)"})
    } catch { $results.Add([pscustomobject]@{Topic='Windows build'; Status='Unavailable'; SuggestedAnswer=''; Evidence=$_.Exception.Message}) }
    try {
        if ($ScheduledTaskName) {
            $task = @(Get-ScheduledTask -ErrorAction Stop | Where-Object TaskName -eq $ScheduledTaskName)
            if ($task.Count -ne 1) { throw 'The requested task was absent or not unique; inspect TaskPath manually.' }
            $actions = @($task[0].Actions)
            $answer = if ($actions.Count -eq 1) { [string]$actions[0].Execute } else { 'Multiple task actions; review evidence' }
            $results.Add([pscustomobject]@{Topic='Scheduled task execution'; Status='Observed'; SuggestedAnswer=$answer; Evidence=($actions | Select-Object Execute, Arguments, WorkingDirectory | Format-List | Out-String)})
        }
        else {
            $inventory = Get-ScheduledTask -ErrorAction Stop | Select-Object TaskName, TaskPath, @{Name='Executables';Expression={($_.Actions.Execute -join '; ')}}
            $results.Add([pscustomobject]@{Topic='Scheduled task execution'; Status='Review required'; SuggestedAnswer="Select the task named in this image's question."; Evidence=($inventory | Format-Table -AutoSize | Out-String -Width 240)})
        }
    } catch { $results.Add([pscustomobject]@{Topic='Scheduled task execution'; Status='Unavailable'; SuggestedAnswer=''; Evidence=$_.Exception.Message}) }
    try {
        $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        if ($StartupValueName) {
            $value = (Get-ItemProperty -LiteralPath $path -Name $StartupValueName -ErrorAction Stop).($StartupValueName)
            if ([string]::IsNullOrWhiteSpace([string]$value)) { throw 'Requested startup value is absent or empty; no answer inferred.' }
            $results.Add([pscustomobject]@{Topic='Startup registry'; Status='Observed'; SuggestedAnswer=[string]$value; Evidence="$path : $StartupValueName = $value"})
        }
        else {
            $inventory = (Get-ItemProperty -LiteralPath $path -ErrorAction Stop).PSObject.Properties | Where-Object Name -notlike 'PS*' | Select-Object Name, Value
            $results.Add([pscustomobject]@{Topic='Startup registry'; Status='Review required'; SuggestedAnswer='Identify the startup value requested by this image.'; Evidence=($inventory | Format-Table -AutoSize | Out-String -Width 240)})
        }
    } catch { $results.Add([pscustomobject]@{Topic='Startup registry'; Status='Unavailable'; SuggestedAnswer=''; Evidence=$_.Exception.Message}) }
    try {
        $ports = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Sort-Object LocalPort, OwningProcess -Unique | ForEach-Object {
            $owner = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [pscustomobject]@{LocalAddress=$_.LocalAddress; Port=$_.LocalPort; PID=$_.OwningProcess; Process=$owner.ProcessName; Path=$owner.Path}
        })
        $results.Add([pscustomobject]@{Topic='Listening ports'; Status='Review required'; SuggestedAnswer='Identify the unexpected listener from its process and path; high ports alone are not proof.'; Evidence=($ports | Format-Table -AutoSize | Out-String -Width 240)})
    } catch { $results.Add([pscustomobject]@{Topic='Listening ports'; Status='Unavailable'; SuggestedAnswer=''; Evidence=$_.Exception.Message}) }
    try {
        $connections=@(Get-NetTCPConnection -State Listen -ErrorAction Stop)
        $results.Add((Get-SystemListenerFinding -Connections $connections))
        if($script:PreHardeningNetworkSnapshot) {
            $prior=Get-SystemListenerFinding -Connections $script:PreHardeningNetworkSnapshot.Connections -Source ("snapshot before this run at "+$script:PreHardeningNetworkSnapshot.CapturedAtUtc+'; not proof of an untouched original image')
            $prior.Topic='System TCP listeners before this run'
            $results.Add($prior)
        }
    } catch { $results.Add([pscustomobject]@{Topic='System TCP port besides 445';Status='Unavailable';SuggestedAnswer='';Evidence=$_.Exception.Message}) }
    try {
        $shares=@(Get-SmbShare -ErrorAction Stop)
        $observed=@($shares | Where-Object Name -eq 'IPC$').Count -eq 1
        $results.Add([pscustomobject]@{Topic='Default IPC administrative share';Status=if($observed){'Observed'}else{'Reference; not observed'};SuggestedAnswer='IPC$';Evidence=('IPC$ is the standard IPC share used alongside C$ and ADMIN$. Shares on this host: '+($shares.Name -join ', '))})
    } catch { $results.Add([pscustomobject]@{Topic='Default IPC administrative share';Status='Reference; host inventory unavailable';SuggestedAnswer='IPC$';Evidence='IPC$ is the standard IPC share. '+$_.Exception.Message}) }
    $results
}

function Invoke-WarriorForensics {
    Write-Section 'Read-only forensics helpers for the current image'
    Write-Host 'These investigation topics do not assume question numbering. Match observed evidence and reference facts to your actual question files.'
    $question = Read-Host 'Path to an actual forensics question file to read (Enter skips)'
    if (-not [string]::IsNullOrWhiteSpace($question)) {
        Write-Host (Get-ReadmeText -Path $question)
    }
    $task = Read-Host 'Exact scheduled task name requested by your question (Enter inventories tasks)'
    $startup = Read-Host 'Exact HKLM Run value requested by your question (Enter inventories startup values)'
    $results = @(Get-WarriorForensicFindings -ScheduledTaskName $task -StartupValueName $startup)
    $cipher=Read-Host 'Cipher text to transform (Enter skips)'
    if(-not [string]::IsNullOrWhiteSpace($cipher)) {
        $method=Read-Host '1 reverse+ROT13, 2 reverse only, 3 ROT13 only, 4 Atbash; Enter skips'
        $methods=@{'1'='ReverseRot13';'2'='Reverse';'3'='Rot13';'4'='Atbash'}
        if($methods.ContainsKey($method)) {
            $results += [pscustomobject]@{Topic='Cipher transformation';Status='Computed; review selected method';SuggestedAnswer=(Convert-ForensicCipher -Text $cipher -Method $methods[$method]);Evidence=("Selected method: "+$methods[$method]+"; input: "+$cipher)}
        }
    }
    $report = Join-Path $script:LogDir ('Windows-Warrior-Forensics-' + [guid]::NewGuid() + '.txt')
    $text = $results | Format-List Topic, Status, SuggestedAnswer, Evidence | Out-String -Width 240
    Write-Host $text
    $text | Set-Content -LiteralPath $report -Encoding UTF8 -ErrorAction Stop
    Write-Host "Evidence report: $report"
    Write-Host 'Review the evidence, enter answers after ANSWER: in the original Desktop question files, and save them. This helper never submits or edits answers.'
}

function Invoke-ImageGroupPlan {
    if(Test-ToolkitDomainController){Invoke-ServerAdGroupPlan;return}
    Write-Section 'Current image - group membership plan'
    $name = Get-WarriorTarget 'Exact local group required by the current README'
    $members = @((Read-Host 'Authorized local usernames for this group, comma separated') -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if (-not $members.Count) { throw [OperationCanceledException]::new('No members supplied; group unchanged.') }
    $users = @($members | ForEach-Object { Get-LocalUser -Name $_ -ErrorAction Stop })
    if ($users.Count -ne $members.Count) { throw 'Every requested member must resolve to an existing local account.' }
    $group = Get-LocalGroup -ErrorAction Stop | Where-Object Name -eq $name
    if ($group -and $group.SID.Value -eq 'S-1-5-32-544' -and $script:WarriorReadmePlan) {
        foreach ($user in $users) {
            if ($script:WarriorReadmePlan.Admins -notcontains $user.Name) { throw "$($user.Name) is not an authorized administrator in this image's README." }
        }
    }
    $current = if ($group) { @(Get-LocalGroupMember -Group $name -ErrorAction Stop) } else { @() }
    $adds = @($users | Where-Object { $current.SID.Value -notcontains $_.SID.Value })
    $match = Confirm-Action 'Also remove other local user members so this group matches the supplied list?' $false
    $localSids = @((Get-LocalUser -ErrorAction Stop).SID.Value)
    $removes = @($current | Where-Object { $match -and $localSids -contains $_.SID.Value -and $users.SID.Value -notcontains $_.SID.Value -and $_.Name.Split('\')[-1] -ne $script:CurrentUserName })
    Write-Host "Group: $name; create: $(-not [bool]$group)"
    Write-Host ('Add: ' + ($adds.Name -join ', '))
    Write-Host ('Remove membership only: ' + ($removes.Name -join ', '))
    if (-not (Confirm-Action 'Apply this group plan?' $false)) { return }
    if (-not $group) { New-LocalGroup -Name $name -ErrorAction Stop | Out-Null }
    foreach ($user in $adds) { Add-LocalGroupMember -Group $name -Member $user.Name -ErrorAction Stop }
    foreach ($user in $removes) { Remove-LocalGroupMember -Group $name -Member $user.Name -ErrorAction Stop }
    Write-Ok 'Group plan applied. Accounts were preserved.'
}

function Invoke-ImageAppAction {
    Write-Section 'Current image - select an installed app'
    $winget = Get-Command winget.exe -CommandType Application -ErrorAction Stop
    Invoke-NativeCommand -FilePath $winget.Source -ArgumentList @('list', '--accept-source-agreements', '--disable-interactivity') | Out-Host
    $id = Get-WarriorTarget 'Exact package ID from the installed-app list'
    $action = Read-Host '[U]pdate this app, [R]emove this app because the README prohibits it, or Enter to cancel'
    if ($action -notmatch '^[uUrR]$') { return }
    if (-not (Confirm-Action "Apply '$action' to this exact package ID: $id?" $false)) { return }
    [pscustomobject]@{PackageId=$id; Action=$action; TimeUTC=[datetime]::UtcNow.ToString('o')} |
        Export-Clixml -LiteralPath (Join-Path $script:LogDir ('App-action-' + [guid]::NewGuid() + '.clixml')) -ErrorAction Stop
    if ($action -match '^[uU]$') {
        Invoke-NativeCommand -FilePath $winget.Source -ArgumentList @('upgrade','--id',$id,'--exact','--silent','--accept-package-agreements','--accept-source-agreements','--disable-interactivity') | Out-Host
    }
    else {
        Invoke-NativeCommand -FilePath $winget.Source -ArgumentList @('uninstall','--id',$id,'--exact','--silent','--accept-source-agreements','--disable-interactivity') | Out-Host
    }
    Write-Ok 'Selected app command completed. Review its output and the image requirements.'
}

function Get-GlobalAuditArguments {
    param([ValidateSet('File','Key')][string]$Type, [ValidatePattern('^S-\d-(\d+-)*\d+$')][string]$Sid, [ValidateSet('Read','Write','Both')][string]$Access)
    $prefix = if ($Type -eq 'File') { 'F' } else { 'K' }
    $mask = if ($Access -eq 'Read') { $prefix+'R' } elseif ($Access -eq 'Write') { $prefix+'W' } else { $prefix+'R'+$prefix+'W' }
    @('/resourceSACL','/set',"/type:$Type","/user:{$Sid}",'/success','/failure',"/access:$mask")
}

function Set-GlobalObjectAuditing {
    Write-Section 'Global Object Access Auditing - explicit opt-in'
    Write-Host 'These rules affect access by the selected account across all files and/or registry keys. They are separate from the local GPO audit subcategory definitions.'
    $kind = Read-Host '[F]iles, [R]egistry, [B]oth, or Enter to cancel'
    if ($kind -notmatch '^[fFrRbB]$') { return }
    $account = Read-Host 'Account (DOMAIN\name), group, or SID to audit; Enter cancels'
    if ([string]::IsNullOrWhiteSpace($account)) { return }
    try {
        $sid = if ($account -match '^S-\d-') { (New-Object Security.Principal.SecurityIdentifier($account)).Value }
               else { (New-Object Security.Principal.NTAccount($account)).Translate([Security.Principal.SecurityIdentifier]).Value }
        $access = Read-Host '[R]ead, [W]rite, or [B]oth (Enter cancels)'
        if ($access -notmatch '^[rRwWbB]$') { return }
        if (-not (Confirm-Action "Enable Success and Failure auditing for $account ($sid) with the selected scope?" $false)) { return }
        $types = if ($kind -match '^[fF]$') { @('File') } elseif ($kind -match '^[rR]$') { @('Key') } else { @('File','Key') }
        $backup = Join-Path $script:LogDir ('Global-Object-Audit-' + [guid]::NewGuid() + '.txt')
        Invoke-NativeCommand auditpol.exe @('/resourceSACL', '/view') | Set-Content -LiteralPath $backup -Encoding UTF8 -ErrorAction Stop
        foreach ($type in $types) {
            $guid = if ($type -eq 'File') { '0cce921d-69ae-11d9-bed3-505054503030' } else { '0cce921e-69ae-11d9-bed3-505054503030' }
            $before = $script:FailureCount
            Enable-Auditing -SubcategoryGuid $guid
            if ($script:FailureCount -gt $before) { throw 'The required audit subcategory could not be configured.' }
            $rights = if ($access -match '^[rR]$') { 'Read' } elseif ($access -match '^[wW]$') { 'Write' } else { 'Both' }
            Invoke-NativeCommand auditpol.exe @(Get-GlobalAuditArguments -Type $type -Sid $sid -Access $rights) | Out-Null
            Invoke-NativeCommand auditpol.exe @('/resourceSACL','/view',"/type:$type","/user:{$sid}") | Out-Host
        }
        Write-Ok "Global access audit entries applied to the live system. Previous entries: $backup"
        Write-Host 'These resource-SACL entries are not written to the local GPO definition. A domain/global-object policy can replace them; verify with auditpol /resourceSACL /view.'
    }
    catch { Write-Bad "Global object auditing failed: $($_.Exception.Message)" }
}

function Invoke-WindowsWarrior {
    do {
        Write-Section 'Guided hardening - 50 example tasks and forensics helpers'
        if ($script:WarriorReadmePlan) { Write-Host "Current image README: $($script:WarriorReadmePlan.Source)" }
        else { Write-Host 'No image README loaded. Choose R to load approved user/admin lists before account changes.' }
        Get-WarriorTasks | Format-Table Id, Title -AutoSize | Out-Host
        Write-Host 'Task 1-50; R load current README; F forensics; M group membership; P apps; A guided tasks; G global audit; 0 back.'
        Write-Host 'Task 3 disables the selected unauthorized account; it never deletes it. A grader requiring deletion may leave that item incomplete.'
        $choice = Read-Host 'Choice'
        if ($choice -eq '0') { return }
        elseif ($choice -match '^r$') { try { Import-WarriorReadmePlan } catch { Write-Bad $_.Exception.Message } }
        elseif ($choice -match '^m$') { try { Invoke-ImageGroupPlan } catch { Write-Bad $_.Exception.Message } }
        elseif ($choice -match '^p$') { try { Invoke-ImageAppAction } catch { Write-Bad $_.Exception.Message } }
        elseif ($choice -match '^f$') { Invoke-WarriorForensics; Wait-Key }
        elseif ($choice -match '^g$') { Set-GlobalObjectAuditing; Wait-Key }
        elseif ($choice -match '^a$') {
            if (Confirm-Action 'Have you saved forensics evidence and reviewed the README requirements before making changes?' $false) {
                foreach ($task in Get-WarriorTasks) { Invoke-WarriorTask -Id $task.Id }
            }
        }
        elseif ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le 50) { Invoke-WarriorTask -Id ([int]$choice); Wait-Key }
        else { Write-Warn 'Choose 1-50, R, F, M, P, A, G, or 0.' }
    } while ($true)
}


#Requires -Version 5.1
<# Server 2022 and image-specific service/account helpers. Declarations only. #>
function Get-ToolkitPlatform {
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $server=[int]$os.ProductType -in 2,3
    $roles=@();$known=-not $server
    if($server -and (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) {
        try {$roles=@(Get-WindowsFeature -ErrorAction Stop | Where-Object Installed | ForEach-Object Name);$known=$true}
        catch {Write-Warn "Server role discovery failed: $($_.Exception.Message)"}
    }
    $autoLogin=$null
    try {
        $key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        if((Get-ItemPropertyValue -LiteralPath $key -Name AutoAdminLogon -ErrorAction SilentlyContinue) -eq '1') {
            # Read names only. Never read DefaultPassword or other stored credentials.
            $autoLogin=Get-ItemPropertyValue -LiteralPath $key -Name DefaultUserName -ErrorAction SilentlyContinue
        }
    } catch {}
    [pscustomobject]@{Caption=$os.Caption;Build=[int]$os.BuildNumber;IsServer=$server;IsServer2022=($server -and [int]$os.BuildNumber -eq 20348);IsDomainController=([int]$os.ProductType -eq 2 -or [int]$computer.DomainRole -in 4,5);DomainJoined=[bool]$computer.PartOfDomain;Domain=[string]$computer.Domain;ComputerName=[string]$computer.Name;Roles=$roles;RolesKnown=$known;AutoLogonUser=$autoLogin}
}

function Test-ToolkitServer { [bool]($script:ToolkitPlatform -and $script:ToolkitPlatform.IsServer) }
function Test-ToolkitDomainController { [bool]($script:ToolkitPlatform -and $script:ToolkitPlatform.IsDomainController) }
function Assert-LocalAccountWorkflow {
    if(Test-ToolkitDomainController){throw 'This is a domain controller. Use option 26 for targeted Active Directory accounts and domain policy; local SAM operations are unavailable.'}
}

function Test-PasswordProtectedAccount {
    param([string]$Name)
    $short=$Name.Split('\')[-1]
    ($script:ToolkitPlatform -and $script:ToolkitPlatform.AutoLogonUser -and $script:ToolkitPlatform.AutoLogonUser.Split('\')[-1] -ieq $short) -or
    ($script:ServerImageRules -and $script:ServerImageRules.PrimaryAccount -and $script:ServerImageRules.PrimaryAccount -ieq $short)
}

function Get-ServerServiceBlockReason {
    param([string]$Name)
    if($Name -ieq 'CSSClient'){return 'The competition README prohibits stopping CSSClient.'}
    if($script:ServerImageRules -and $script:ServerImageRules.RequiredServices -contains $Name){return 'This service is required by the current README.'}
    if(-not (Test-ToolkitServer)){return ''}
    if(-not $script:ToolkitPlatform.RolesKnown){return 'Installed server roles could not be determined; service stops are blocked until role discovery succeeds.'}
    $protected=@('RpcSs','DcomLaunch','SamSs','EventLog','Schedule','BFE','mpssvc','LanmanWorkstation','WinRM')
    if($script:ToolkitPlatform.DomainJoined){$protected+=@('Netlogon','Dnscache','W32Time')}
    if(Test-ToolkitDomainController){$protected+=@('NTDS','Kdc','Netlogon','DFSR','ADWS','LanmanServer')}
    $map=@{
        'AD-Domain-Services'=@('NTDS','Kdc','Netlogon','DFSR','ADWS')
        'DNS'=@('DNS');'DHCP'=@('DHCPServer');'AD-Certificate'=@('CertSvc')
        'Web-Server'=@('W3SVC','WAS','IISADMIN','AppHostSvc');'FS-FileServer'=@('LanmanServer')
        'Hyper-V'=@('vmms','vmcompute','hns');'RemoteAccess'=@('RemoteAccess','RaMgmtSvc','SstpSvc','IKEEXT','PolicyAgent')
        'NPAS'=@('IAS');'ADFS-Federation'=@('adfssrv')
    }
    foreach($role in $map.Keys){if($script:ToolkitPlatform.Roles -contains $role){$protected+=$map[$role]}}
    if($script:ToolkitPlatform.Roles -contains 'ADLDS' -and $Name -like 'ADAM_*'){return 'This service is an installed AD LDS instance.'}
    if(@($script:ToolkitPlatform.Roles | Where-Object {$_ -like 'RDS-*'}).Count){$protected+=@('TermService','SessionEnv','UmRdpService','RDMS','Tssdis','TSGateway','TScPubRPC')}
    if($env:SESSIONNAME -like 'RDP-*'){$protected+=@('TermService','SessionEnv','UmRdpService')}
    if($protected -contains $Name){return 'This service supports the OS, domain, installed roles, or the active RDP session.'}
    ''
}

function Assert-ServiceCanStop {
    param([string]$Name)
    $reason=Get-ServerServiceBlockReason $Name
    if($reason){throw "$Name cannot be stopped by this workflow: $reason"}
    $service=Get-Service -Name $Name -ErrorAction Stop
    foreach($dependent in @($service.DependentServices)) {
        if($dependent.Status -eq 'Running') {
            $reason=Get-ServerServiceBlockReason $dependent.Name
            if($reason){throw "Stopping $Name would stop protected dependent service $($dependent.Name): $reason"}
        }
    }
}

function Read-ServerImageRules {
    param([string]$Text,[string]$Source='current README')
    $required=New-Object 'System.Collections.Generic.List[string]'
    $map=@{'AD DS'='NTDS';'DNS'='DNS';'RDP'='TermService';'SSH'='sshd'}
    $section=[regex]::Match($Text,'(?is)Critical Services\s*:\s*(.*?)(?:User Auditing|Competition Guidelines|The (?:Town|company) has|\z)').Groups[1].Value
    foreach($label in $map.Keys){if($section -match ('(?im)^\s*'+[regex]::Escape($label)+'\s*$')){$required.Add($map[$label])}}
    if($Text -match '(?i)do not disable or stop (?:the )?CSSClient'){$required.Add('CSSClient')}
    $port=$null
    $match=[regex]::Match($Text,'(?i)port\s+(\d{1,5})\s+as the port for SSH')
    if($match.Success){$port=[int]$match.Groups[1].Value;if($port -lt 1 -or $port -gt 65535){throw 'README SSH port is invalid.'}}
    $primary=$null
    $match=[regex]::Match($Text,'(?i)primary[^\r\n]*auto-login[^\r\n]*user account\s*\(([A-Za-z0-9._-]+)\)')
    if($match.Success){$primary=$match.Groups[1].Value}
    $admins=New-Object 'System.Collections.Generic.List[string]';$mode=$false
    foreach($line in ($Text -split '\r?\n')) {
        $value=$line.Trim()
        if($value -match '^Domain Admins\s*:'){$mode=$true;continue}
        if(-not $mode -or -not $value -or $value -match '^(password|pass|pw)\s*:'){continue}
        if($value -match '^([A-Za-z0-9._-]+)(?:\s*\(you\))?$'){$admins.Add($Matches[1])}
        else{$mode=$false}
    }
    $town=@();$coven=@()
    foreach($alignment in 'Town','Coven') {
        $pattern='(?is)(?:UN)?AUTHORIZED '+$alignment+' roles\s*:\s*(.*?)(?=(?:UN)?AUTHORIZED (?:Town|Coven) roles|Authorized Administrators|Competition Guidelines|\z)'
        $body=[regex]::Match($Text,$pattern).Groups[1].Value
        $body=[regex]::Replace($body,'(?im)^\s*(?:Town|Coven)\s+(?:Investigative|Protective|Killing|Support|Power|Deception|Utility)\s*:',',')
        $items=@(($body -replace '\r?\n',' ') -split ',' | ForEach-Object {($_ -replace '\s+',' ').Trim()} | Where-Object {$_})
        if($alignment -eq 'Town'){$town=$items}else{$coven=$items}
    }
    [pscustomobject]@{Source=$Source;RequiredServices=@($required | Select-Object -Unique);SshPort=$port;PrimaryAccount=$primary;DomainAdmins=@($admins);TownRoles=$town;CovenRoles=$coven;GraveyardGroup=if($Text -match '(?i)Graveyard group'){'Graveyard'}else{$null}}
}

function Import-ServerImageRules {
    param([string]$Path)
    if(-not $Path){$Path=Read-Host 'Path to this server image README (Enter cancels)'}
    if([string]::IsNullOrWhiteSpace($Path)){return}
    $rules=Read-ServerImageRules -Text (Get-ReadmeText -Path $Path) -Source $Path
    Write-Host ('Required services: '+($rules.RequiredServices -join ', '))
    Write-Host "SSH port: $($rules.SshPort); protected primary account: $($rules.PrimaryAccount)"
    Write-Host ('Approved Domain Admins: '+($rules.DomainAdmins -join ', '))
    Write-Host "Town roles: $($rules.TownRoles.Count); Coven roles: $($rules.CovenRoles.Count); disabled-account group: $($rules.GraveyardGroup)"
    if(Confirm-Action 'Use these parsed server requirements for this image?' $false){$script:ServerImageRules=$rules}
}

function Set-ToolkitServiceState {
    param([string]$Name,[ValidateSet('Automatic','Manual','Disabled')][string]$StartupType)
    $service=@(Get-Service -ErrorAction Stop | Where-Object Name -eq $Name)
    if($service.Count -ne 1){throw 'Select one exact, installed service name.'}
    if($StartupType -eq 'Disabled'){Assert-ServiceCanStop $Name}
    Write-Host "$Name : $($service[0].Status), $($service[0].StartType) -> $StartupType"
    if(-not (Confirm-Action "Apply this service change to '$Name'?" $false)){return}
    $backup=Join-Path $script:LogDir ('Service-'+[guid]::NewGuid()+'.clixml')
    $service | Select-Object Name,Status,StartType | Export-Clixml -LiteralPath $backup -ErrorAction Stop
    if($StartupType -eq 'Disabled') {
        if($service[0].Status -ne 'Stopped'){Stop-Service -Name $Name -ErrorAction Stop}
        Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
    }
    else {
        Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop
        Start-Service -Name $Name -ErrorAction Stop
    }
    $after=Get-Service -Name $Name -ErrorAction Stop
    $status=if($StartupType -eq 'Disabled'){'Stopped'}else{'Running'}
    if([string]$after.StartType -ne $StartupType -or [string]$after.Status -ne $status){throw 'Service state did not match the requested result.'}
    Write-Ok "$Name verified: $StartupType / $status. Previous state: $backup"
}

function Get-RequiredServiceChecks {
    $names=if($script:ServerImageRules){@($script:ServerImageRules.RequiredServices)}else{@()}
    foreach($name in $names) {
        $service=Get-Service -Name $name -ErrorAction SilentlyContinue
        [pscustomobject]@{Check='Service';Name=$name;Result=if($service){[string]$service.Status}else{'Not installed'};Detail=if($service){[string]$service.StartType}else{'Install the required role/capability using supported Windows tools.'}}
    }
    $ports=@()
    if($names -contains 'NTDS'){$ports+=88,135,389,445}
    if($names -contains 'DNS'){$ports+=53}
    if($names -contains 'TermService'){$ports+=3389}
    if($names -contains 'sshd' -and $script:ServerImageRules.SshPort){$ports+=[int]$script:ServerImageRules.SshPort}
    $listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop)
    foreach($port in @($ports | Select-Object -Unique)) {
        $listening=@($listeners | Where-Object LocalPort -eq $port).Count -gt 0
        $probe=$false
        if($listening){$probe=Test-NetConnection -ComputerName $script:ToolkitPlatform.ComputerName -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue}
        [pscustomobject]@{Check='Local TCP reachability';Name=[string]$port;Result=if($probe){'Local probe passed'}elseif($listening){'Listening; local probe failed'}else{'Not listening'};Detail='A separate client must verify remote reachability; TCP checks do not verify DNS UDP or application authentication.'}
    }
}

function Set-SshPortText {
    param([string]$Text,[ValidateRange(1,65535)][int]$Port)
    $lines=New-Object 'System.Collections.Generic.List[string]';$lines.Add("Port $Port")
    $global=$true
    foreach($line in ($Text -split '\r?\n')) {
        if($line -match '^\s*Match\s+'){$global=$false}
        if($global -and $line -match '^\s*Port\s+'){continue}
        $lines.Add($line)
    }
    $lines -join "`r`n"
}

function Set-RequiredSshPort {
    if(-not $script:ServerImageRules -or -not $script:ServerImageRules.SshPort){throw 'Load a README with an explicit SSH port first.'}
    $port=[int]$script:ServerImageRules.SshPort
    $service=Get-Service -Name sshd -ErrorAction SilentlyContinue
    if(-not $service){throw 'OpenSSH Server is not installed. Use the approved Windows capability source to install OpenSSH.Server~~~~0.0.1.0, then enable/start sshd with option 8.'}
    $config=Join-Path $env:ProgramData 'ssh\sshd_config'
    $exe=Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
    if(-not (Test-Path -LiteralPath $config) -or -not (Test-Path -LiteralPath $exe)){throw 'Install/initialize the Windows OpenSSH Server capability first; sshd.exe and sshd_config are required.'}
    $scope=Read-Host 'Allowed remote address scope (Enter = LocalSubnet; type Any only if required)'
    if([string]::IsNullOrWhiteSpace($scope)){$scope='LocalSubnet'}
    Write-Host "Proposed SSH port: $port; firewall remote scope: $scope"
    if(-not (Confirm-Action 'Validate the configuration, update SSH/firewall and restart sshd?' $false)){return}
    $work=Join-Path $script:LogDir ('SSH-'+[guid]::NewGuid());$null=[IO.Directory]::CreateDirectory($work)
    $before=Get-Content -LiteralPath $config -Raw -ErrorAction Stop
    $backup=Join-Path $work 'sshd_config.before';$before | Set-Content -LiteralPath $backup -Encoding UTF8 -ErrorAction Stop
    $text=Set-SshPortText -Text $before -Port $port
    $candidate=Join-Path $work 'sshd_config.candidate'
    $encoding=New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($candidate,$text,$encoding)
    Invoke-NativeCommand -FilePath $exe -ArgumentList @('-t','-f',$candidate) | Out-Null
    try {
        [IO.File]::WriteAllText($config,$text,$encoding)
        foreach($store in 'PersistentStore','localhost') {
            $name="CyberPatriot-SSH-$port"
            $rule=Get-NetFirewallRule -PolicyStore $store -Name $name -ErrorAction SilentlyContinue
            if($rule){Set-NetFirewallRule -PolicyStore $store -Name $name -Enabled True -RemoteAddress $scope -ErrorAction Stop | Out-Null}
            else {New-NetFirewallRule -PolicyStore $store -Name $name -DisplayName "Required SSH TCP $port" -Direction Inbound -Action Allow -Enabled True -Protocol TCP -LocalPort $port -RemoteAddress $scope -Profile Any -ErrorAction Stop | Out-Null}
        }
        Set-Service -Name sshd -StartupType Automatic -ErrorAction Stop
        Invoke-NativeCommand gpupdate.exe @('/target:computer','/force','/wait:60') | Out-Null
        Restart-Service -Name sshd -ErrorAction Stop
        if(-not @(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction Stop).Count){throw "SSH did not start listening on $port."}
        Write-Ok "SSH is listening on $port. Verify login from an allowed remote client. Config backup: $backup"
    }
    catch {
        [IO.File]::WriteAllText($config,$before,$encoding)
        try{Restart-Service -Name sshd -ErrorAction Stop}catch{Write-Warn 'The previous SSH configuration was restored; restart sshd manually.'}
        throw
    }
}

function Invoke-ServiceManager {
    do {
        Write-Section 'Services - enable/start or disable/stop'
        Write-Host '1 list/filter  2 Automatic + Start  3 Manual + Start  4 Stop + Disable'
        Write-Host '5 verify required services/ports  6 configure README SSH port  R load README  0 back'
        $choice=Read-Host 'Choice'
        try {
            switch -Regex ($choice) {
                '^0$' {return}
                '^1$' {$filter=Read-Host 'Name/display-name search (Enter = all)';Get-Service -ErrorAction Stop | Where-Object {-not $filter -or $_.Name -like "*$filter*" -or $_.DisplayName -like "*$filter*"} | Sort-Object Name | Format-Table Name,DisplayName,Status,StartType -AutoSize | Out-Host}
                '^[234]$' {$name=Read-Host 'Exact service Name, not DisplayName';$type=@{'2'='Automatic';'3'='Manual';'4'='Disabled'}[$choice];Set-ToolkitServiceState -Name $name -StartupType $type}
                '^5$' {Get-RequiredServiceChecks | Format-Table -Wrap -AutoSize | Out-Host}
                '^6$' {Set-RequiredSshPort}
                '^[rR]$' {Import-ServerImageRules}
            }
        } catch {Write-Bad "Service action failed: $($_.Exception.Message)"}
    } while($true)
}

function Assert-ServerCommand {
    param([string]$Name)
    if(-not (Get-Command $Name -ErrorAction SilentlyContinue)){throw "$Name is unavailable. Install the relevant Server Manager/RSAT management tools before using this action."}
}

function Get-CurrentAdDomain {
    Assert-ServerCommand Get-ADDomain
    if(-not $script:ToolkitPlatform.DomainJoined){throw 'This server is not joined to an AD domain.'}
    Get-ADDomain -Identity $script:ToolkitPlatform.Domain -ErrorAction Stop
}

function Set-ServerDomainAccountPolicy {
    param([ValidateSet('Password','Lockout')][string]$Part)
    $domain=Get-CurrentAdDomain
    $before=Get-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -ErrorAction Stop
    $work=Join-Path $script:LogDir ('DomainPolicy-'+[guid]::NewGuid()+'.clixml')
    Write-Host "Domain-wide $Part policy target: $($domain.DNSRoot). Fine-grained password policies can override it for individual users."
    if(-not (Confirm-Action 'Back up and change the default DOMAIN policy?' $false)){return}
    $before | Export-Clixml -LiteralPath $work -ErrorAction Stop
    if($Part -eq 'Password') {
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -MinPasswordLength $PwMinLen -PasswordHistoryCount $PwHistory -MinPasswordAge ([timespan]::FromDays($PwMinAge)) -MaxPasswordAge ([timespan]::FromDays($PwMaxAge)) -ComplexityEnabled $true -ReversibleEncryptionEnabled $false -ErrorAction Stop
    }
    else {
        if($LockThreshold -lt 1 -or $LockDuration -lt $LockWindow){throw 'Invalid domain lockout threshold/duration/window.'}
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -LockoutThreshold $LockThreshold -LockoutDuration ([timespan]::FromMinutes($LockDuration)) -LockoutObservationWindow ([timespan]::FromMinutes($LockWindow)) -ErrorAction Stop
    }
    $after=Get-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -ErrorAction Stop
    $ok=if($Part -eq 'Password') {
        $after.MinPasswordLength -eq $PwMinLen -and $after.PasswordHistoryCount -eq $PwHistory -and $after.MinPasswordAge.TotalDays -eq $PwMinAge -and $after.MaxPasswordAge.TotalDays -eq $PwMaxAge -and $after.ComplexityEnabled -and -not $after.ReversibleEncryptionEnabled
    } else {$after.LockoutThreshold -eq $LockThreshold -and $after.LockoutDuration.TotalMinutes -eq $LockDuration -and $after.LockoutObservationWindow.TotalMinutes -eq $LockWindow}
    if(-not $ok){throw 'The default domain policy read-back did not match.'}
    Write-Ok "Default domain $Part policy verified. Previous policy: $work"
}

function Get-ImageRoleClassification {
    param([string]$Description,[string[]]$TownRoles,[string[]]$CovenRoles)
    $town=@($TownRoles | Where-Object {$Description -match ('(?i)(?<![\w])'+[regex]::Escape($_)+'(?![\w])')})
    $coven=@($CovenRoles | Where-Object {$Description -match ('(?i)(?<![\w])'+[regex]::Escape($_)+'(?![\w])')})
    if($town.Count -eq 1 -and -not $coven.Count){return 'Town'}
    if($coven.Count -eq 1 -and -not $town.Count){return 'Coven'}
    if($town.Count -or $coven.Count){return 'Ambiguous'}
    'Unknown'
}

function Get-ServerAdAccountPlan {
    param([object[]]$Users,[string[]]$DomainAdminMembers)
    if(-not $script:ServerImageRules){throw 'Load and confirm this image README first.'}
    $rules=$script:ServerImageRules
    foreach($user in $Users) {
        $sid=[string]$user.SID.Value
        $protected=$user.SamAccountName -ieq $script:CurrentUserName -or (Test-PasswordProtectedAccount $user.SamAccountName) -or $sid -match '-(500|501|502)$'
        $alignment=Get-ImageRoleClassification -Description $user.Description -TownRoles $rules.TownRoles -CovenRoles $rules.CovenRoles
        $approvedAdmin=$rules.DomainAdmins -contains $user.SamAccountName
        $actions=New-Object 'System.Collections.Generic.List[string]'
        if(-not $protected) {
            if(-not $user.Enabled -and $rules.GraveyardGroup){$actions.Add('EnsureGraveyard')}
            elseif($alignment -eq 'Coven' -and -not $approvedAdmin){$actions.Add('Disable')}
            if($rules.DomainAdmins.Count -and $DomainAdminMembers -contains $user.SamAccountName -and -not $approvedAdmin -and $alignment -ne 'Ambiguous'){$actions.Add('RemoveDomainAdmin')}
            if($approvedAdmin -and $user.Enabled -and $alignment -ne 'Coven' -and $DomainAdminMembers -notcontains $user.SamAccountName){$actions.Add('AddDomainAdmin')}
        }
        $review=($alignment -eq 'Ambiguous') -or ($alignment -eq 'Unknown' -and -not $approvedAdmin) -or ($approvedAdmin -and $alignment -eq 'Coven')
        if($review -and $alignment -ne 'Town'){
            $removeAdmin=$actions -contains 'RemoveDomainAdmin'
            $actions.Clear()
            if($removeAdmin){$actions.Add('RemoveDomainAdmin')}
            if(-not $protected -and -not $user.Enabled -and $rules.GraveyardGroup){$actions.Add('EnsureGraveyard')}
        }
        if($actions -contains 'Disable' -and $rules.GraveyardGroup -and $actions -notcontains 'EnsureGraveyard'){$actions.Add('EnsureGraveyard')}
        [pscustomobject]@{User=$user;Name=$user.SamAccountName;Enabled=[bool]$user.Enabled;Alignment=$alignment;ApprovedAdmin=$approvedAdmin;IsDomainAdmin=($DomainAdminMembers -contains $user.SamAccountName);Protected=$protected;InfoPresent=[bool]$user.info;ReviewRequired=$review;Actions=@($actions)}
    }
}

function Invoke-ServerAdAccountAudit {
    Assert-ServerCommand Get-ADUser
    $domain=Get-CurrentAdDomain
    if(-not $script:ServerImageRules){Import-ServerImageRules;if(-not $script:ServerImageRules){return}}
    if(-not $script:ServerImageRules.TownRoles.Count){throw 'This README has no supported Town/Coven role lists. Use the targeted AD actions and inspect unknown roles manually.'}
    $admin=Get-ADGroup -Identity ($domain.DomainSID.Value+'-512') -ErrorAction Stop
    $admins=@(Get-ADGroupMember -Identity $admin -ErrorAction Stop | Where-Object objectClass -eq user | ForEach-Object SamAccountName)
    $users=@(Get-ADUser -Filter * -Properties Description,info,Enabled -ErrorAction Stop)
    $plan=@(Get-ServerAdAccountPlan -Users $users -DomainAdminMembers $admins)
    $report=Join-Path $script:LogDir ('AD-AccountPlan-'+[guid]::NewGuid()+'.csv')
    $plan | Select-Object Name,Enabled,Alignment,ApprovedAdmin,IsDomainAdmin,Protected,InfoPresent,ReviewRequired,@{Name='SID';Expression={$_.User.SID.Value}},@{Name='DistinguishedName';Expression={$_.User.DistinguishedName}},@{Name='Actions';Expression={$_.Actions -join ','}} | Export-Csv -LiteralPath $report -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    $plan | Select-Object Name,Enabled,Alignment,Protected,ReviewRequired,@{Name='Actions';Expression={$_.Actions -join ','}} | Format-Table -AutoSize | Out-Host
    Write-Host "Report: $report. Unknown/ambiguous comments are not proof that an account is unauthorized. No info/will attributes will be changed."
    if(-not (Confirm-Action 'Apply the listed account plan (disable-only; never delete or enable accounts)?' $false)){return}
    $graveyard=$null
    foreach($entry in $plan) {
        if($entry.Protected -or -not $entry.Actions.Count){continue}
        if($entry.Actions -contains 'Disable') {
            Disable-ADAccount -Identity $entry.User.DistinguishedName -ErrorAction Stop
            if((Get-ADUser -Identity $entry.User.DistinguishedName -ErrorAction Stop).Enabled){throw "Disable not verified for $($entry.Name)."}
        }
        if($entry.Actions -contains 'RemoveDomainAdmin') {
            Remove-ADGroupMember -Identity $admin -Members $entry.User.DistinguishedName -Confirm:$false -ErrorAction Stop
            if(@(Get-ADGroupMember -Identity $admin -ErrorAction Stop | Where-Object SamAccountName -eq $entry.Name).Count){throw "Domain Admin removal not verified for $($entry.Name)."}
        }
        if($entry.Actions -contains 'AddDomainAdmin') {
            Add-ADGroupMember -Identity $admin -Members $entry.User.DistinguishedName -ErrorAction Stop
            if(-not @(Get-ADGroupMember -Identity $admin -ErrorAction Stop | Where-Object SamAccountName -eq $entry.Name).Count){throw "Approved Domain Admin addition not verified: $($entry.Name)."}
        }
        if($entry.Actions -contains 'EnsureGraveyard') {
            if(-not $graveyard) {
                $name=$script:ServerImageRules.GraveyardGroup
                $graveyard=Get-ADGroup -Filter {SamAccountName -eq $name} -ErrorAction Stop
                if(-not $graveyard){$graveyard=New-ADGroup -Name $name -SamAccountName $name -GroupScope Global -GroupCategory Security -PassThru -ErrorAction Stop}
            }
            $members=@(Get-ADGroupMember -Identity $graveyard -ErrorAction Stop)
            if($members.SID.Value -notcontains $entry.User.SID.Value){Add-ADGroupMember -Identity $graveyard -Members $entry.User.DistinguishedName -ErrorAction Stop}
            if((Get-ADUser -Identity $entry.User.DistinguishedName -ErrorAction Stop).Enabled){throw "A dead account became enabled: $($entry.Name)."}
            if(-not @(Get-ADGroupMember -Identity $graveyard -ErrorAction Stop | Where-Object {$_.SID.Value -eq $entry.User.SID.Value}).Count){throw "Graveyard membership not verified: $($entry.Name)."}
        }
    }
    Write-Ok 'Listed AD account changes verified. Town accounts, protected accounts, disabled state and info attributes were preserved.'
}

function Invoke-TargetedAdUserAction {
    Assert-ServerCommand Get-ADUser
    $identity=Read-Host 'Exact AD user sAMAccountName, SID or distinguished name (Enter cancels)'
    if([string]::IsNullOrWhiteSpace($identity)){return}
    $user=Get-ADUser -Identity $identity -Properties SIDHistory,UserAccountControl,PasswordNeverExpires,Description -ErrorAction Stop
    Write-Host "Target: $($user.SamAccountName) [$($user.SID)]"
    Write-Host '1 disable unauthorized account  2 remove Domain Admin membership  3 disable DES-only Kerberos'
    Write-Host '4 clear SID history  5 reset password to configured default  6 require password / expiration  0 cancel'
    $choice=Read-Host 'Action'
    if($choice -notmatch '^[1-6]$'){return}
    if($user.SamAccountName -ieq $script:CurrentUserName -or $user.SID.Value -match '-(500|501|502)$' -or (Test-PasswordProtectedAccount $user.SamAccountName)){throw 'This is a current/primary/built-in protected account. Use dedicated administrative recovery procedures if a change is required.'}
    if($choice -in '1','2' -and $script:ServerImageRules -and $script:ServerImageRules.DomainAdmins -contains $user.SamAccountName){throw 'The README approves this administrator; update/review the image plan before disabling or demoting it.'}
    if(-not (Confirm-Action "Apply action $choice to this exact DOMAIN account?" $false)){return}
    $user | Export-Clixml -LiteralPath (Join-Path $script:LogDir ('AD-user-'+[guid]::NewGuid()+'.clixml')) -ErrorAction Stop
    switch($choice) {
        '1' {Disable-ADAccount -Identity $user -ErrorAction Stop;if((Get-ADUser -Identity $user -ErrorAction Stop).Enabled){throw 'Disable read-back failed.'}}
        '2' {$domain=Get-CurrentAdDomain;$group=Get-ADGroup -Identity ($domain.DomainSID.Value+'-512') -ErrorAction Stop;Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false -ErrorAction Stop;if(@(Get-ADGroupMember -Identity $group -ErrorAction Stop | Where-Object {$_.SID.Value -eq $user.SID.Value}).Count){throw 'Group membership removal not verified.'}}
        '3' {Set-ADAccountControl -Identity $user -UseDESKeyOnly $false -ErrorAction Stop;if((Get-ADUser -Identity $user -Properties UserAccountControl -ErrorAction Stop).UserAccountControl -band 0x200000){throw 'DES-only flag remains enabled.'}}
        '4' {Set-ADUser -Identity $user -Clear sIDHistory -ErrorAction Stop;if((Get-ADUser -Identity $user -Properties SIDHistory -ErrorAction Stop).SIDHistory){throw 'SID history is still present.'}}
        '5' {Set-ADAccountPassword -Identity $user -Reset -NewPassword (Get-DefaultAccountPassword) -ErrorAction Stop;Write-Host 'Password reset was accepted by AD; the password value is not read back or logged.'}
        '6' {Set-ADAccountControl -Identity $user -PasswordNotRequired $false -ErrorAction Stop;Set-ADUser -Identity $user -PasswordNeverExpires $false -ErrorAction Stop;$after=Get-ADUser -Identity $user -Properties UserAccountControl,PasswordNeverExpires -ErrorAction Stop;if(($after.UserAccountControl -band 0x20) -or $after.PasswordNeverExpires){throw 'Password flags did not match.'}}
    }
    Write-Ok 'Targeted AD action completed. No account was deleted or enabled.'
}

function Set-ServerRegistryBaseline {
    $before=$script:RegFail
    $lsa='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $system='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-RegistryValue $lsa NoLMHash 1
    Set-RegistryValue $lsa LimitBlankPasswordUse 1
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 0
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' ProtectionMode 1
    Set-RegistryValue $system EnableLUA 1
    Set-RegistryValue $system PromptOnSecureDesktop 1
    Set-RegistryValue $system ConsentPromptBehaviorAdmin 2
    Set-RegistryValue $system DontDisplayLastUserName 1
    Set-RegistryValue $system legalnoticecaption $DefaultLogonCaption String
    Set-RegistryValue $system legalnoticetext $DefaultLogonText String
    Write-RegistryResult -Before $before -SuccessMessage 'Server registry/logon baseline applied. Server roles, cached credentials, IPv6 and role-specific network settings were preserved.'
}

function Enable-ServerFirewall {
    foreach($name in 'BFE','mpssvc'){
        $service=Get-Service -Name $name -ErrorAction Stop
        if([string]$service.StartType -ne 'Automatic'){Set-Service -Name $name -StartupType Automatic -ErrorAction Stop}
        if([string]$service.Status -ne 'Running'){Start-Service -Name $name -ErrorAction Stop}
        $after=Get-Service -Name $name -ErrorAction Stop
        if([string]$after.Status -ne 'Running' -or [string]$after.StartType -ne 'Automatic'){throw "Required firewall service not ready: $name"}
    }
    Write-Host 'Server firewall profiles will be enabled with logging. Existing rules are preserved.'
    $block=Confirm-Action 'Also set inbound Block / outbound Allow after reviewing ALL required server-role rules?' $false
    foreach($store in 'localhost','PersistentStore') {
        foreach($profile in 'Domain','Private','Public') {
            $settings=@{PolicyStore=$store;Profile=$profile;Enabled='True';LogBlocked='True';LogAllowed='True';LogMaxSizeKilobytes=16384;ErrorAction='Stop'}
            if($block){$settings.DefaultInboundAction='Block';$settings.DefaultOutboundAction='Allow'}
            Set-NetFirewallProfile @settings
        }
    }
    Invoke-NativeCommand gpupdate.exe @('/target:computer','/force','/wait:60') | Out-Null
    foreach($store in 'localhost','ActiveStore') {
        $profiles=@(Get-NetFirewallProfile -PolicyStore $store -ErrorAction Stop)
        foreach($name in 'Domain','Private','Public') {
            $profile=@($profiles | Where-Object Name -eq $name)
            if($profile.Count -ne 1 -or [string]$profile[0].Enabled -ne 'True' -or [string]$profile[0].LogBlocked -ne 'True' -or [string]$profile[0].LogAllowed -ne 'True' -or $profile[0].LogMaxSizeKilobytes -lt 16384){throw "Firewall profile/logging $name was not verified in $store."}
            if($block -and ([string]$profile[0].DefaultInboundAction -ne 'Block' -or [string]$profile[0].DefaultOutboundAction -ne 'Allow')){throw "Traffic defaults are overridden for $name in $store."}
        }
    }
    Write-Ok 'Server firewall profiles verified ON. Required service firewall rules were not disabled.'
    if(-not $block){Write-Host 'Existing inbound/outbound defaults were preserved. Review them against the README.'}
}

function Disable-ToolkitLegacyFeatures {
    if(Test-ToolkitServer) {
        Assert-ServerCommand Get-WindowsFeature
        foreach($name in 'FS-SMB1','Telnet-Client','PowerShell-V2') {
            $feature=Get-WindowsFeature -Name $name -ErrorAction Stop
            if($feature -and $feature.Installed -and (Confirm-Action "Remove installed legacy SERVER feature '$name' after checking required applications?" $false)) {
                Uninstall-WindowsFeature -Name $name -Restart:$false -ErrorAction Stop | Out-Host
                if((Get-WindowsFeature -Name $name -ErrorAction Stop).Installed){throw "Feature removal was not verified: $name"}
            }
        }
        return
    }
    foreach($name in 'SMB1Protocol','SMB1Protocol-Client','SMB1Protocol-Server','TelnetClient','TFTP','MicrosoftWindowsPowerShellV2Root','MicrosoftWindowsPowerShellV2') {
        try {$feature=Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop}
        catch {Write-Host "Feature unavailable: $name";continue}
        if($feature.State -eq 'Enabled'){Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart -ErrorAction Stop | Out-Null;Write-Ok "Disabled feature: $name"}
    }
}

function Show-ServerInstalledSoftware {
    Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object DisplayName | Sort-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher | Format-Table -AutoSize | Out-Host
}

function Test-ServerOsUpgrade {
    param($Update)
    @($Update.Categories | Where-Object {$_.CategoryID -ieq '3689BDC8-B205-4AF4-8D4A-A63924C5E9D5'}).Count -gt 0 -or
    ($Update.Title -match '(?i)(?:upgrade to|feature update to).*Windows Server')
}

function New-ServerUpdateSession {New-Object -ComObject Microsoft.Update.Session}
function New-ServerUpdateCollection {New-Object -ComObject Microsoft.Update.UpdateColl}
function Invoke-ServerWindowsUpdate {
    Write-Host "Using this server's configured Windows Update/WSUS source. No OS upgrade, source replacement, Store installation or automatic reboot is requested."
    if(-not (Confirm-Action 'Search for and install applicable software updates using the configured source?' $false)){return}
    $session=New-ServerUpdateSession
    $session.ClientApplicationID='LOMAGOSH by Jasiah O'
    $searcher=$session.CreateUpdateSearcher()
    $found=$searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    if($found.ResultCode -ne 2){throw 'Windows Update search did not complete successfully.'}
    $updates=New-ServerUpdateCollection
    for($i=0;$i -lt $found.Updates.Count;$i++) {
        $update=$found.Updates.Item($i)
        if((Test-ServerOsUpgrade $update) -or $update.InstallationBehavior.CanRequestUserInput){Write-Host "Skipped upgrade/interactive update: $($update.Title)";continue}
        if(-not $update.EulaAccepted){$update.AcceptEula()}
        $null=$updates.Add($update)
    }
    if(-not $updates.Count){Write-Host 'No eligible non-upgrade software updates were found.';return}
    $downloader=$session.CreateUpdateDownloader();$downloader.Updates=$updates
    $download=$downloader.Download()
    if($download.ResultCode -ne 2){throw 'Not all selected updates downloaded successfully; installation was not started.'}
    $installer=$session.CreateUpdateInstaller();$installer.Updates=$updates
    $result=$installer.Install()
    $failed=@()
    for($i=0;$i -lt $updates.Count;$i++) {
        $item=$result.GetUpdateResult($i)
        Write-Host "$($updates.Item($i).Title): result $($item.ResultCode), HRESULT $($item.HResult)"
        if($item.ResultCode -ne 2){$failed+=$updates.Item($i).Title}
    }
    if($failed.Count -or $result.ResultCode -ne 2){throw ('Some updates did not install successfully: '+($failed -join ', '))}
    Write-Ok 'Selected Server 2022 software updates installed. The configured WSUS/Windows Update source was preserved.'
    if($result.RebootRequired){Write-Warn 'A planned server reboot is required. This action did not restart the server.'}
}

function Remove-ServerDomainUsersBackupRight {
    $domain=Get-CurrentAdDomain
    $sid=$domain.DomainSID.Value+'-513'
    $work=Join-Path $script:LogDir ('BackupRight-'+[guid]::NewGuid());$null=[IO.Directory]::CreateDirectory($work)
    $before=Join-Path $work 'before.inf'
    Invoke-NativeCommand secedit.exe @('/export','/mergedpolicy','/cfg',$before,'/areas','USER_RIGHTS','/quiet') | Out-Null
    $rights=Read-PolicyInfSection -Text (Get-Content -LiteralPath $before -Raw -ErrorAction Stop) -Section 'Privilege Rights'
    $members=@($rights.SeBackupPrivilege -split ',' | ForEach-Object {$_.Trim()} | Where-Object {$_})
    $after=@($members | Where-Object {$_.TrimStart('*') -ne $sid})
    if($after.Count -eq $members.Count){Write-Host 'Domain Users has no direct SeBackupPrivilege assignment.';return}
    Write-Host "Remove only $sid from SeBackupPrivilege; preserve: $($after -join ', ')"
    if(-not (Confirm-Action 'Apply this targeted user-rights change?' $false)){return}
    $cfg=Join-Path $work 'desired.inf'
    New-SecurityPolicyInf -Section 'Privilege Rights' -Values @{SeBackupPrivilege=($after -join ',')} | Set-Content -LiteralPath $cfg -Encoding Unicode -ErrorAction Stop
    Invoke-NativeCommand secedit.exe @('/configure','/db',(Join-Path $work 'policy.sdb'),'/cfg',$cfg,'/areas','USER_RIGHTS','/quiet') | Out-Null
    Invoke-NativeCommand gpupdate.exe @('/target:computer','/force','/wait:60') | Out-Null
    $check=Join-Path $work 'verified.inf'
    Invoke-NativeCommand secedit.exe @('/export','/mergedpolicy','/cfg',$check,'/areas','USER_RIGHTS','/quiet') | Out-Null
    $current=Read-PolicyInfSection -Text (Get-Content -LiteralPath $check -Raw -ErrorAction Stop) -Section 'Privilege Rights'
    if(@($current.SeBackupPrivilege -split ',' | Where-Object {$_.Trim().TrimStart('*') -eq $sid}).Count){throw 'Domain Users still has the right, possibly through domain policy. Edit the responsible GPO and verify inherited/group-derived rights.'}
    Write-Ok "Direct Domain Users backup right removed. Other user rights were preserved. Backup: $before"
}

function Set-ServerLdapSigning {
    if(-not (Test-ToolkitDomainController)){throw 'LDAP server signing applies to an AD domain controller.'}
    if(-not (Confirm-Action 'Require LDAP server signing? Confirm required clients use signing or TLS before proceeding.' $false)){return}
    $before=$script:RegFail
    $path='HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    Set-RegistryValue $path LDAPServerIntegrity 2
    if($script:RegFail -gt $before -or (Get-ItemPropertyValue -LiteralPath $path -Name LDAPServerIntegrity -ErrorAction Stop) -ne 2){throw 'LDAP signing was not verified.'}
    Write-Ok 'LDAP signing registry policy verified. Test required directory clients and plan any needed service restart.'
}

function Invoke-ServerDnsAction {
    Assert-ServerCommand Get-DnsServerZone
    Write-Host '1 secure dynamic updates for one AD-integrated zone  2 disable version queries  3 disable recursion (authoritative-only servers)'
    $choice=Read-Host 'Choice'
    switch($choice) {
        '1' {
            Get-DnsServerZone -ErrorAction Stop | Select-Object ZoneName,IsDsIntegrated,DynamicUpdate | Format-Table | Out-Host
            $name=Get-WarriorTarget 'Exact current-image DNS zone name'
            $zone=Get-DnsServerZone -Name $name -ErrorAction Stop
            if(-not $zone.IsDsIntegrated){throw 'Secure dynamic updates require an AD-integrated zone. The tool will not silently convert the zone.'}
            $zone | Export-Clixml -LiteralPath (Join-Path $script:LogDir ('DNS-zone-'+[guid]::NewGuid()+'.clixml')) -ErrorAction Stop
            Set-DnsServerPrimaryZone -Name $name -DynamicUpdate Secure -ErrorAction Stop
            if([string](Get-DnsServerZone -Name $name -ErrorAction Stop).DynamicUpdate -ne 'Secure'){throw 'Secure-update setting not verified.'}
        }
        '2' {
            $settings=Get-DnsServerSetting -All -ErrorAction Stop
            if(-not $settings.PSObject.Properties['EnableVersionQuery']){throw 'This DNS management provider does not expose EnableVersionQuery.'}
            if(-not (Confirm-Action 'Disable DNS version queries?' $false)){return}
            $settings | Export-Clixml -LiteralPath (Join-Path $script:LogDir ('DNS-settings-'+[guid]::NewGuid()+'.clixml')) -ErrorAction Stop
            $settings.EnableVersionQuery=$false;Set-DnsServerSetting -InputObject $settings -ErrorAction Stop
            if((Get-DnsServerSetting -All -ErrorAction Stop).EnableVersionQuery){throw 'DNS version-query setting not verified.'}
        }
        '3' {
            if(-not (Confirm-Action 'Is this DNS server authoritative-only, with no required recursive/forwarded client resolution? Disable recursion?' $false)){return}
            Get-DnsServerRecursion -ErrorAction Stop | Export-Clixml -LiteralPath (Join-Path $script:LogDir ('DNS-recursion-'+[guid]::NewGuid()+'.clixml')) -ErrorAction Stop
            Set-DnsServerRecursion -Enable $false -ErrorAction Stop
            if((Get-DnsServerRecursion -ErrorAction Stop).Enable){throw 'DNS recursion remains enabled.'}
        }
        default {return}
    }
    Write-Ok 'Selected DNS setting verified. Test resolution from a required client.'
}

function Invoke-ServerDhcpAction {
    Assert-ServerCommand Get-DhcpServerAuditLog
    Write-Host '1 enable DHCP audit logging  2 enable name protection for one IPv4 scope  3 authorize this DHCP server in AD'
    switch(Read-Host 'Choice') {
        '1' {if(-not (Confirm-Action 'Enable DHCP audit logging?' $false)){return};Set-DhcpServerAuditLog -Enable $true -ErrorAction Stop;if(-not (Get-DhcpServerAuditLog -ErrorAction Stop).Enable){throw 'DHCP audit logging not verified.'}}
        '2' {
            Get-DhcpServerv4Scope -ErrorAction Stop | Format-Table ScopeId,Name,State | Out-Host
            $scope=Get-WarriorTarget 'Exact current-image DHCP IPv4 scope ID'
            Get-DhcpServerv4DnsSetting -ScopeId $scope -ErrorAction Stop | Export-Clixml -LiteralPath (Join-Path $script:LogDir ('DHCP-scope-'+[guid]::NewGuid()+'.clixml')) -ErrorAction Stop
            Set-DhcpServerv4DnsSetting -ScopeId $scope -NameProtection $true -ErrorAction Stop
            if(-not (Get-DhcpServerv4DnsSetting -ScopeId $scope -ErrorAction Stop).NameProtection){throw 'DHCP name protection not verified.'}
        }
        '3' {
            $domain=Get-CurrentAdDomain
            $dns=$script:ToolkitPlatform.ComputerName+'.'+$domain.DNSRoot
            Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Format-Table IPAddress,InterfaceAlias | Out-Host
            $ip=Get-WarriorTarget "One IPv4 address belonging to THIS DHCP server ($dns)"
            if(-not @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object IPAddress -eq $ip).Count){throw 'The selected address does not belong to this server.'}
            Add-DhcpServerInDC -DnsName $dns -IPAddress $ip -ErrorAction Stop
            if(-not @(Get-DhcpServerInDC -ErrorAction Stop | Where-Object {$_.DnsName -ieq $dns -and [string]$_.IPAddress -eq $ip}).Count){throw 'DHCP authorization not verified.'}
        }
        default {return}
    }
    Write-Ok 'Selected DHCP setting verified.'
}

function Disable-ServerBuiltinAccounts {
    $domain=Get-CurrentAdDomain
    foreach($rid in 500,501) {
        $user=Get-ADUser -Identity ($domain.DomainSID.Value+"-$rid") -ErrorAction Stop
        if($user.SamAccountName -ieq $script:CurrentUserName -or (Test-PasswordProtectedAccount $user.SamAccountName)) {Write-Warn "Preserved current/auto-login built-in account $($user.SamAccountName).";continue}
        if($user.Enabled -and (Confirm-Action "Disable built-in DOMAIN account $($user.SamAccountName)?" $false)) {
            Disable-ADAccount -Identity $user -ErrorAction Stop
            if((Get-ADUser -Identity $user -ErrorAction Stop).Enabled){throw 'Built-in account disable was not verified.'}
            Write-Ok "Disabled $($user.SamAccountName)."
        }
    }
}

function Reset-ApprovedServerPasswords {
    if(-not $script:ServerImageRules -or -not $script:ServerImageRules.TownRoles.Count){throw 'Load the current role-based README first, or use option 26 for one explicitly selected AD account.'}
    $users=@(Get-ADUser -Filter * -Properties Description,info,Enabled -ErrorAction Stop)
    $plan=@(Get-ServerAdAccountPlan -Users $users -DomainAdminMembers @())
    $targets=@($plan | Where-Object {$_.Enabled -and -not $_.Protected -and -not $_.ReviewRequired -and ($_.Alignment -eq 'Town' -or $_.ApprovedAdmin)})
    $targets | Select-Object Name,Alignment | Format-Table | Out-Host
    if(-not $targets.Count){Write-Host 'No eligible accounts selected.';return}
    if(-not (Confirm-Action 'Reset only these approved, enabled DOMAIN accounts to the configured default? Current/primary/disabled accounts remain untouched.' $false)){return}
    foreach($entry in $targets) {
        try {Set-ADAccountPassword -Identity $entry.User.DistinguishedName -Reset -NewPassword (Get-DefaultAccountPassword) -ErrorAction Stop;Write-Ok "AD accepted the reset for $($entry.Name)."}
        catch {Write-Bad "Password reset failed for $($entry.Name): $($_.Exception.Message)"}
    }
}

function Set-ServerMachineAccountQuota {
    $domain=Get-CurrentAdDomain
    $old=Get-ADObject -Identity $domain.DistinguishedName -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop
    Write-Host "Domain: $($domain.DNSRoot); current machine-account quota: $($old.'ms-DS-MachineAccountQuota')"
    if(-not (Confirm-Action 'Set this domain quota to 0? Confirm authorized computer-join workflows have delegated permissions.' $false)){return}
    $old | Export-Clixml -LiteralPath (Join-Path $script:LogDir ('MachineQuota-'+[guid]::NewGuid()+'.clixml')) -ErrorAction Stop
    Set-ADObject -Identity $domain.DistinguishedName -Replace @{'ms-DS-MachineAccountQuota'=0} -ErrorAction Stop
    if((Get-ADObject -Identity $domain.DistinguishedName -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop).'ms-DS-MachineAccountQuota' -ne 0){throw 'Machine-account quota not verified.'}
    Write-Ok 'Domain machine-account quota verified as 0.'
}

function Set-ServerGpoReadApplyPermission {
    Assert-ServerCommand Get-GPO
    Get-GPO -All -ErrorAction Stop | Select-Object DisplayName,Id | Format-Table | Out-Host
    $identity=Get-WarriorTarget 'Exact GPO GUID whose Authenticated Users edit permission is unauthorized'
    $id=[guid]$identity
    $gpo=Get-GPO -Guid $id -ErrorAction Stop
    Get-GPPermission -Guid $id -All -ErrorAction Stop | Format-Table Trustee,Permission,Inherited -AutoSize | Out-Host
    if(-not (Confirm-Action "Replace Authenticated Users' explicit rights on '$($gpo.DisplayName)' with Read+Apply, removing edit rights?" $false)){return}
    $backup=Join-Path $script:LogDir ('GPO-'+[guid]::NewGuid());$null=[IO.Directory]::CreateDirectory($backup)
    Backup-GPO -Guid $id -Path $backup -ErrorAction Stop | Out-Null
    $group=(New-Object Security.Principal.SecurityIdentifier('S-1-5-11')).Translate([Security.Principal.NTAccount]).Value
    Set-GPPermission -Guid $id -TargetName $group -TargetType Group -PermissionLevel GpoApply -Replace -ErrorAction Stop
    $state=Get-GPPermission -Guid $id -TargetName $group -TargetType Group -ErrorAction Stop
    if([string]$state.Permission -ne 'GpoApply'){throw 'GPO read/apply permission was not verified; inspect inherited and custom permissions.'}
    Write-Ok "Explicit GPO permission verified as Read+Apply. Inspect inherited/group-derived permissions too. Backup: $backup"
}

function Invoke-ServerDisplaySpecifierReview {
    Assert-ServerCommand Get-ADRootDSE
    $root=Get-ADRootDSE -ErrorAction Stop
    $base='CN=DisplaySpecifiers,'+$root.configurationNamingContext
    $objects=@(Get-ADObject -SearchBase $base -LDAPFilter '(adminContextMenu=*)' -Properties adminContextMenu -ErrorAction Stop)
    $objects | Select-Object DistinguishedName,@{Name='ContextMenu';Expression={$_.adminContextMenu -join '; '}} | Format-List | Out-Host
    if(-not (Confirm-Action 'After completing forensics, remove ONE confirmed malicious context-menu value?' $false)){return}
    $dn=Get-WarriorTarget 'Exact display-specifier distinguished name from this domain'
    if(-not $dn.EndsWith(','+$base,[StringComparison]::OrdinalIgnoreCase)){throw 'The selected object is outside the current domain display-specifier container.'}
    $object=Get-ADObject -Identity $dn -Properties adminContextMenu -ErrorAction Stop
    $value=Read-Host 'Paste the exact malicious adminContextMenu value; Enter cancels'
    if(-not $value){return}
    if(@($object.adminContextMenu) -cnotcontains $value){throw 'The exact value is not present; no attribute was changed.'}
    if(-not (Confirm-Action 'Remove only this value and preserve all other context-menu entries?' $false)){return}
    $object | Export-Clixml -LiteralPath (Join-Path $script:LogDir ('DisplaySpecifier-'+[guid]::NewGuid()+'.clixml')) -ErrorAction Stop
    Set-ADObject -Identity $dn -Remove @{adminContextMenu=$value} -ErrorAction Stop
    if(@((Get-ADObject -Identity $dn -Properties adminContextMenu -ErrorAction Stop).adminContextMenu) -ccontains $value){throw 'Context-menu entry removal not verified.'}
    Write-Ok 'Only the confirmed context-menu value was removed.'
}

function Invoke-ServerDefenderExtras {
    Assert-ServerCommand Get-MpPreference
    Write-Host '1 block PSExec/WMI process creation  2 enable supported DNS sinkhole protection  3 enable Defender sandbox variable  4 report service protection'
    switch(Read-Host 'Choice') {
        '1' {
            if(-not (Confirm-Action 'Enable this ASR rule? It can disrupt required PSExec/WMI remote administration.' $false)){return}
            $id='d1e49aac-8f56-4280-b9ba-993a6d77406c'
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
            $state=Get-MpPreference -ErrorAction Stop;$index=[array]::IndexOf(@($state.AttackSurfaceReductionRules_Ids),$id)
            if($index -lt 0 -or [int]$state.AttackSurfaceReductionRules_Actions[$index] -ne 1){throw 'ASR rule was not verified.'}
        }
        '2' {
            if(-not (Get-Command Set-MpPreference -ErrorAction Stop).Parameters.ContainsKey('EnableDnsSinkhole')){throw 'Update the Defender platform first; this provider does not support EnableDnsSinkhole.'}
            if(-not (Confirm-Action 'Enable Defender DNS sinkhole protection?' $false)){return}
            Set-MpPreference -EnableDnsSinkhole $true -ErrorAction Stop
            if(-not (Get-MpPreference -ErrorAction Stop).EnableDnsSinkhole){throw 'DNS sinkhole preference not verified.'}
        }
        '3' {
            if(-not (Confirm-Action 'Set the documented MP_FORCE_USE_SANDBOX machine variable? A planned reboot/Defender restart may be needed; this does not prove sandbox activation.' $false)){return}
            [Environment]::SetEnvironmentVariable('MP_FORCE_USE_SANDBOX','1','Machine')
            if([Environment]::GetEnvironmentVariable('MP_FORCE_USE_SANDBOX','Machine') -ne '1'){throw 'Sandbox request was not saved.'}
            Write-Host 'Sandbox request saved; verify active Defender protection separately.'
        }
        '4' {Invoke-NativeCommand sc.exe @('qprotection','WinDefend') | Out-Host;Get-MpComputerStatus -ErrorAction Stop | Format-List AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled | Out-Host;return}
        default {return}
    }
    Write-Ok 'Selected Defender setting accepted and read back. Tamper Protection/platform support still governs runtime behavior.'
}

function Invoke-ServerEnvironmentCleanup {
    Write-Host 'This removes only exact C:\temp PATH entries and SSLKEYLOGFILE bindings. It does not delete key-log evidence or dump other environment values.'
    if(-not (Confirm-Action 'Have you completed packet/key-log forensics and approved this environment cleanup?' $false)){return}
    foreach($scope in 'User','Machine') {
        $path=[Environment]::GetEnvironmentVariable('Path',$scope)
        $ssl=[Environment]::GetEnvironmentVariable('SSLKEYLOGFILE',$scope)
        [pscustomobject]@{Scope=$scope;Path=$path;SSLKEYLOGFILE=$ssl} | Export-Clixml -LiteralPath (Join-Path $script:LogDir ('Environment-'+$scope+'-'+[guid]::NewGuid()+'.clixml')) -ErrorAction Stop
        $parts=@($path -split ';' | Where-Object {([Environment]::ExpandEnvironmentVariables($_).Trim('"').TrimEnd('\')) -ine 'C:\temp'})
        [Environment]::SetEnvironmentVariable('Path',($parts -join ';'),$scope)
        [Environment]::SetEnvironmentVariable('SSLKEYLOGFILE',$null,$scope)
        if([Environment]::GetEnvironmentVariable('SSLKEYLOGFILE',$scope)){throw 'SSL key-log binding remains set.'}
    }
    Remove-Item Env:\SSLKEYLOGFILE -ErrorAction SilentlyContinue
    Write-Ok 'Selected persistent environment bindings removed. Start new processes to use the updated PATH.'
}

function Invoke-ServerForensics {
    Write-Host 'Read-only server investigation. Finish evidence collection before disabling accounts or removing scripts/certificates.'
    Write-Host '1 AD display-specifier menu inventory  2 file hash/signature/certificate  3 SYSVOL script inventory  4 packet-capture guidance'
    switch(Read-Host 'Choice') {
        '1' {$root=Get-ADRootDSE -ErrorAction Stop;Get-ADObject -SearchBase ('CN=DisplaySpecifiers,'+$root.configurationNamingContext) -LDAPFilter '(adminContextMenu=*)' -Properties adminContextMenu -ErrorAction Stop | Select-Object DistinguishedName,adminContextMenu | Format-List | Out-Host}
        '2' {
            $path=Get-WarriorTarget 'Exact DLL/executable/script path from your actual question'
            Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop | Format-List | Out-Host
            $signature=Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
            [pscustomobject]@{Status=$signature.Status;Subject=$signature.SignerCertificate.Subject;Issuer=$signature.SignerCertificate.Issuer;Thumbprint=$signature.SignerCertificate.Thumbprint;NotAfter=$signature.SignerCertificate.NotAfter} | Format-List | Out-Host
            Write-Host 'A certificate name or signature alone does not establish trust. Compare the exact thumbprint and chain with trusted reference data.'
        }
        '3' {
            $share=Get-SmbShare -Name SYSVOL -ErrorAction Stop
            Get-ChildItem -LiteralPath $share.Path -Recurse -File -ErrorAction SilentlyContinue | Where-Object Extension -in '.ps1','.vbs','.bat','.cmd' | Select-Object FullName,Length,LastWriteTimeUtc | Format-Table -AutoSize | Out-Host
            Write-Host 'Inspect selected files manually. Scripts are not executed and plaintext credentials are not printed by this inventory.'
        }
        '4' {Write-Host 'Open the actual PCAP in Wireshark. Set Preferences > Protocols > TLS > (Pre)-Master-Secret log filename to the preserved key-log file. Inspect DNS/mDNS and decrypted request URLs. Image-specific URLs and answers are never assumed.'}
    }
}

function Get-ServerAnswerKeyChecklist {
    @(
        [pscustomobject]@{Area='AD users';Tools='Role-aware audit; targeted disable, Domain Admin membership, DES-only, SID history, password flags';Review='Use current README/comments. Preserve disabled accounts/info; never delete accounts.'},
        [pscustomobject]@{Area='Domain policy';Tools='Verified default domain password/lockout policy; machine-account quota; GPO Read+Apply permissions';Review='FGPP, inherited permissions and required join workflows need review.'},
        [pscustomobject]@{Area='Directory roles';Tools='LDAP signing, secure DNS zone updates, optional DNS recursion/version controls, DHCP authorization/auditing/name protection';Review='NSPI anonymous RPC/LDAP access needs a separate protocol-specific review; no guessed registry control is applied.'},
        [pscustomobject]@{Area='Defender';Tools='PSExec/WMI ASR, provider-supported DNS sinkhole, sandbox request, read-only PPL status';Review='PPL repairs use supported Defender servicing. No LaunchProtected registry bypass.'},
        [pscustomobject]@{Area='Permissions/IPsec';Tools='Existing user-rights and server inventory; review service/channel ACLs and IPsec crypto sets';Review='Do not replace all rights/ACLs or VPN crypto settings with a workstation template.'},
        [pscustomobject]@{Area='Persistence/forensics';Tools='AD context-menu inventory/removal, file signing/hash, SYSVOL scripts, packet-capture guidance, targeted task/service/file cleanup';Review='Do not remove Microsoft-named certificates without exact thumbprint/evidence. Preserve PCAP/key logs first.'},
        [pscustomobject]@{Area='Image-specific items';Tools='Software inventory; reviewed legacy-feature removal; exact C:\temp PATH and SSLKEYLOGFILE cleanup';Review='IPv6, quotas, partitions, WPBT/ProtectedRoots and certificates require individual verification. No disk deletion or undocumented security toggles are automated.'},
        [pscustomobject]@{Area='Reference: undocumented controls';Tools='The supplied answer key mentions HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots\Flags=1 and HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\DisableWpbtExecution=1.';Review='Reference information only: these undocumented controls are not applied automatically or treated as proof of protection.'},
        [pscustomobject]@{Area='Reference: ACLs and IPsec';Tools='Review sc.exe sdshow EventLog; Get-WinEvent -ListLog Security; Get-NetIPsecMainModeCryptoSet -PolicyStore ActiveStore; Get-NetIPsecQuickModeCryptoSet -PolicyStore ActiveStore.';Review='Remove unauthorized Everyone write/control rights with a verified ACL plan. Choose mutually supported DH/SHA algorithms for IPsec peers; do not overwrite every ACL or crypto set.'}
    )
}

function Invoke-ServerBaseline {
    Write-Host 'Server baseline: firewall enable/logging, UAC/logon registry baseline, auditing, automatic-update configuration.'
    Write-Host 'It preserves server roles, WSUS, RDP/SSH, IPv6, shares, domain accounts, user rights and installed features. Domain/user/role changes are reviewed separately.'
    if(-not (Confirm-Action 'Have you completed forensics and reviewed this server baseline?' $false)){return}
    $before=$script:FailureCount;$script:Auto=$true
    try {Enable-WindowsFirewall;Enable-UAC;Set-ServerRegistryBaseline;Enable-Auditing;Enable-AutoUpdate}
    finally {$script:Auto=$false}
    if($script:FailureCount -gt $before){Write-Bad 'Server baseline had errors; inspect the transcript.'}
    else {Write-Host 'Selected baseline steps finished. Use option 26 for domain policy/accounts and role-specific settings; verify required services from a remote client.'}
}

function Invoke-ServerRoleManager {
    if(-not (Test-ToolkitServer)){throw 'These workflows require the Server 2022 script on Windows Server.'}
    do {
        Write-Section 'Server 2022 - role-aware management'
        Write-Host "Domain controller: $($script:ToolkitPlatform.IsDomainController); domain: $($script:ToolkitPlatform.Domain)"
        Write-Host ('Installed roles/features: '+($script:ToolkitPlatform.Roles -join ', '))
        Write-Host 'R load image README  S services  V verify required services/ports  1 role-based AD audit  2 targeted AD user'
        Write-Host '3 domain password policy  4 domain lockout  5 LDAP signing  6 DNS  7 DHCP  8 machine-account quota'
        Write-Host '9 GPO Authenticated Users permissions  10 Domain Users backup right  11 Defender  12 environment cleanup'
        Write-Host '13 AD context-menu review/removal  14 AD group plan  15 create approved AD user  F forensics  K answer-key coverage/review  0 back'
        $choice=Read-Host 'Choice'
        try {
            switch -Regex ($choice) {
                '^0$' {return};'^[rR]$' {Import-ServerImageRules};'^[sS]$' {Invoke-ServiceManager}
                '^[vV]$' {Get-RequiredServiceChecks | Format-Table -AutoSize -Wrap | Out-Host}
                '^1$' {Invoke-ServerAdAccountAudit};'^2$' {Invoke-TargetedAdUserAction}
                '^3$' {Set-ServerDomainAccountPolicy Password};'^4$' {Set-ServerDomainAccountPolicy Lockout}
                '^5$' {Set-ServerLdapSigning};'^6$' {Invoke-ServerDnsAction};'^7$' {Invoke-ServerDhcpAction}
                '^8$' {Set-ServerMachineAccountQuota};'^9$' {Set-ServerGpoReadApplyPermission};'^10$' {Remove-ServerDomainUsersBackupRight}
                '^11$' {Invoke-ServerDefenderExtras};'^12$' {Invoke-ServerEnvironmentCleanup};'^13$' {Invoke-ServerDisplaySpecifierReview}
                '^14$' {Invoke-ServerAdGroupPlan};'^15$' {New-ApprovedServerAdUser}
                '^[fF]$' {Invoke-ServerForensics};'^[kK]$' {Get-ServerAnswerKeyChecklist | Format-List | Out-Host}
            }
        } catch {Write-Bad "Server action failed: $($_.Exception.Message)"}
    } while($true)
}

function Invoke-ServerAdGroupPlan {
    $domain=Get-CurrentAdDomain
    $name=Get-WarriorTarget 'Exact AD group sAMAccountName from this image'
    $group=Get-ADGroup -Filter {SamAccountName -eq $name} -ErrorAction Stop
    $names=@((Read-Host 'Approved user sAMAccountNames, comma separated') -split ',' | ForEach-Object {$_.Trim()} | Where-Object {$_} | Select-Object -Unique)
    if(-not $names.Count){return}
    $users=@($names | ForEach-Object {Get-ADUser -Identity $_ -ErrorAction Stop})
    $members=if($group){@(Get-ADGroupMember -Identity $group -ErrorAction Stop)}else{@()}
    $isAdmin=$group -and $group.SID.Value -eq ($domain.DomainSID.Value+'-512')
    if($isAdmin -and $script:ServerImageRules -and $script:ServerImageRules.DomainAdmins.Count) {
        foreach($user in $users){if($script:ServerImageRules.DomainAdmins -notcontains $user.SamAccountName){throw "$($user.SamAccountName) is not an approved Domain Admin."}}
    }
    $match=Confirm-Action 'Remove other direct USER members so the group matches this list? Nested groups and current user are preserved.' $false
    $adds=@($users | Where-Object {$members.SID.Value -notcontains $_.SID.Value})
    $removes=@($members | Where-Object {$match -and $_.objectClass -eq 'user' -and $users.SID.Value -notcontains $_.SID.Value -and $_.SamAccountName -ine $script:CurrentUserName -and -not(Test-PasswordProtectedAccount $_.SamAccountName)})
    Write-Host "Group: $name; create: $(-not [bool]$group); add: $($adds.SamAccountName -join ', '); remove membership: $($removes.SamAccountName -join ', ')"
    if(-not (Confirm-Action 'Apply this exact AD group plan?' $false)){return}
    $members | Export-Clixml -LiteralPath (Join-Path $script:LogDir ('AD-group-'+[guid]::NewGuid()+'.clixml')) -ErrorAction Stop
    if(-not $group){$group=New-ADGroup -Name $name -SamAccountName $name -GroupScope Global -GroupCategory Security -PassThru -ErrorAction Stop}
    foreach($user in $adds){Add-ADGroupMember -Identity $group -Members $user -ErrorAction Stop}
    foreach($user in $removes){Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false -ErrorAction Stop}
    $after=@(Get-ADGroupMember -Identity $group -ErrorAction Stop)
    if(@($adds | Where-Object {$after.SID.Value -notcontains $_.SID.Value}).Count -or @($removes | Where-Object {$after.SID.Value -contains $_.SID.Value}).Count){throw 'AD group membership read-back did not match.'}
    Write-Ok 'AD group plan verified. No accounts were deleted or enabled.'
}

function New-ApprovedServerAdUser {
    $domain=Get-CurrentAdDomain
    if(-not $script:ServerImageRules -or -not $script:ServerImageRules.TownRoles.Count){throw 'Load the current role-based README first.'}
    $name=Get-WarriorTarget 'New authorized user sAMAccountName'
    if($name -notmatch '^[A-Za-z0-9._-]{1,20}$'){throw 'Use a valid local-format sAMAccountName of at most 20 characters.'}
    $roles=@($script:ServerImageRules.TownRoles)
    for($i=0;$i -lt $roles.Count;$i++){Write-Host "$($i+1)) $($roles[$i])"}
    $pick=Read-Host 'Approved Town role number (Enter cancels)'
    if($pick -notmatch '^\d+$' -or [int]$pick -lt 1 -or [int]$pick -gt $roles.Count){return}
    $role=$roles[[int]$pick-1]
    $path=Read-Host "OU/container DN (Enter = $($domain.UsersContainer))"
    if(-not $path){$path=$domain.UsersContainer}
    Write-Host "Create enabled standard domain user $name; role comment $role; container $path; configured default password. No administrator rights are granted."
    if(-not (Confirm-Action 'Create this authorized domain account?' $false)){return}
    New-ADUser -Name $name -SamAccountName $name -Path $path -Description $role -AccountPassword (Get-DefaultAccountPassword) -Enabled $true -PasswordNeverExpires $false -ErrorAction Stop
    $after=Get-ADUser -Identity $name -Properties Description -ErrorAction Stop
    if(-not $after.Enabled -or $after.Description -ne $role){throw 'New account did not match the requested state.'}
    Write-Ok 'Authorized AD account created. Additional group rights require a separate reviewed plan.'
}


# All helpers above are embedded. Nothing is loaded from old/ or another script.
$script:ToolkitPlatform=Get-ToolkitPlatform
if($ToolkitTarget -eq 'Server2022' -and -not $script:ToolkitPlatform.IsServer2022){Write-Error 'Use LOMAGOSH-Server2022.ps1 only on Windows Server 2022 (build 20348). No hardening changes were made.';exit 1}
if($ToolkitTarget -eq 'Windows11' -and ($script:ToolkitPlatform.IsServer -or $script:ToolkitPlatform.Build -lt 22000)){Write-Error 'Use LOMAGOSH-Windows11.ps1 only on Windows 11. Use the Server 2022 file for a supported server.';exit 1}
Write-Host "LOMAGOSH by Jasiah O | $($script:ToolkitPlatform.Caption) | domain controller: $($script:ToolkitPlatform.IsDomainController)"
Save-PreHardeningNetworkSnapshot

# Initial prompt
Clear-Host
$answer = Read-Host "Have you answered all the forensics questions? [y/n]"
if ($answer -ne 'y') {
    if ((Get-Command Invoke-WarriorForensics -ErrorAction SilentlyContinue) -and
        (Confirm-Action 'Open the read-only Windows Warrior forensics helpers first?' $true)) {
        Invoke-WarriorForensics
    }
    if (-not (Confirm-Action 'Have you saved your forensics answers and are you ready to start hardening?' $false)) {
        try { Stop-Transcript | Out-Null } catch {}
        exit
    }
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
            '8'  { Invoke-ServiceManager }
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
            '24' { Invoke-WindowsWarrior }
            '25' { Set-GlobalObjectAuditing }
            '26' { Invoke-ServerRoleManager }
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
