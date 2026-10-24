#Requires -Version 5.1
<#
Guided companion for CyberPatriot-Win11-Hardening.ps1; run Run-Hardening.cmd.
Contains declarations only. Importing this file performs no hardening.
#>
function Get-WarriorTasks {
    # Id | title | illustrative command | explanation | GUI path
    $catalog = @'
1|Disable Guest|Disable-LocalUser -Name Guest|Disables the built-in Guest account, including renamed Guest accounts.|lusrmgr.msc > Users > Guest > Properties > Account is disabled
2|Disable built-in Administrator|Disable-LocalUser -Name Administrator|Disables the built-in administrator; protects the account running this tool.|lusrmgr.msc > Users > Administrator > Properties > Account is disabled
3|Disable unauthorized hacker account|Disable-LocalUser -Name hacker|Disables hacker and removes its administrator membership. Accounts are NEVER deleted, including in this tutorial.|lusrmgr.msc > Users > hacker > Properties > Account is disabled
4|Remove webdev from Administrators|Remove-LocalGroupMember -Group Administrators -Member webdev|Removes administrator privileges while preserving the webdev account.|lusrmgr.msc > Groups > Administrators > webdev > Remove
5|Require a password for intern|Set-LocalUser -Name intern -Password (Read-Host -AsSecureString); net.exe user intern /passwordreq:yes|Prompts securely for a password of at least 12 characters; never uses the tutorial's shared example password.|lusrmgr.msc > Users > intern > Set Password; Properties > require a password
6|Make contractor password expire|Set-LocalUser -Name contractor -PasswordNeverExpires $false|Subjects contractor to the account password-expiration policy.|lusrmgr.msc > Users > contractor > Properties > clear Password never expires
7|Create standard user analyst|New-LocalUser -Name analyst -Password (Read-Host -AsSecureString)|Creates analyst if absent, adds it to Users and ensures it is not an administrator.|lusrmgr.msc > Users > New User; Groups > Users > Add analyst
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

function Read-WarriorPassword {
    param([string]$Account)
    $password = Read-Host "New password for $Account (at least 12 characters)" -AsSecureString
    if ($password.Length -lt 12) { throw 'Password must be at least 12 characters; the system complexity policy also applies.' }
    $password
}

function Stop-WarriorService {
    param([string]$Name)
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service) { Write-Host "$Name is already absent."; return }
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
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $system = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    switch ($Id) {
        1 { Disable-WarriorAccount -BuiltinRid '501' }
        2 { Disable-WarriorAccount -BuiltinRid '500' }
        3 { $name = Get-WarriorTarget 'Unauthorized local username to DISABLE' Unauthorized; Disable-WarriorAccount -Name $name; if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) { Remove-WarriorAdminMembership -Name $name } }
        4 { Remove-WarriorAdminMembership -Name (Get-WarriorTarget 'Standard user who should not be an administrator' Standard) }
        5 {
            $name = Get-WarriorTarget 'Authorized account requiring a new password' Authorized
            Set-LocalUser -Name $name -Password (Read-WarriorPassword $name) -ErrorAction Stop
            Invoke-NativeCommand -FilePath net.exe -ArgumentList @('user', $name, '/passwordreq:yes') | Out-Null
        }
        6 { Set-LocalUser -Name (Get-WarriorTarget 'Authorized account whose password must expire' Authorized) -PasswordNeverExpires $false -ErrorAction Stop }
        7 {
            $name = Get-WarriorTarget 'Authorized standard account to create or reconcile' Authorized
            if ($name -eq $script:CurrentUserName -or ($script:WarriorReadmePlan -and $script:WarriorReadmePlan.Admins -contains $name)) {
                throw 'This account is the current user or an approved administrator; it cannot be reconciled as a standard user.'
            }
            if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) {
                New-LocalUser -Name $name -Password (Read-WarriorPassword $name) -PasswordNeverExpires:$false -ErrorAction Stop | Out-Null
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
    $results
}

function Invoke-WarriorForensics {
    Write-Section 'Read-only forensics helpers for the current image'
    Write-Host 'These are four investigation topics, not assumptions about question numbering or answers. Match the evidence to your actual question files.'
    $question = Read-Host 'Path to an actual forensics question file to read (Enter skips)'
    if (-not [string]::IsNullOrWhiteSpace($question)) {
        Write-Host (Get-ReadmeText -Path $question)
    }
    $task = Read-Host 'Exact scheduled task name requested by your question (Enter inventories tasks)'
    $startup = Read-Host 'Exact HKLM Run value requested by your question (Enter inventories startup values)'
    $results = @(Get-WarriorForensicFindings -ScheduledTaskName $task -StartupValueName $startup)
    $report = Join-Path $script:LogDir ('Windows-Warrior-Forensics-' + [guid]::NewGuid() + '.txt')
    $text = $results | Format-List Topic, Status, SuggestedAnswer, Evidence | Out-String -Width 240
    Write-Host $text
    $text | Set-Content -LiteralPath $report -Encoding UTF8 -ErrorAction Stop
    Write-Host "Evidence report: $report"
    Write-Host 'Review the evidence, enter answers after ANSWER: in the original Desktop question files, and save them. This helper never submits or edits answers.'
}

function Invoke-ImageGroupPlan {
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
        Write-Section 'Guided hardening - 50 example tasks and 4 forensics helpers'
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
