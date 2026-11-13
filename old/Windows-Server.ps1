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
        $body=[regex]::Replace($body,'(?im)^\s*(?:Town|Coven)\s+(?:Investigative|Protective|Killing|Support|Power|Deception|Utility)\s*:','')
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
    $service=Get-Service -Name sshd -ErrorAction Stop
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
            if($profile.Count -ne 1 -or [string]$profile[0].Enabled -ne 'True'){throw "Firewall profile $name is not enabled in $store."}
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
    $session.ClientApplicationID='CyberPatriot Server 2022 Toolkit'
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
