#Requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$tokens=$null;$errors=$null
$tree=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'LOMAGOSH-Server2022.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
foreach($node in $tree.EndBlock.Statements){if($node -is [System.Management.Automation.Language.FunctionDefinitionAst]){. ([scriptblock]::Create($node.Extent.Text))}}
$script:passed=0;$script:actions=@();$script:good=@();$script:bad=@()
function Assert-True($Value,$Message){if(-not $Value){throw "FAILED: $Message"}}
function Test-Case($Name,[scriptblock]$Action){& $Action;$script:passed++;Write-Host "PASS: $Name"}
function Confirm-Action {return $true}
function Write-Section($Text){}
function Write-Ok($Text){$script:good+=$Text}
function Write-Bad($Text){$script:bad+=$Text;$script:FailureCount++}
function Write-Warn($Text){}
function Wait-Key{}
$script:input=New-Object 'System.Collections.Generic.Queue[string]'
function Read-Host {param($Prompt) if(-not $script:input.Count){throw "Unexpected prompt: $Prompt"};$script:input.Dequeue()}
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('lomagosh-server-tests-'+[guid]::NewGuid())
$null=[IO.Directory]::CreateDirectory($temporary)
$script:LogDir=$temporary;$script:CurrentUserName='operator';$script:FailureCount=0
$PwMinLen=14;$PwHistory=24;$PwMinAge=1;$PwMaxAge=60;$LockThreshold=5;$LockDuration=30;$LockWindow=30
$script:fixture=@'
Windows Server 2022 Example README
Critical Services:
 AD DS
 DNS
 RDP
 SSH
The Town has decided on port 223 as the port for SSH.
User Auditing
Disabled accounts move to the Graveyard group. Keep them disabled; preserve info.
AUTHORIZED Town roles:
 Town Investigative : Sheriff, Investigator
 Town Power : Jailor, Mayor
UNAUTHORIZED Coven roles:
 Coven Power : Witch, Hex Master
 Coven Utility : Poisoner, Voodoo
                 Master, Wildling
Authorized Administrators
Domain Admins:
operator (you)
 password: ignored-example-value
friend
 password: ignored-example-value
Competition Guidelines
The primary, auto-login, user account (operator) must be preserved.
Do not disable or stop the CSSClient service or process.
'@
function Set-FakeServerContext {
    $script:ToolkitPlatform=[pscustomobject]@{IsServer=$true;IsServer2022=$true;IsDomainController=$true;DomainJoined=$true;Domain='example.test';ComputerName='DC1';Roles=@('AD-Domain-Services','DNS');RolesKnown=$true;AutoLogonUser='operator'}
    $script:ServerImageRules=Read-ServerImageRules -Text $script:fixture
}
$script:services=@{}
function Add-FakeService($Name,$Status='Running',$Type='Automatic'){$script:services[$Name]=[pscustomobject]@{Name=$Name;DisplayName=$Name;Status=$Status;StartType=$Type;DependentServices=@()}}
function Get-Service {
    param($Name,$ErrorAction)
    if($Name){if($script:services.ContainsKey($Name)){$script:services[$Name]};return}
    $script:services.Values
}
function Set-Service {param($Name,$StartupType,$ErrorAction) $script:actions+='SetService';$script:services[$Name].StartType=$StartupType}
function Start-Service {param($Name,$ErrorAction) $script:actions+='StartService';$script:services[$Name].Status='Running'}
function Stop-Service {param($Name,$ErrorAction) $script:actions+='StopService';$script:services[$Name].Status='Stopped'}
try {
    Test-Case 'Both branded files are standalone and select their own edition' {
        $client=[IO.File]::ReadAllText((Join-Path $root 'LOMAGOSH-Windows11.ps1'))
        $server=[IO.File]::ReadAllText((Join-Path $root 'LOMAGOSH-Server2022.ps1'))
        Assert-True ($client -match '\$ToolkitTarget = ''Windows11''' -and $server -match '\$ToolkitTarget = ''Server2022''') 'Explicit edition selectors'
        Assert-True ($client -match 'LOMAGOSH by Jasiah O' -and $server -match 'LOMAGOSH by Jasiah O') 'Requested branding'
        $left=$client -replace '(?m)^\$ToolkitTarget = .*$','EDITION'
        $right=$server -replace '(?m)^\$ToolkitTarget = .*$','EDITION'
        Assert-True ($left -ceq $right) 'Shared implementation stays consistent'
        $dots=$tree.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot},$true)
        Assert-True ($dots.Count -eq 0) 'No external script dot-sourcing'
        foreach($function in 'Get-ToolkitPlatform','Initialize-WindowsPolicyApi','Invoke-ServiceManager','Invoke-ServerAdAccountAudit','Invoke-WindowsWarrior'){
            Assert-True (@($tree.EndBlock.Statements | Where-Object {$_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $function}).Count -eq 1) 'Required helper embedded exactly once'
        }
    }
    Test-Case 'Current-image rules parse critical services, SSH 223, primary account and multiline roles without storing passwords' {
        Set-FakeServerContext
        $rules=$script:ServerImageRules
        Assert-True ($rules.RequiredServices.Count -eq 5 -and $rules.RequiredServices -contains 'sshd' -and $rules.RequiredServices -contains 'CSSClient') 'AD DS/DNS/RDP/SSH/CSSClient required'
        Assert-True ($rules.SshPort -eq 223 -and $rules.PrimaryAccount -eq 'operator') 'Actual image port and primary account parsed'
        Assert-True ($rules.CovenRoles -contains 'Voodoo Master' -and $rules.TownRoles -contains 'Jailor') 'Multiline role names normalized'
        Assert-True ($rules.DomainAdmins.Count -eq 2 -and ($rules | ConvertTo-Json -Depth 4) -notmatch 'ignored-example-value') 'Admin list excludes password lines'
    }
    Test-Case 'Server 2022/DC discovery reads names but never stored auto-login passwords' {
        $script:registryNames=@()
        function Get-CimInstance {param($ClassName,$ErrorAction) if($ClassName -eq 'Win32_OperatingSystem'){[pscustomobject]@{ProductType=2;BuildNumber='20348';Caption='Windows Server 2022'}}else{[pscustomobject]@{DomainRole=5;PartOfDomain=$true;Domain='example.test';Name='DC1'}}}
        function Get-WindowsFeature {param($ErrorAction) @([pscustomobject]@{Name='DNS';Installed=$true},[pscustomobject]@{Name='DHCP';Installed=$false})}
        function Get-ItemPropertyValue {param($LiteralPath,$Name,$ErrorAction) $script:registryNames+=$Name;if($Name -eq 'AutoAdminLogon'){'1'}else{'operator'}}
        $context=Get-ToolkitPlatform
        Assert-True ($context.IsServer2022 -and $context.IsDomainController -and $context.RolesKnown -and $context.Roles.Count -eq 1) 'OS/role context detected'
        Assert-True ($script:registryNames.Count -eq 2 -and $script:registryNames -notcontains 'DefaultPassword') 'No credential read'
    }
    Test-Case 'Workstation discovery does not query server roles' {
        function Get-CimInstance {param($ClassName,$ErrorAction) if($ClassName -eq 'Win32_OperatingSystem'){[pscustomobject]@{ProductType=1;BuildNumber='26100';Caption='Windows 11'}}else{[pscustomobject]@{DomainRole=0;PartOfDomain=$false;Domain='WORKGROUP';Name='PC1'}}}
        function Get-WindowsFeature {throw 'Should not query workstation server roles'}
        function Get-ItemPropertyValue {param($LiteralPath,$Name,$ErrorAction) $null}
        Assert-True (-not (Get-ToolkitPlatform).IsServer) 'Windows 11 profile discovered independently'
    }
    Test-Case 'Server 2019 is not mislabeled as Server 2022' {
        function Get-CimInstance {param($ClassName,$ErrorAction) if($ClassName -eq 'Win32_OperatingSystem'){[pscustomobject]@{ProductType=3;BuildNumber='17763';Caption='Windows Server 2019'}}else{[pscustomobject]@{DomainRole=2;PartOfDomain=$false;Domain='WORKGROUP';Name='OLD'}}}
        function Get-WindowsFeature {param($ErrorAction) @()}
        function Get-ItemPropertyValue {param($LiteralPath,$Name,$ErrorAction) $null}
        $context=Get-ToolkitPlatform
        Assert-True ($context.IsServer -and -not $context.IsServer2022) 'Unsupported build detected'
    }
    Test-Case 'Required/role/management services cannot be stopped by general cleanup' {
        Set-FakeServerContext
        foreach($name in 'NTDS','Kdc','DNS','TermService','sshd','CSSClient','WinRM','EventLog'){
            Assert-True ([bool](Get-ServerServiceBlockReason $name)) 'Required service protected'
        }
        $script:ToolkitPlatform.RolesKnown=$false
        Assert-True ([bool](Get-ServerServiceBlockReason 'AnyOtherService')) 'Unknown roles fail closed for service stops'
        Set-FakeServerContext
    }
    Test-Case 'Auto-login and README-primary password protection are case-insensitive' {
        Set-FakeServerContext
        Assert-True (Test-PasswordProtectedAccount 'EXAMPLE\OPERATOR') 'Auto-login primary protected'
        Assert-True (-not (Test-PasswordProtectedAccount 'another')) 'Other targets remain selectable'
    }
    Test-Case 'Service manager enables Automatic and starts an installed service with read-back' {
        Set-FakeServerContext;$script:services=@{};$script:actions=@();Add-FakeService 'ExampleService' Stopped Disabled
        Set-ToolkitServiceState -Name ExampleService -StartupType Automatic
        Assert-True ($script:services.ExampleService.Status -eq 'Running' -and $script:services.ExampleService.StartType -eq 'Automatic' -and $script:actions.Count -eq 2) 'Enabled/started exactly selected service'
    }
    Test-Case 'Service manager stops/disables an explicitly selected noncritical service' {
        Set-FakeServerContext;$script:services=@{};$script:actions=@();Add-FakeService 'ExampleService'
        Set-ToolkitServiceState -Name ExampleService -StartupType Disabled
        Assert-True ($script:services.ExampleService.Status -eq 'Stopped' -and $script:services.ExampleService.StartType -eq 'Disabled') 'Disabled/stopped selected service'
    }
    Test-Case 'Service manager refuses CSSClient disable before any write' {
        Set-FakeServerContext;$script:services=@{};$script:actions=@();Add-FakeService CSSClient
        $caught=$false;try{Set-ToolkitServiceState -Name CSSClient -StartupType Disabled}catch{$caught=$true}
        Assert-True ($caught -and $script:actions.Count -eq 0) 'Scoring-client service preserved'
    }
    Test-Case 'Stopping a dependency of a protected running role service is refused' {
        Set-FakeServerContext;$script:services=@{};Add-FakeService 'ExampleDependency'
        $script:services.ExampleDependency.DependentServices=@([pscustomobject]@{Name='NTDS';Status='Running'})
        $caught=$false;try{Assert-ServiceCanStop ExampleDependency}catch{$caught=$true}
        Assert-True $caught 'Required dependent role preserved'
    }
    Test-Case 'Exact service selection rejects wildcard-like names' {
        Set-FakeServerContext;$script:services=@{};$script:actions=@();Add-FakeService ExampleService
        $caught=$false;try{Set-ToolkitServiceState -Name 'Example*' -StartupType Disabled}catch{$caught=$true}
        Assert-True ($caught -and $script:actions.Count -eq 0) 'No broad service mutation'
    }
    Test-Case 'Required service checks include local TCP probes for SSH 223 rather than status alone' {
        Set-FakeServerContext;$script:services=@{};foreach($name in $script:ServerImageRules.RequiredServices){Add-FakeService $name}
        function Get-NetTCPConnection {param($State,$ErrorAction) foreach($port in 53,88,135,389,445,3389,223){[pscustomobject]@{LocalPort=$port;OwningProcess=100}}}
        function Test-NetConnection {param($ComputerName,$Port,$InformationLevel,$WarningAction) $true}
        $checks=@(Get-RequiredServiceChecks)
        $ssh=@($checks | Where-Object {$_.Check -eq 'Local TCP reachability' -and $_.Name -eq '223'})
        Assert-True ($ssh.Count -eq 1 -and $ssh[0].Result -eq 'Local probe passed' -and $ssh[0].Detail -match 'separate client') 'Local and remote evidence distinguished'
    }
    Test-Case 'SSH port rewrite preserves other settings and Match blocks' {
        $before="# preserved`nPort 22`nPort 2222`nPasswordAuthentication yes`nMatch User sample`n    AllowTcpForwarding no"
        $after=Set-SshPortText -Text $before -Port 223
        Assert-True ($after.StartsWith('Port 223') -and ($after -split '\r?\n' | Where-Object {$_ -match '^Port '}).Count -eq 1) 'One intended global port'
        Assert-True ($after -match 'PasswordAuthentication yes' -and $after -match 'Match User sample' -and $after -match 'AllowTcpForwarding no') 'Other authentication policy retained'
    }
    Test-Case 'Role classifier distinguishes authorized, unauthorized, unknown and ambiguous comments' {
        Assert-True ((Get-ImageRoleClassification 'Town Power: Jailor' @('Sheriff','Jailor') @('Witch')) -eq 'Town') 'Town role recognized'
        Assert-True ((Get-ImageRoleClassification 'Witch' @('Sheriff') @('Witch')) -eq 'Coven') 'Coven role recognized'
        Assert-True ((Get-ImageRoleClassification 'Sheriff and Witch' @('Sheriff') @('Witch')) -eq 'Ambiguous') 'Conflicting roles need review'
        Assert-True ((Get-ImageRoleClassification 'other notes' @('Sheriff') @('Witch')) -eq 'Unknown') 'No arbitrary role inferred'
    }
    Test-Case 'Account plan preserves Town/current/built-in users and disabled wills while targeting Coven/admin memberships' {
        Set-FakeServerContext
        $users=@(
            [pscustomobject]@{SamAccountName='operator';Enabled=$true;Description='Jailor';SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-1001'};info='primary will'},
            [pscustomobject]@{SamAccountName='townie';Enabled=$true;Description='Sheriff';SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-1002'};info='town will'},
            [pscustomobject]@{SamAccountName='enemy';Enabled=$true;Description='Witch';SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-1003'};info='preserve'},
            [pscustomobject]@{SamAccountName='dead';Enabled=$false;Description='Sheriff';SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-1004'};info='dead will'},
            [pscustomobject]@{SamAccountName='unknown';Enabled=$true;Description='unclear';SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-1005'};info=''},
            [pscustomobject]@{SamAccountName='krbtgt';Enabled=$false;Description='';SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-502'};info=''}
        )
        $plan=@(Get-ServerAdAccountPlan -Users $users -DomainAdminMembers @('operator','townie','enemy'))
        Assert-True (@($plan | Where-Object Name -eq operator)[0].Actions.Count -eq 0) 'Primary protected'
        $town=@($plan | Where-Object Name -eq townie)[0];$enemy=@($plan | Where-Object Name -eq enemy)[0]
        Assert-True ($town.Actions -contains 'RemoveDomainAdmin' -and $town.Actions -notcontains 'Disable') 'Standard Town account preserved, unauthorized privilege removed'
        Assert-True ($enemy.Actions -contains 'Disable' -and $enemy.Actions -contains 'EnsureGraveyard') 'Coven disabled instead of deleted'
        Assert-True (@($plan | Where-Object Name -eq dead)[0].Actions -contains 'EnsureGraveyard' -and $users[3].info -eq 'dead will' -and -not $users[3].Enabled) 'Dead account state/will preserved'
        Assert-True (@($plan | Where-Object Name -eq unknown)[0].Actions.Count -eq 0 -and @($plan | Where-Object Name -eq krbtgt)[0].Actions.Count -eq 0) 'Unknown and krbtgt not swept into cleanup'
    }
    Test-Case 'Domain-controller account guard rejects local SAM operations' {
        Set-FakeServerContext
        $caught=$false;try{Assert-LocalAccountWorkflow}catch{$caught=$true}
        Assert-True $caught 'AD workflow required on DC'
    }
    Test-Case 'Applying the role-based AD audit preserves wills/disabled accounts and verifies exact group changes' {
        Set-FakeServerContext
        $script:directory=@{}
        foreach($row in @(
            @('operator','Jailor',$true,1001),@('townie','Sheriff',$true,1002),@('enemy','Witch',$true,1003),@('dead','Sheriff',$false,1004),@('unknown','unclassified',$true,1005),@('friend','Mayor',$true,1006),@('krbtgt','',$false,502)
        )) {
            $name=[string]$row[0]
            $script:directory[$name]=[pscustomobject]@{SamAccountName=$name;Name=$name;DistinguishedName="CN=$name,DC=example,DC=test";Enabled=[bool]$row[2];Description=[string]$row[1];SID=[pscustomobject]@{Value="S-1-5-21-1-2-3-$($row[3])"};info="preserve-$name";objectClass='user'}
        }
        $script:members=@{'Domain Admins'=@('operator','townie','enemy')};$script:grave=$null
        function Get-CurrentAdDomain {[pscustomobject]@{DNSRoot='example.test';DomainSID=[pscustomobject]@{Value='S-1-5-21-1-2-3'}}}
        function Get-ADUser {
            param($Identity,$Filter,$Properties,$ErrorAction)
            if($Filter){$script:directory.Values;return}
            if($Identity -is [string]) {$script:directory.Values | Where-Object {$_.SamAccountName -eq $Identity -or $_.DistinguishedName -eq $Identity}}else{$script:directory[$Identity.SamAccountName]}
        }
        function Get-ADGroup {
            param($Identity,$Filter,$ErrorAction)
            if($Identity){[pscustomobject]@{SamAccountName='Domain Admins';Name='Domain Admins';SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-512'}}}elseif($script:grave){$script:grave}
        }
        function Get-ADGroupMember {param($Identity,$ErrorAction) foreach($name in @($script:members[$Identity.SamAccountName])){if($name){$script:directory[$name]}}}
        function Disable-ADAccount {param($Identity,$ErrorAction) foreach($user in $script:directory.Values){if($user.DistinguishedName -eq $Identity){$user.Enabled=$false}}}
        function Remove-ADGroupMember {param($Identity,$Members,$Confirm,$ErrorAction) $name=@($script:directory.Values | Where-Object DistinguishedName -eq $Members)[0].SamAccountName;$script:members[$Identity.SamAccountName]=@($script:members[$Identity.SamAccountName] | Where-Object {$_ -ne $name})}
        function Add-ADGroupMember {param($Identity,$Members,$ErrorAction) $name=@($script:directory.Values | Where-Object DistinguishedName -eq $Members)[0].SamAccountName;$script:members[$Identity.SamAccountName]=@($script:members[$Identity.SamAccountName])+$name}
        function New-ADGroup {param($Name,$SamAccountName,$GroupScope,$GroupCategory,[switch]$PassThru,$ErrorAction) $script:grave=[pscustomobject]@{SamAccountName=$SamAccountName;Name=$Name};$script:members[$SamAccountName]=@();$script:grave}
        Invoke-ServerAdAccountAudit
        Assert-True (-not $script:directory.enemy.Enabled -and -not $script:directory.dead.Enabled -and $script:directory.townie.Enabled) 'Only confirmed Coven disabled; dead not enabled; Town retained'
        Assert-True ($script:members['Domain Admins'] -contains 'friend' -and $script:members['Domain Admins'] -notcontains 'townie' -and $script:members['Domain Admins'] -notcontains 'enemy') 'Admin roster reconciled'
        Assert-True ($script:members.Graveyard -contains 'dead' -and $script:members.Graveyard -contains 'enemy' -and $script:members.Graveyard -notcontains 'krbtgt') 'Disabled users grouped without touching krbtgt'
        Assert-True (@($script:directory.Values | Where-Object {$_.info -ne ('preserve-'+$_.SamAccountName)}).Count -eq 0 -and $script:directory.operator.Enabled -and $script:directory.unknown.Enabled) 'Wills, primary and unclassified users preserved'
    }
    Test-Case 'Default domain password/lockout policy changes use verified AD settings' {
        Set-FakeServerContext
        $script:domainPolicy=[pscustomobject]@{MinPasswordLength=8;PasswordHistoryCount=0;MinPasswordAge=[timespan]::Zero;MaxPasswordAge=[timespan]::Zero;ComplexityEnabled=$false;ReversibleEncryptionEnabled=$true;LockoutThreshold=0;LockoutDuration=[timespan]::Zero;LockoutObservationWindow=[timespan]::Zero}
        function Get-CurrentAdDomain {[pscustomobject]@{DNSRoot='example.test'}}
        function Get-ADDefaultDomainPasswordPolicy {param($Identity,$ErrorAction) $script:domainPolicy}
        function Set-ADDefaultDomainPasswordPolicy {
            param($Identity,$MinPasswordLength,$PasswordHistoryCount,$MinPasswordAge,$MaxPasswordAge,$ComplexityEnabled,$ReversibleEncryptionEnabled,$LockoutThreshold,$LockoutDuration,$LockoutObservationWindow,$ErrorAction)
            foreach($key in @('MinPasswordLength','PasswordHistoryCount','MinPasswordAge','MaxPasswordAge','ComplexityEnabled','ReversibleEncryptionEnabled','LockoutThreshold','LockoutDuration','LockoutObservationWindow')){if($PSBoundParameters.ContainsKey($key)){$script:domainPolicy.$key=$PSBoundParameters[$key]}}
        }
        Set-ServerDomainAccountPolicy Password
        Set-ServerDomainAccountPolicy Lockout
        Assert-True ($script:domainPolicy.MinPasswordLength -eq 14 -and $script:domainPolicy.ComplexityEnabled -and -not $script:domainPolicy.ReversibleEncryptionEnabled) 'Domain password fields enforced'
        Assert-True ($script:domainPolicy.LockoutThreshold -eq 5 -and $script:domainPolicy.LockoutDuration.TotalMinutes -eq 30) 'Domain lockout fields enforced'
    }
    Test-Case 'DC password and lockout menus route to domain policy rather than local SAM' {
        Set-FakeServerContext;$script:parts=@()
        function Set-ServerDomainAccountPolicy {param($Part) $script:parts+=$Part}
        Set-PasswordPolicy;Set-LockoutPolicy
        Assert-True (($script:parts -join ',') -eq 'Password,Lockout') 'Both menus routed by actual role'
    }
    Test-Case 'Server run-all uses a conservative plan without bulk account/service/network resets' {
        Set-FakeServerContext;$script:steps=@()
        function Enable-WindowsFirewall {$script:steps+='Firewall'}
        function Enable-UAC {$script:steps+='UAC'}
        function Set-ServerRegistryBaseline {$script:steps+='Registry'}
        function Enable-Auditing {$script:steps+='Audit'}
        function Enable-AutoUpdate {$script:steps+='Updates'}
        function Set-AllPasswords {throw 'Must not bulk reset domain accounts'}
        function Disable-UnnecessaryServices {throw 'Must not disable roles'}
        function Set-NetworkHardening {throw 'Must not change role networking'}
        Invoke-ServerBaseline
        Assert-True (($script:steps -join ',') -eq 'Firewall,UAC,Registry,Audit,Updates' -and -not $script:Auto) 'Only reviewed baseline actions dispatched'
    }
    Test-Case 'Server firewall verifies underlying services and preserves traffic defaults when not explicitly approved' {
        Set-FakeServerContext;$script:services=@{};$script:actions=@();Add-FakeService BFE Stopped Disabled;Add-FakeService mpssvc Running Manual
        $script:profileChanges=@()
        function Confirm-Action {return $false}
        function Set-NetFirewallProfile {param($PolicyStore,$Profile,$Enabled,$LogBlocked,$LogAllowed,$LogMaxSizeKilobytes,$DefaultInboundAction,$DefaultOutboundAction,$ErrorAction) $script:profileChanges+=@{Store=$PolicyStore;Name=$Profile;Inbound=$DefaultInboundAction;Outbound=$DefaultOutboundAction}}
        function Get-NetFirewallProfile {param($PolicyStore,$ErrorAction) foreach($name in 'Domain','Private','Public'){[pscustomobject]@{Name=$name;Enabled='True';LogBlocked='True';LogAllowed='True';LogMaxSizeKilobytes=16384}}}
        function Invoke-NativeCommand {param($FilePath,$ArgumentList) }
        Enable-ServerFirewall
        Assert-True ($script:services.BFE.Status -eq 'Running' -and $script:services.BFE.StartType -eq 'Automatic' -and $script:services.mpssvc.StartType -eq 'Automatic') 'Firewall services operational'
        Assert-True ($script:profileChanges.Count -eq 6 -and @($script:profileChanges | Where-Object {$_.Inbound -or $_.Outbound}).Count -eq 0) 'Server rules/defaults preserved unless requested'
    }
    Test-Case 'OS upgrade classification excludes upgrades while allowing normal cumulative patches' {
        $upgrade=[pscustomobject]@{Title='Upgrade to Windows Server 2025';Categories=@()}
        $category=[pscustomobject]@{Title='New platform';Categories=@([pscustomobject]@{CategoryID='3689BDC8-B205-4AF4-8D4A-A63924C5E9D5'})}
        $patch=[pscustomobject]@{Title='Cumulative Update for Microsoft Server operating system';Categories=@()}
        Assert-True ((Test-ServerOsUpgrade $upgrade) -and (Test-ServerOsUpgrade $category) -and -not(Test-ServerOsUpgrade $patch)) 'OS upgrades filtered'
        $commands=${function:Invoke-ServerWindowsUpdate}.Ast.FindAll({param($n)$n -is [System.Management.Automation.Language.CommandAst]},$true)
        Assert-True (@($commands | Where-Object {$_.GetCommandName() -in 'Remove-RegValue','Restart-Computer','Add-WUServiceManager'}).Count -eq 0) 'No WSUS source removal or automatic restart'
    }
    Test-Case 'Root contains two scripts and preserved old files rather than runtime helpers' {
        $entries=@(Get-ChildItem -LiteralPath $root -Force | Where-Object Name -ne '.git')
        Assert-True ($entries.Count -eq 3 -and @($entries | Where-Object Name -eq old).Count -eq 1) 'Only two runnable root files plus old/'
        Assert-True (Test-Path -LiteralPath (Join-Path $root 'old/README.md')) 'Previous files retained'
    }
}
finally{Remove-Item -LiteralPath $temporary -Recurse -Force}
Write-Host "$script:passed Server 2022 regression tests passed. Native server/domain changes were not executed."
