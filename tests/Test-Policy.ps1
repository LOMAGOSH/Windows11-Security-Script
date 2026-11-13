#Requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'Windows-Policy.ps1')
$script:passed=0
function Assert-True($Value,$Message){if(-not $Value){throw "FAILED: $Message"}}
function Test-Case($Name,[scriptblock]$Action){& $Action;$script:passed++;Write-Host "PASS: $Name"}
function Write-Warn($Message){}
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('policy-tests-'+[guid]::NewGuid())
$null=[IO.Directory]::CreateDirectory($temporary)
try {
    Test-Case 'Windows COM and NetAPI bridge compiles without executing native operations' {
        Initialize-WindowsPolicyApi
        Assert-True ('CyberPatriot.WindowsPolicyApi' -as [type]) 'Native declarations compiled'
    }
    Test-Case 'COM identifiers and interface method order match the Microsoft gpedit.h contract' {
        $api=[CyberPatriot.WindowsPolicyApi]
        $interface=$api.Assembly.GetType('CyberPatriot.IGroupPolicyObject')
        $class=$api.GetField('GpoClass',[Reflection.BindingFlags]'NonPublic,Static').GetValue($null)
        Assert-True ($interface.GUID -eq [guid]'ea502723-a23d-11d1-a7d3-0000f87571e3' -and $class -eq [guid]'ea502722-a23d-11d1-a7d3-0000f87571e3') 'SDK interface and coclass IDs'
        $order=@($interface.GetMethods() | Sort-Object MetadataToken | ForEach-Object Name) -join ','
        Assert-True ($order -eq 'New,OpenDSGPO,OpenLocalMachineGPO,OpenRemoteMachineGPO,Save,Delete,GetName,GetDisplayName,SetDisplayName,GetPath,GetDSPath,GetFileSysPath,GetRegistryKey') 'SDK vtable order'
    }
    Test-Case 'INF merge preserves unrelated settings, comments and user rights' {
        $text="[System Access]`r`nMinimumPasswordLength = 18`r`n[Event Audit]`r`n; keep comment`r`nAuditLogonEvents = 0`r`n[Privilege Rights]`r`nSeBackupPrivilege = *S-1-5-32-544"
        $merged=Set-PolicyInfSection -ExistingText $text -Section 'Event Audit' -Values (Get-LegacyAuditValues)
        $audit=Read-PolicyInfSection $merged 'Event Audit'
        Assert-True ($audit.Count -eq 9 -and @($audit.Values | Where-Object {$_ -ne '3'}).Count -eq 0) 'Nine legacy categories configured'
        Assert-True ($merged -match 'MinimumPasswordLength = 18' -and $merged -match 'SeBackupPrivilege = \*S-1-5-32-544' -and $merged -match '; keep comment') 'Unrelated policy retained'
    }
    Test-Case 'INF merge is repeatable and adds missing sections without duplicate keys' {
        $first=New-SecurityPolicyInf 'Event Audit' (Get-LegacyAuditValues)
        $second=Set-PolicyInfSection $first 'Event Audit' (Get-LegacyAuditValues)
        Assert-True (($second -split '\r?\n' | Where-Object {$_ -match '^AuditLogonEvents\s*='}).Count -eq 1) 'One value per key'
        Assert-True ($second -match 'signature="\$CHICAGO\$"') 'Valid security-template version retained'
    }
    Test-Case 'Already-correct effective password policy needs no repair' {
        $script:repairs=@()
        function Get-EffectiveAccountPolicy {param($Work) @{MinimumPasswordLength=14;PasswordComplexity=1;ClearTextPassword=0}}
        function Set-AccountPolicyValues {param($Values,$Work) $script:repairs += $Values}
        Confirm-AccountPolicy -Desired ([ordered]@{MinimumPasswordLength=14;PasswordComplexity=1;ClearTextPassword=0}) -Work $temporary
        Assert-True ($script:repairs.Count -eq 0) 'No unnecessary writes'
    }
    Test-Case 'Read-back repairs only mismatched fields and verifies the repair' {
        $script:state=@{MinimumPasswordLength=8;PasswordComplexity=1;ClearTextPassword=1};$script:repairs=@()
        function Get-EffectiveAccountPolicy {param($Work) $script:state}
        function Set-AccountPolicyValues {param($Values,$Work) $script:repairs += $Values;foreach($key in $Values.Keys){$script:state[$key]=$Values[$key]}}
        Confirm-AccountPolicy -Desired ([ordered]@{MinimumPasswordLength=14;PasswordComplexity=1;ClearTextPassword=0}) -Work $temporary
        Assert-True ($script:repairs.Count -eq 1 -and $script:repairs[0].Count -eq 2 -and $script:state.MinimumPasswordLength -eq 14) 'One bounded repair of mismatched fields'
    }
    Test-Case 'Persistent password-policy mismatch throws after one repair rather than reporting success' {
        $script:attempts=0
        function Get-EffectiveAccountPolicy {param($Work) @{PasswordComplexity=0}}
        function Set-AccountPolicyValues {param($Values,$Work) $script:attempts++}
        $caught=$false
        try {Confirm-AccountPolicy -Desired @{PasswordComplexity=1} -Work $temporary}catch{$caught=$_.Exception.Message -match 'still differs'}
        Assert-True ($caught -and $script:attempts -eq 1) 'Unresolved override reported with bounded retries'
    }
    Test-Case 'Missing read-back fields do not count as a passing policy' {
        function Get-EffectiveAccountPolicy {param($Work) @{}}
        function Set-AccountPolicyValues {param($Values,$Work) }
        $caught=$false;try{Confirm-AccountPolicy -Desired @{ClearTextPassword=0} -Work $temporary}catch{$caught=$true}
        Assert-True $caught 'Missing encryption state fails verification'
    }
    Test-Case 'Lockout read-back repairs the full requested values without parsing localized net.exe output' {
        $script:state=@{LockoutBadCount=0;LockoutDuration=10;ResetLockoutCount=10}
        function Get-EffectiveAccountPolicy {param($Work) $script:state}
        function Set-AccountPolicyValues {param($Values,$Work) foreach($key in $Values.Keys){$script:state[$key]=$Values[$key]}}
        Confirm-AccountPolicy -Desired ([ordered]@{LockoutBadCount=5;LockoutDuration=30;ResetLockoutCount=30}) -Work $temporary
        Assert-True ($script:state.LockoutBadCount -eq 5 -and $script:state.ResetLockoutCount -eq 30) 'Lockout values verified'
    }
    Test-Case 'Enabled-account flags are fixed and read again without resetting passwords or enabling accounts' {
        $script:flags=[pscustomobject]@{SID='S-1-5-21-1-2-3-1001';PasswordRequired=$false;PasswordExpires=$false};$script:changes=@()
        function Get-LocalUser {param($ErrorAction) @([pscustomobject]@{Name='alice';Enabled=$true;SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-1001'}},[pscustomobject]@{Name='disabled';Enabled=$false;SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-1002'}})}
        function Get-CimInstance {param($ClassName,$Filter,$ErrorAction) $script:flags}
        function Set-LocalUser {param($Name,$PasswordNeverExpires,$ErrorAction) $script:changes+='expiration';$script:flags.PasswordExpires=$true}
        function Invoke-NativeCommand {param($FilePath,$ArgumentList) $script:changes+='required';Assert-True ($ArgumentList[0] -eq 'user' -and $ArgumentList[1] -eq 'alice' -and $ArgumentList[2] -eq '/passwordreq:yes') 'Only intended flag changed';$script:flags.PasswordRequired=$true}
        Confirm-EnabledAccountPasswordFlags
        Assert-True ($script:changes.Count -eq 2) 'Only enabled account flags repaired'
    }
    Test-Case 'Unavailable account flags fail verification' {
        function Get-LocalUser {param($ErrorAction) [pscustomobject]@{Name='alice';Enabled=$true;SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-1001'}}}
        function Get-CimInstance {param($ClassName,$Filter,$ErrorAction) @()}
        $caught=$false;try{Confirm-EnabledAccountPasswordFlags}catch{$caught=$true}
        Assert-True $caught 'No silent flag-verification skip'
    }
    Test-Case 'Audit extension identifiers come from the installed Windows registry, not guessed constants' {
        function Get-ChildItem {param($LiteralPath,$ErrorAction) [pscustomobject]@{PSPath='fake';PSChildName='11111111-2222-3333-4444-555555555555'}}
        function Get-ItemProperty {param($LiteralPath,$Name,$ErrorAction) [pscustomobject]@{DllName='auditcse.dll'}}
        Assert-True ((Get-PolicyExtensionGuid auditcse.dll).ToString() -eq '11111111-2222-3333-4444-555555555555') 'Installed CSE identifier used'
        $caught=$false;try{Get-PolicyExtensionGuid scecli.dll}catch{$caught=$true}
        Assert-True $caught 'Missing CSE is an explicit capability failure'
    }
    Test-Case 'GPO save backs up existing files and preserves unrelated security template settings' {
        $machine=Join-Path $temporary 'GroupPolicy/Machine';$null=[IO.Directory]::CreateDirectory((Join-Path $machine 'Microsoft/Windows NT/SecEdit'))
        $existing=Join-Path $machine 'Microsoft/Windows NT/SecEdit/GptTmpl.inf'
        "[System Access]`r`nMinimumPasswordLength = 18" | Set-Content -LiteralPath $existing -Encoding Unicode
        $work=Join-Path $temporary 'save-work';$null=[IO.Directory]::CreateDirectory($work)
        $csv=Join-Path $work 'input.csv';'test audit input' | Set-Content -LiteralPath $csv
        $script:testMachine=$machine;$script:savedLegacy=''
        function Get-LocalGpoMachinePath {$script:testMachine}
        function Get-PolicyExtensionGuid {param($Dll) [guid]'11111111-2222-3333-4444-555555555555'}
        function Invoke-NativeGpoAuditSave {param($Csv,$LegacyInf,$AuditExtension,$SecurityExtension) $script:savedLegacy=Get-Content -LiteralPath $LegacyInf -Raw}
        $path=Save-LocalAuditPolicy -Csv $csv -Work $work -Legacy
        Assert-True (Test-Path -LiteralPath (Join-Path $work 'LocalGpoBackup')) 'Original GPO backed up'
        Assert-True ($script:savedLegacy -match 'MinimumPasswordLength = 18' -and $script:savedLegacy -match 'AuditLogonEvents = 3') 'Merged template passed to native API'
        Assert-True ($path -like '*audit.csv') 'Persistence path returned for independent read-back'
    }
    Test-Case 'Saving system audit policy preserves existing per-user audit rows' {
        $machine=Join-Path $temporary 'PreservedPolicy/Machine';$audit=Join-Path $machine 'Microsoft/Windows NT/Audit/audit.csv'
        $null=[IO.Directory]::CreateDirectory((Split-Path -Parent $audit))
        $other=[pscustomobject][ordered]@{'Machine Name'='';'Policy Target'='S-1-5-21-1-2-3-1001';Subcategory='Per-user';'Subcategory GUID'='{0cce9215-69ae-11d9-bed3-505054503030}';'Inclusion Setting'='Success';'Exclusion Setting'='';'Setting Value'='1'}
        $other | Export-Csv -LiteralPath $audit -NoTypeInformation -Encoding Unicode
        $work=Join-Path $temporary 'preserve-work';$null=[IO.Directory]::CreateDirectory($work)
        $csv=Join-Path $work 'desired.csv'
        $system=$other | Select-Object *;$system.'Policy Target'='System';$system.'Setting Value'='3'
        $system | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding Unicode
        $script:testMachine=$machine;$script:savedAudit=@()
        function Get-LocalGpoMachinePath {$script:testMachine}
        function Get-PolicyExtensionGuid {param($Dll) [guid]'11111111-2222-3333-4444-555555555555'}
        function Invoke-NativeGpoAuditSave {param($Csv,$LegacyInf,$AuditExtension,$SecurityExtension) $script:savedAudit=@(Import-Csv -LiteralPath $Csv)}
        $null=Save-LocalAuditPolicy -Csv $csv -Work $work
        Assert-True ($script:savedAudit.Count -eq 2 -and @($script:savedAudit | Where-Object {$_.'Policy Target' -eq 'S-1-5-21-1-2-3-1001' -and $_.'Setting Value' -eq '1'}).Count -eq 1) 'Existing per-user rule preserved'
    }
}
finally {Remove-Item -LiteralPath $temporary -Recurse -Force}
Write-Host "$script:passed policy tests passed. Native Windows operations were not executed."
