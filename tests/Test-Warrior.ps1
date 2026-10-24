#Requires -Version 5.1
# Imports declarations only. Every Windows command is replaced before actions run.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
foreach ($name in 'CyberPatriot-Win11-Hardening.ps1','Windows-Warrior.ps1') {
    $tokens = $null; $errors = $null
    $tree = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root $name),[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw ($errors | Out-String) }
    foreach ($node in $tree.EndBlock.Statements) {
        if ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) { . ([scriptblock]::Create($node.Extent.Text)) }
    }
}
$script:passed = 0
function Assert-True($Condition, [string]$Message) { if (-not $Condition) { throw "FAILED: $Message" } }
function Test-Case([string]$Name, [scriptblock]$Action) { & $Action; $script:passed++; Write-Host "PASS: $Name" }
$script:inputQueue = New-Object 'System.Collections.Generic.Queue[string]'
$script:confirm = $true
$script:actions = New-Object 'System.Collections.Generic.List[object]'
$script:good = @(); $script:bad = @()
$script:RegFail = 0; $script:FailureCount = 0; $script:CurrentUserName = 'student'
function Read-Host {
    param($Prompt, [switch]$AsSecureString)
    if (-not $script:inputQueue.Count) { throw "Unexpected prompt: $Prompt" }
    $text = $script:inputQueue.Dequeue()
    if ($AsSecureString) { return (ConvertTo-SecureString $text -AsPlainText -Force) }
    $text
}
function Confirm-Action { return $script:confirm }
function Write-Ok($Text) { $script:good += $Text }
function Write-Bad($Text) { $script:bad += $Text; $script:FailureCount++ }
function Write-Warn($Text) { }
function Write-Section($Text) { }
function Wait-Key { }
function Reset-Records {
    $script:actions.Clear(); $script:inputQueue.Clear(); $script:good=@(); $script:bad=@(); $script:confirm=$true
    $script:WarriorReadmePlan=$null
}
function Record-Action($Kind,$Name,$Value) { $script:actions.Add([pscustomobject]@{Kind=$Kind;Name=$Name;Value=$Value}) }
function Invoke-NativeCommand { param($FilePath,$ArgumentList) Record-Action Native $FilePath $ArgumentList }
function Set-RegistryValue { param($Path,$Name,$Value,$Type) Record-Action Registry $Name $Value }
function Set-MpPreference { param($DisableRealtimeMonitoring,$PUAProtection,$MAPSReporting,$ErrorAction) Record-Action Defender 'preferences' $null }
function Set-SmbServerConfiguration { param($EnableSMB1Protocol,[switch]$Force,$ErrorAction) Record-Action SMB SMB1 $EnableSMB1Protocol }
function Enable-WindowsFirewall { Record-Action Firewall Profiles $null }
function Enable-Auditing { param([guid[]]$SubcategoryGuid) Record-Action Audit Selected $SubcategoryGuid }
$script:users = @{}
function Add-FakeUser($Name,$Rid) { $script:users[$Name] = [pscustomobject]@{Name=$Name;Enabled=$true;SID=[pscustomobject]@{Value="S-1-5-21-111-222-333-$Rid"}} }
Add-FakeUser student 1001
Add-FakeUser loki 1002
Add-FakeUser bbanner 1003
Add-FakeUser jrhodes 1004
Add-FakeUser renamedGuest 501
function Get-LocalUser {
    param($Name,$ErrorAction)
    if ($Name) { if ($script:users.ContainsKey($Name)) { $script:users[$Name] }; return }
    $script:users.Values
}
function Disable-LocalUser { param($Name,$ErrorAction) Record-Action DisableAccount $Name $null; $script:users[$Name].Enabled=$false }
function Set-LocalUser { param($Name,$Password,$PasswordNeverExpires,$ErrorAction) Record-Action SetAccount $Name $PasswordNeverExpires }
function New-LocalUser { param($Name,$Password,$PasswordNeverExpires,$ErrorAction) Add-FakeUser $Name 1010; Record-Action CreateAccount $Name $null }
$script:group = [pscustomobject]@{Name='Analysts';SID=[pscustomobject]@{Value='S-1-5-21-111-222-333-2000'}}
function Get-LocalGroup {
    param($SID,$ErrorAction)
    if ($SID -eq 'S-1-5-32-544') { return [pscustomobject]@{Name='LocalizedAdmins'; SID=[pscustomobject]@{Value=$SID}} }
    if ($SID -eq 'S-1-5-32-545') { return [pscustomobject]@{Name='LocalizedUsers'; SID=[pscustomobject]@{Value=$SID}} }
    if ($script:group) { $script:group }
}
function Get-LocalGroupMember {
    param($Group,$ErrorAction)
    if ($Group -eq 'LocalizedAdmins') { $names=@('loki','bbanner') }
    elseif ($Group -eq 'Analysts') { $names=@('loki') }
    else { $names=@() }
    foreach ($name in $names) { [pscustomobject]@{Name="PC\$name"; SID=$script:users[$name].SID; ObjectClass='User'} }
}
function Remove-LocalGroupMember { param($Group,$Member,$ErrorAction) Record-Action RemoveMembership $Member $Group }
function Add-LocalGroupMember { param($Group,$Member,$ErrorAction) Record-Action AddMembership $Member $Group }
function New-LocalGroup { param($Name,$ErrorAction) Record-Action CreateGroup $Name $null }
$oldProgramData=$env:ProgramData; $oldSystemDrive=$env:SystemDrive
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('warrior-tests-'+[guid]::NewGuid())
$null=[IO.Directory]::CreateDirectory($temporary)
$script:LogDir=$temporary
$env:ProgramData=Join-Path $temporary 'ProgramData'
$env:SystemDrive=$temporary
$PwMinLen=14; $PwMaxAge=60; $PwMinAge=1; $PwHistory=24; $LockThreshold=5; $LockDuration=30; $LockWindow=30
try {
    Test-Case 'All 50 task cards have commands, explanations and GUI instructions' {
        $tasks=@(Get-WarriorTasks)
        Assert-True ($tasks.Count -eq 50 -and (($tasks.Id | Sort-Object -Unique).Count -eq 50)) 'Fifty unique task cards'
        foreach($task in $tasks) { Assert-True ($task.Id -ge 1 -and $task.Id -le 50 -and $task.Command -and $task.Explanation -and $task.Gui) 'Complete card' }
    }
    Test-Case 'Executable task actions contain no Windows Warrior example target names' {
        $source=${function:Invoke-WarriorTaskAction}.ToString()
        Assert-True ($source -notmatch '\b(hacker|webdev|intern|contractor|analyst|EvilAllow|EvilSvc|EvilUpdater|Backdoor|Secret|nc\.exe)\b') 'Names are selected from current image'
    }
    Test-Case 'Second-image unauthorized account is disabled and demoted without deletion' {
        Reset-Records; $script:inputQueue.Enqueue('loki')
        Invoke-WarriorTaskAction 3
        Assert-True (@($script:actions | Where-Object { $_.Kind -eq 'DisableAccount' -and $_.Name -eq 'loki' }).Count -eq 1) 'loki disabled'
        Assert-True (@($script:actions | Where-Object { $_.Kind -eq 'RemoveMembership' -and $_.Name -eq 'loki' }).Count -eq 1) 'loki admin membership removed'
    }
    Test-Case 'Second-image standard user is removed from localized Administrators group' {
        Reset-Records; $script:inputQueue.Enqueue('bbanner')
        Invoke-WarriorTaskAction 4
        Assert-True ($script:actions[0].Name -eq 'bbanner' -and $script:actions[0].Value -eq 'LocalizedAdmins') 'Selected user demoted by SID-resolved group'
    }
    Test-Case 'README approval prevents disabling an authorized account' {
        Reset-Records; $script:WarriorReadmePlan=[pscustomobject]@{Admins=@('student');Users=@('student','bbanner')}; $script:inputQueue.Enqueue('bbanner')
        $caught=$false
        try { Invoke-WarriorTaskAction 3 } catch { $caught=$true }
        Assert-True ($caught -and $script:actions.Count -eq 0) 'Approved account preserved'
    }
    Test-Case 'Blank target or declined confirmation causes no account mutation' {
        Reset-Records; $script:inputQueue.Enqueue('')
        try { Invoke-WarriorTaskAction 3 } catch [OperationCanceledException] { }
        Assert-True ($script:actions.Count -eq 0) 'Blank is not a default sample username'
        $script:inputQueue.Enqueue('loki'); $script:confirm=$false
        try { Invoke-WarriorTaskAction 3 } catch [OperationCanceledException] { }
        Assert-True ($script:actions.Count -eq 0) 'Decline is respected'
    }
    Test-Case 'Current account cannot be disabled' {
        Reset-Records; $script:inputQueue.Enqueue('student')
        $caught=$false; try { Invoke-WarriorTaskAction 3 } catch { $caught=$true }
        Assert-True ($caught -and $script:actions.Count -eq 0) 'Current account protected'
    }
    Test-Case 'Guest is found by SID when renamed' {
        Reset-Records; Invoke-WarriorTaskAction 1
        Assert-True ($script:actions[0].Name -eq 'renamedGuest') 'Renamed Guest disabled'
    }
    Test-Case 'Password expiration applies to the account selected in this image' {
        Reset-Records; $script:inputQueue.Enqueue('jrhodes'); Invoke-WarriorTaskAction 6
        Assert-True ($script:actions[0].Name -eq 'jrhodes' -and $script:actions[0].Value -eq $false) 'Selected account expiration enabled'
    }
    Test-Case 'A different authorized standard account is created and added to Users' {
        Reset-Records; $script:inputQueue.Enqueue('tchalla'); $script:inputQueue.Enqueue('Test-only-Passphrase-123!')
        Invoke-WarriorTaskAction 7
        Assert-True (@($script:actions | Where-Object { $_.Kind -eq 'CreateAccount' -and $_.Name -eq 'tchalla' }).Count -eq 1) 'Selected account created'
        Assert-True (@($script:actions | Where-Object { $_.Kind -eq 'AddMembership' -and $_.Value -eq 'LocalizedUsers' }).Count -eq 1) 'Standard Users membership granted'
    }
    Test-Case 'Generic account-policy steps retain stronger configured thresholds' {
        Reset-Records
        foreach($id in 8,10,11,12,13,14,15) { Invoke-WarriorTaskAction $id }
        Assert-True ($script:actions[0].Value[1] -eq '/minpwlen:14') 'Minimum is not weakened to 12'
        Assert-True ($script:actions[1].Value[1] -eq '/maxpwage:60') 'Maximum is not weakened to 90'
        Assert-True ($script:actions.Count -eq 8) 'All policy commands dispatched'
    }
    Test-Case 'Registry, Defender and SMB task actions dispatch through tested helpers' {
        Reset-Records
        foreach($id in 17,18,19,20,21,30,31,33,34,35,36,37,38,39,40,41,42) { Invoke-WarriorTaskAction $id }
        Assert-True (@($script:actions | Where-Object Kind -eq Registry).Count -eq 17) 'Seventeen registry targets dispatched'
        Assert-True (@($script:actions | Where-Object Kind -eq Defender).Count -eq 3) 'Defender API called for all three protections'
    }
    Test-Case 'Audit tasks select their own GUIDs and firewall tasks reuse local-GPO configuration' {
        Reset-Records; foreach($id in 22,23,43,44,45) { Invoke-WarriorTaskAction $id }
        Assert-True (@($script:actions | Where-Object Kind -eq Firewall).Count -eq 2) 'Firewall helper reused'
        $audit=@($script:actions | Where-Object Kind -eq Audit)
        Assert-True ($audit.Count -eq 3 -and $audit[0].Value[0].ToString() -like '0cce9215-*' -and $audit[2].Value[0].ToString() -like '0cce923f-*') 'Correct audit GUIDs selected'
    }
    Test-Case 'Group plan previews and creates an image-specific group with approved members' {
        Reset-Records; $script:group=$null
        $script:inputQueue.Enqueue('BlueTeam'); $script:inputQueue.Enqueue('bbanner,jrhodes')
        Invoke-ImageGroupPlan
        Assert-True (@($script:actions | Where-Object Kind -eq CreateGroup).Count -eq 1) 'Group created'
        Assert-True (@($script:actions | Where-Object Kind -eq AddMembership).Count -eq 2) 'Selected members added'
    }
    Test-Case 'Group membership reconciliation preserves accounts' {
        Reset-Records; $script:group=[pscustomobject]@{Name='Analysts';SID=[pscustomobject]@{Value='S-1-5-21-111-222-333-2000'}}
        $script:inputQueue.Enqueue('Analysts'); $script:inputQueue.Enqueue('bbanner')
        Invoke-ImageGroupPlan
        Assert-True (@($script:actions | Where-Object { $_.Kind -eq 'RemoveMembership' -and $_.Name -eq 'PC\loki' }).Count -eq 1) 'Unauthorized membership removed'
        Assert-True (@($script:actions | Where-Object Kind -eq DisableAccount).Count -eq 0) 'Account remains intact'
    }
    Test-Case 'Media preview matches requested extensions without consuming unrelated files' {
        $media=Join-Path $temporary 'media'; $null=[IO.Directory]::CreateDirectory((Join-Path $media 'sub'))
        Set-Content -LiteralPath (Join-Path $media 'song.mp3') -Value 'test evidence'
        Set-Content -LiteralPath (Join-Path $media 'sub/clip.avi') -Value 'test evidence'
        Set-Content -LiteralPath (Join-Path $media 'keep.txt') -Value 'required document'
        $files=@(Get-WarriorMediaFiles -Root $media)
        Assert-True ($files.Count -eq 2) 'Only media candidates selected'
    }
    Test-Case 'File removal uses reversible quarantine with hash and original-path evidence' {
        $file=Join-Path $temporary 'sample.bin'; Set-Content -LiteralPath $file -Value 'test payload'
        $hash=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        Move-WarriorEvidenceFile -Path $file
        $record=Import-Csv -LiteralPath (Join-Path $env:ProgramData 'CyberPatriot-Hardening/Quarantine/manifest.csv')
        Assert-True (-not (Test-Path -LiteralPath $file)) 'Removed from original path'
        Assert-True ($record.OriginalPath -eq $file -and $record.SHA256 -eq $hash -and (Get-FileHash -LiteralPath $record.QuarantinedPath).Hash -eq $hash) 'Evidence can be restored intact'
    }
    Test-Case 'Forensics reports observed evidence without guessing a high listening port' {
        function Get-CimInstance { param($ClassName,$ErrorAction) [pscustomobject]@{Caption='Test Windows';BuildNumber='22631'} }
        function Get-ScheduledTask { param($ErrorAction) [pscustomobject]@{TaskName='DifferentImageTask';TaskPath='\';Actions=@([pscustomobject]@{Execute='C:\Tools\evidence.exe';Arguments='';WorkingDirectory='C:\Tools'})} }
        function Get-ItemProperty { param($LiteralPath,$Name,$ErrorAction) [pscustomobject]@{DifferentStartup='C:\Tools\startup.exe'} }
        function Get-NetTCPConnection { param($State,$ErrorAction) @([pscustomobject]@{LocalAddress='127.0.0.1';LocalPort=53123;OwningProcess=1234},[pscustomobject]@{LocalAddress='0.0.0.0';LocalPort=62000;OwningProcess=1235}) }
        function Get-Process { param($Id,$ErrorAction) [pscustomobject]@{ProcessName='test';Path='C:\Tools\test.exe'} }
        $findings=@(Get-WarriorForensicFindings -ScheduledTaskName DifferentImageTask -StartupValueName DifferentStartup)
        Assert-True ($findings.Count -eq 4 -and $findings[0].SuggestedAnswer -eq '22631') 'Observed build reported'
        Assert-True ($findings[1].SuggestedAnswer -eq 'C:\Tools\evidence.exe') 'Selected task evidence reported'
        Assert-True ($findings[3].Status -eq 'Review required' -and $findings[3].SuggestedAnswer -notmatch '^\d+$') 'No unsupported port answer'
        $inventory=@(Get-WarriorForensicFindings)
        Assert-True ($inventory[1].Status -eq 'Review required' -and $inventory[2].Status -eq 'Review required') 'No default task/value assumed'
    }
    Test-Case 'Global auditing builds documented opt-in commands without broadening the chosen rights' {
        $file=@(Get-GlobalAuditArguments File 'S-1-5-21-111-222-333-1001' Both)
        $key=@(Get-GlobalAuditArguments Key 'S-1-5-21-111-222-333-1001' Read)
        Assert-True ($file -contains '/access:FRFW' -and $file -contains '/user:{S-1-5-21-111-222-333-1001}') 'File rights and SID preserved'
        Assert-True ($key -contains '/access:KR' -and $key -contains '/type:Key') 'Registry read-only selection preserved'
    }
    Test-Case 'Cleanup removes only a selected service from another image' {
        Reset-Records; $script:inputQueue.Enqueue('AnotherBadService')
        function Get-Service { param($Name,$ErrorAction) [pscustomobject]@{Name='AnotherBadService';Status='Running'} }
        function Get-CimInstance { param($ClassName,$ErrorAction) [pscustomobject]@{Name='AnotherBadService';PathName='C:\Tools\bad.exe'} }
        function Stop-Service { param($Name,[switch]$Force,$ErrorAction) Record-Action StopService $Name $null }
        function Set-Service { param($Name,$StartupType,$ErrorAction) Record-Action ConfigureService $Name $StartupType }
        Invoke-WarriorTaskAction 28
        $delete=@($script:actions | Where-Object Kind -eq Native)
        Assert-True ($delete.Count -eq 1 -and $delete[0].Value[0] -eq 'delete' -and $delete[0].Value[1] -eq 'AnotherBadService') 'Only chosen service registration deleted'
    }
    Test-Case 'Scheduled task cleanup preserves unrelated tasks' {
        Reset-Records; $script:inputQueue.Enqueue('DifferentBadTask')
        function Get-ScheduledTask { param($ErrorAction) @([pscustomobject]@{TaskName='DifferentBadTask';TaskPath='\'},[pscustomobject]@{TaskName='RequiredBackup';TaskPath='\'}) }
        function Export-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction) '<Task />' }
        function Unregister-ScheduledTask { param($TaskName,$TaskPath,$Confirm,$ErrorAction) Record-Action RemoveTask $TaskName $TaskPath }
        Invoke-WarriorTaskAction 46
        Assert-True ($script:actions.Count -eq 1 -and $script:actions[0].Name -eq 'DifferentBadTask') 'Only selected task removed'
        Assert-True (@(Get-ChildItem -LiteralPath $temporary -Filter 'Removed-task-*.xml').Count -gt 0) 'Task XML preserved'
    }
    Test-Case 'Startup and share cleanup use current-image targets' {
        Reset-Records; $script:inputQueue.Enqueue('DifferentBadStartup'); $script:inputQueue.Enqueue('UnauthorizedProjects')
        function Get-ItemProperty { param($LiteralPath,$ErrorAction) [pscustomobject]@{DifferentBadStartup='C:\Tools\bad.exe';RequiredStartup='C:\Tools\good.exe'} }
        function Remove-ItemProperty { param($LiteralPath,$Name,$ErrorAction) Record-Action RemoveStartup $Name $null }
        function Get-SmbShare { param($ErrorAction) @([pscustomobject]@{Name='UnauthorizedProjects';Path='C:\Projects'},[pscustomobject]@{Name='RequiredShare';Path='C:\Required'}) }
        function Remove-SmbShare { param($Name,[switch]$Force,$ErrorAction) Record-Action RemoveShare $Name $null }
        Invoke-WarriorTaskAction 47
        Invoke-WarriorTaskAction 50
        Assert-True ($script:actions.Count -eq 2 -and $script:actions[0].Name -eq 'DifferentBadStartup' -and $script:actions[1].Name -eq 'UnauthorizedProjects') 'Unrelated startup and share preserved'
    }
    Test-Case 'App updates use one exact package ID selected from the current image' {
        Reset-Records; $script:inputQueue.Enqueue('Example.DifferentEditor'); $script:inputQueue.Enqueue('U')
        function Get-Command { param($Name,$CommandType,$ErrorAction) [pscustomobject]@{Source='test-winget.exe'} }
        Invoke-ImageAppAction
        $upgrade=@($script:actions | Where-Object { $_.Kind -eq 'Native' -and $_.Value[0] -eq 'upgrade' })
        Assert-True ($upgrade.Count -eq 1 -and $upgrade[0].Value -contains '--exact' -and $upgrade[0].Value -contains 'Example.DifferentEditor') 'No fixed app or upgrade-all selected'
    }
    Test-Case 'Previewing a tutorial task performs no actions and selects no default target' {
        Reset-Records
        Invoke-WarriorTask -Id 3 -ReportOnly
        Assert-True ($script:actions.Count -eq 0) 'Preview has no mutations'
    }
    Test-Case 'Global auditing is skipped without explicit scope' {
        Reset-Records; $script:inputQueue.Enqueue('')
        Set-GlobalObjectAuditing
        Assert-True ($script:actions.Count -eq 0) 'No global rule applied by default'
    }
    Test-Case 'Companion contains no account deletion or execution of README command text' {
        $commands=$tree.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst]},$true)
        Assert-True (@($commands | Where-Object {$_.GetCommandName() -in @('Remove-LocalUser','Invoke-Expression')}).Count -eq 0) 'No account deletion or README eval'
    }
}
finally {
    $env:ProgramData=$oldProgramData; $env:SystemDrive=$oldSystemDrive
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
Write-Host "$script:passed walkthrough tests passed. No Windows hardening actions were executed."
