#Requires -Version 5.1
<#
Runs without elevation. Imports function declarations only, never the toolkit's
launcher, menu, or hardening actions. Windows operations are replaced with fakes.
On Windows, also tests the real registry writer in a temporary HKCU test key.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$toolkit = Join-Path $root 'CyberPatriot-Win11-Hardening.ps1'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($toolkit, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($node in $ast.EndBlock.Statements) {
    if ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
        . ([scriptblock]::Create($node.Extent.Text))
    }
}
$realRegistryWriter = ${function:Set-RegistryValue}
$realNativeRunner = ${function:Invoke-NativeCommand}
$script:passed = 0
function Assert-True($Condition, [string]$Message) {
    if (-not $Condition) { throw "FAILED: $Message" }
}
function Test-Case([string]$Name, [scriptblock]$Action) {
    & $Action
    $script:passed++
    Write-Host "PASS: $Name"
}
$script:good = New-Object 'System.Collections.Generic.List[string]'
$script:bad = New-Object 'System.Collections.Generic.List[string]'
function Write-Ok([string]$Text) { $script:good.Add($Text) }
function Write-Bad([string]$Text) { $script:bad.Add($Text); $script:FailureCount++ }
function Write-Warn([string]$Text) { }
function Write-Section([string]$Text) { }
function Wait-Key { }
function Clear-Host { }
$script:FailureCount = 0
$script:RegFail = 0
$script:keys = @{}
$script:properties = @{}
$script:failWrite = $false
$script:failCreate = $false
function Test-Path {
    [CmdletBinding()]
    param([string]$LiteralPath, [string]$Path)
    $target = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($target -match '^HKLM:') { return $script:keys.ContainsKey($target) }
    Microsoft.PowerShell.Management\Test-Path -LiteralPath $target
}
function New-Item {
    [CmdletBinding()]
    param([string]$Path, [switch]$Force)
    if ($script:failCreate) { Write-Error 'Simulated registry key access denied'; return }
    Assert-True ($Path -match '^HKLM:') 'Only fake HKLM keys may be created'
    $script:keys[$Path] = $true
}
function New-ItemProperty {
    [CmdletBinding()]
    param([string]$LiteralPath, [string]$Name, $Value, [string]$PropertyType, [switch]$Force)
    if ($script:failWrite) { Write-Error 'Simulated registry property access denied'; return }
    Assert-True ($script:keys.ContainsKey($LiteralPath)) 'Key created before property'
    $script:properties["$LiteralPath|$Name"] = [pscustomobject]@{Value = $Value; Type = $PropertyType}
}
Set-Alias -Name r -Value Invoke-History -Scope Script
Test-Case 'Registry writes work while the built-in R alias is present' {
    Assert-True ((Get-Command r).Definition -eq 'Invoke-History') 'R still resolves to history'
    Set-RegistryValue 'HKLM:\Test' 'NoLMHash' 1
    Assert-True ($script:properties['HKLM:\Test|NoLMHash'].Value -eq 1) 'NoLMHash written'
    Assert-True ($script:properties['HKLM:\Test|NoLMHash'].Type -eq 'DWord') 'Default is DWORD'
}
Test-Case 'String and binary values retain their types and contents' {
    Set-RegistryValue 'HKLM:\Test' 'Banner' 'Authorized users only' 'String'
    Set-RegistryValue 'HKLM:\Test' 'BinaryValue' ([byte[]]@(0, 1)) 'Binary'
    Assert-True ($script:properties['HKLM:\Test|Banner'].Value -eq 'Authorized users only') 'String preserved'
    Assert-True ($script:properties['HKLM:\Test|BinaryValue'].Value -is [byte[]]) 'Binary array preserved'
}
Test-Case 'Nonterminating registry write errors are caught and counted' {
    $script:failWrite = $true
    Set-RegistryValue 'HKLM:\Test' 'Denied' 1
    $script:failWrite = $false
    Assert-True ($script:RegFail -eq 1) 'One failed write counted'
    Assert-True ($script:bad[-1] -match 'access denied') 'Actual error reported'
}
Test-Case 'A failed key creation does not attempt a property write' {
    $script:failCreate = $true
    Set-RegistryValue 'HKLM:\Missing' 'Denied' 1
    $script:failCreate = $false
    Assert-True ($script:RegFail -eq 2) 'Creation error counted'
    Assert-True (-not $script:properties.ContainsKey('HKLM:\Missing|Denied')) 'No property written'
}
Test-Case 'Registry summaries report only errors from the current option' {
    $script:good.Clear(); $script:bad.Clear()
    Write-RegistryResult -Before 1 -SuccessMessage 'Should not appear'
    Assert-True ($script:good.Count -eq 0 -and $script:bad.Count -eq 1) 'Incomplete step reported'
    Write-RegistryResult -Before 2 -SuccessMessage 'Current step passed'
    Assert-True ($script:good[-1] -eq 'Current step passed') 'Old errors do not poison new step'
}
$hostExe = (Get-Process -Id $PID).Path
Test-Case 'Native command success preserves output' {
    $result = Invoke-NativeCommand -FilePath $hostExe -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Write-Output 42; exit 0')
    Assert-True ($result -eq '42') 'Native output preserved'
}
Test-Case 'Native failure includes exit status and diagnostic output' {
    $caught = $false
    try { Invoke-NativeCommand -FilePath $hostExe -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Write-Output denied; exit 7') }
    catch { $caught = $_.Exception.Message -match 'exit code 7' -and $_.Exception.Message -match 'denied' }
    Assert-True $caught 'Nonzero status throws with native error details'
}

# Menu-function tests record intended writes and native commands without touching Windows.
$script:writes = New-Object 'System.Collections.Generic.List[object]'
$script:nativeCalls = New-Object 'System.Collections.Generic.List[object]'
$script:failNative = ''
$script:failRegistryName = ''
function Set-RegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][string]$Path,
        [Parameter(Mandatory = $true, Position = 1)][string]$Name,
        [Parameter(Mandatory = $true, Position = 2)][AllowNull()][AllowEmptyString()][AllowEmptyCollection()]$Value,
        [Parameter(Position = 3)][string]$Type = 'DWord'
    )
    if ($Name -eq $script:failRegistryName) { $script:RegFail++; Write-Bad "Simulated failure: $Name"; return }
    $script:writes.Add([pscustomobject]@{Path = $Path; Name = $Name; Value = $Value; Type = $Type})
}
function Invoke-NativeCommand {
    [CmdletBinding()]
    param([string]$FilePath, [string[]]$ArgumentList)
    $script:nativeCalls.Add([pscustomobject]@{FilePath = $FilePath; Arguments = $ArgumentList})
    if ($FilePath -eq $script:failNative) { throw "Simulated $FilePath failure (exit code 5)" }
}
function Reset-Records {
    $script:writes.Clear(); $script:nativeCalls.Clear(); $script:good.Clear(); $script:bad.Clear()
    $script:failNative = ''; $script:failRegistryName = ''
}
function Read-Host { param([string]$Prompt) return '' }
$oldTemp = $env:TEMP
$testTemp = Join-Path ([IO.Path]::GetTempPath()) ('cp-tests-' + [guid]::NewGuid())
$null = [IO.Directory]::CreateDirectory($testTemp)
$env:TEMP = $testTemp
$PwHistory = 24; $PwMaxAge = 60; $PwMinAge = 1; $PwMinLen = 14
$LockThreshold = 5; $LockDuration = 30; $LockWindow = 30
$script:LogDir = $testTemp; $script:Stamp = 'test'
try {
    Test-Case 'Option 4 configures every password setting and NoLMHash' {
        Reset-Records
        Set-PasswordPolicy
        Assert-True ($script:nativeCalls.Count -eq 5) 'Four net calls and one secedit call'
        Assert-True ($script:nativeCalls[3].Arguments[1] -eq '/minpwlen:14') 'Password setting interpolated'
        Assert-True (@($script:writes | Where-Object Name -eq 'NoLMHash').Count -eq 1) 'NoLMHash applied'
        Assert-True ($script:bad.Count -eq 0 -and $script:good.Count -eq 1) 'Successful password result'
        Assert-True (-not (Microsoft.PowerShell.Management\Test-Path (Join-Path $testTemp 'cp-pwpol.inf'))) 'Temporary policy cleaned'
    }
    Test-Case 'Option 4 stops and reports a net.exe failure' {
        Reset-Records; $script:failNative = 'net.exe'
        Set-PasswordPolicy
        Assert-True ($script:good.Count -eq 0 -and $script:bad.Count -eq 1) 'No false success'
        Assert-True ($script:nativeCalls.Count -eq 1 -and $script:writes.Count -eq 0) 'Failed prerequisite stops changes'
    }
    Test-Case 'Option 4 reports secedit failure and cleans the temporary policy' {
        Reset-Records; $script:failNative = 'secedit.exe'
        Set-PasswordPolicy
        Assert-True ($script:good.Count -eq 0 -and $script:bad.Count -eq 1) 'No false secedit success'
        Assert-True (-not (Microsoft.PowerShell.Management\Test-Path (Join-Path $testTemp 'cp-pwpol.inf'))) 'Cleanup runs on failure'
    }
    Test-Case 'Option 4 does not report success when NoLMHash is rejected' {
        Reset-Records; $script:failRegistryName = 'NoLMHash'
        Set-PasswordPolicy
        Assert-True ($script:good.Count -eq 0 -and $script:bad.Count -gt 0) 'Registry failure makes step incomplete'
    }
    Test-Case 'Option 5 reports a rejected lockout policy' {
        Reset-Records; $script:failNative = 'net.exe'
        Set-LockoutPolicy
        Assert-True ($script:good.Count -eq 0 -and $script:bad.Count -eq 1) 'No false lockout success'
    }
    Test-Case 'Option 9 writes all UAC settings rather than invoking history' {
        Reset-Records
        Enable-UAC
        Assert-True ($script:writes.Count -eq 10) 'Ten UAC registry settings dispatched'
        Assert-True ($script:writes[0].Name -eq 'EnableLUA') 'UAC enabled'
        Assert-True ($script:bad.Count -eq 0 -and $script:good.Count -eq 1) 'Success unaffected by prior failed options'
    }
    Test-Case 'Option 10 skip leaves Remote Assistance unchanged' {
        Reset-Records
        Set-RemoteDesktop
        Assert-True ($script:writes.Count -eq 0) 'Skip causes no registry changes'
    }
    Test-Case 'Option 12 dispatches string, binary and empty multistring settings' {
        Reset-Records
        Set-SecurityOptions
        $empty = @($script:writes | Where-Object Type -eq 'MultiString')
        Assert-True ($empty.Count -eq 2 -and $empty[0].Value.Count -eq 0) 'Empty REG_MULTI_SZ arguments bind correctly'
        Assert-True (@($script:writes | Where-Object Type -eq 'Binary').Count -eq 1) 'Binary security setting dispatched'
        Assert-True ($script:bad.Count -eq 0) 'No binding or native errors'
    }
    Test-Case 'Option 13 applies both audit registry settings and auditpol' {
        Reset-Records
        Enable-Auditing
        Assert-True ($script:writes.Count -eq 2) 'Both audit registry settings dispatched'
        Assert-True ($script:nativeCalls[0].FilePath -eq 'auditpol.exe') 'Auditpol invoked'
        Assert-True ($script:good.Count -eq 1 -and $script:bad.Count -eq 0) 'Successful audit result'
    }
    Test-Case 'Option 13 reports auditpol failure without a success message' {
        Reset-Records; $script:failNative = 'auditpol.exe'
        Enable-Auditing
        Assert-True ($script:good.Count -eq 0 -and $script:bad.Count -eq 1) 'Audit failure visible'
        Assert-True ($script:writes.Count -eq 1) 'Stops after failed native command'
    }
    Test-Case 'Option 15 handles every advanced registry call including UNC names' {
        Reset-Records
        Set-AdvancedSecurity
        $netlogon = @($script:writes | Where-Object Name -eq '\\*\NETLOGON')
        Assert-True ($netlogon.Count -eq 1 -and $netlogon[0].Type -eq 'String') 'NETLOGON registry value name preserved'
        Assert-True (@($script:writes | Where-Object Name -eq '\\*\SYSVOL').Count -eq 1) 'SYSVOL value preserved'
        Assert-True ($script:writes.Count -gt 100 -and $script:bad.Count -eq 0) 'All advanced calls dispatch'
    }
    Test-Case 'Option 15 reports failed registry writes as incomplete' {
        Reset-Records; $script:failRegistryName = 'DisableWcnUi'
        Set-AdvancedSecurity
        Assert-True ($script:good.Count -eq 0 -and $script:bad.Count -gt 0) 'No false advanced-security success'
    }
    function Confirm-Action { return $true }
    Test-Case 'Option 21 aborts if the user-rights backup fails' {
        Reset-Records; $script:failNative = 'secedit.exe'
        Set-UserRights
        Assert-True ($script:nativeCalls.Count -eq 1) 'Only backup attempted'
        Assert-True ($script:good.Count -eq 0 -and $script:bad.Count -eq 1) 'Backup failure visible'
    }
    Test-Case 'Run everything restores interactive mode after an unexpected failure' {
        function Set-UserProperties { throw 'Simulated unexpected failure' }
        $caught = $false
        try { Invoke-Everything } catch { $caught = $true }
        Assert-True ($caught -and -not $script:Auto) 'Auto mode reset by finally'
    }
    Test-Case 'README audit removes unauthorized admin membership and only disables accounts' {
        Reset-Records
        $script:CurrentUserName = 'student'
        $fixture = Join-Path $testTemp 'README.txt'
        Set-Content -LiteralPath $fixture -Value "Authorized Administrators:`nalice`nAuthorized Users:`nstudent"
        $script:fixture = $fixture
        function Find-ReadmeFile { Get-Item -LiteralPath $script:fixture }
        function Read-Host { param([string]$Prompt) if ($Prompt -like 'Apply changes?*') { return 'Y' }; return '' }
        function Get-LocalUser {
            foreach ($name in 'alice', 'student', 'intruder') {
                [pscustomobject]@{Name = $name; Enabled = $true; SID = [pscustomobject]@{Value = "S-1-5-21-111-222-333-1001"}}
            }
        }
        function Get-LocalGroupMember {
            param($Group, $ErrorAction)
            foreach ($name in 'alice', 'student', 'intruder') {
                [pscustomobject]@{Name = "PC\$name"; ObjectClass = 'User'; SID = [pscustomobject]@{Value = "S-1-5-21-111-222-333-1001"}}
            }
        }
        $script:disabled = @(); $script:removedMembers = @()
        function Disable-LocalUser { param($Name, $ErrorAction) $script:disabled += $Name }
        function Remove-LocalGroupMember { param($Group, $Member, $ErrorAction) $script:removedMembers += $Member }
        Invoke-ReadmeAudit
        Assert-True ($script:disabled.Count -eq 1 -and $script:disabled[0] -eq 'intruder') 'Only unauthorized account disabled'
        Assert-True ($script:removedMembers.Count -eq 1 -and $script:removedMembers[0] -eq 'PC\intruder') 'Unauthorized admin membership removed; current account preserved'
    }
    Test-Case 'Maintained script has no account-deletion commands or R helper calls' {
        $commands = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
        Assert-True (@($commands | Where-Object { $_.GetCommandName() -in @('R', 'Remove-LocalUser') }).Count -eq 0) 'No history collision or account deletion'
    }
}
finally {
    $env:TEMP = $oldTemp
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $testTemp -Recurse -Force
}

if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    Remove-Item Function:\Test-Path, Function:\New-Item, Function:\New-ItemProperty
    ${function:Set-RegistryValue} = $realRegistryWriter
    Test-Case 'Windows registry integration: DWORD, string, binary and empty REG_MULTI_SZ read back correctly' {
        $key = 'HKCU:\Software\CyberPatriot-Hardening-Tests\' + [guid]::NewGuid()
        $before = $script:RegFail
        try {
            Set-RegistryValue $key 'Number' 1
            Set-RegistryValue $key 'Text' 'Authorized users only' 'String'
            Set-RegistryValue $key 'Bytes' ([byte[]]@(0, 1)) 'Binary'
            Set-RegistryValue $key 'EmptyList' @() 'MultiString'
            Assert-True ($script:RegFail -eq $before) 'All real registry writes succeeded'
            $values = Get-ItemProperty -LiteralPath $key
            Assert-True ($values.Number -eq 1 -and $values.Text -eq 'Authorized users only') 'DWORD and string round trip'
            Assert-True ($values.Bytes.Count -eq 2 -and $values.Bytes[1] -eq 1) 'Binary round trip'
            Assert-True ($values.EmptyList.Count -eq 0) 'Empty multistring round trip'
            Assert-True ((Get-Item -LiteralPath $key).GetValueKind('EmptyList') -eq 'MultiString') 'Correct registry value kind'
        }
        finally { Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
else { Write-Host 'SKIP: Real Windows registry integration requires Windows.' }
Write-Host "$script:passed tests passed. No hardening actions were executed."
