#Requires -Version 5.1
<#
Compatibility launcher for the maintained Windows 11 hardening toolkit.
Keep CyberPatriot-Win11-Hardening.ps1 in the same folder as this file.
#>
$toolkit = Join-Path $PSScriptRoot 'CyberPatriot-Win11-Hardening.ps1'
if (-not (Test-Path -LiteralPath $toolkit -PathType Leaf)) {
    Write-Error 'Download the complete repository: CyberPatriot-Win11-Hardening.ps1 must be beside Win112026.ps1.'
    exit 1
}
& $toolkit
