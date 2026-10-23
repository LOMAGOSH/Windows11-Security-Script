# Windows11-Security-Script

Download the repository ZIP and extract it, keeping the files together. Double-click
`Run-Hardening.cmd`, then approve the Windows UAC prompt. The launcher runs
`CyberPatriot-Win11-Hardening.ps1` in elevated, 64-bit Windows PowerShell 5.1.
`Win112026.ps1` forwards to the same maintained script.

Read the competition README and finish forensics before applying hardening.
Menu option 23 audits the authorized-user and administrator lists. Unauthorized
accounts can be disabled; account deletion is unavailable. Removing a group
membership does not delete an account. Review prompts and the transcript saved to
the Desktop (or TEMP if the Desktop is unavailable).

The registry writer uses `Set-RegistryValue`; `R` is PowerShell's built-in history
alias and must not be used for registry changes. Failed writes and nonzero native
policy-command results are reported as errors. CIS references identify intended
settings; they do not constitute a verified compliance assessment.

Run regression checks from the repository directory without elevation:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Hardening.ps1
```

Tests import function declarations only and simulate hardening operations. On
Windows, they also round-trip registry values in a temporary HKCU test key and
remove that key afterward. They never change system policy, accounts or services.
The simulated checks can also run with `pwsh` on Linux; real registry integration
is skipped there. Validate actual hardening on a disposable Windows 11 VM.
