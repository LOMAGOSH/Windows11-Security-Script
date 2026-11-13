# Windows11-Security-Script

Download the repository ZIP and extract it, keeping the files together. Double-click
`Run-Hardening.cmd`, then approve the Windows UAC prompt. The launcher runs
`CyberPatriot-Win11-Hardening.ps1` in elevated, 64-bit Windows PowerShell 5.1.
`Win112026.ps1` forwards to the same maintained script. Keep
`Windows-Policy.ps1` and `Windows-Warrior.ps1` beside the main script; all are
included in the repository ZIP.

Read the competition README and finish forensics before applying hardening.
Menu option 23 audits the authorized-user and administrator lists. Unauthorized
accounts can be disabled; account deletion is unavailable. Removing a group
membership does not delete an account. Review prompts and the transcript saved to
the Desktop (or TEMP if the Desktop is unavailable).

Option 2 uses `DefaultNewPassword` from the script settings automatically, without
asking you to type a password. It changes enabled local accounts and keeps a
separate confirmation for changing your currently signed-in account (default Yes;
choose No to skip it). New users
created from option 14 or the guided walkthrough, and individual walkthrough
password resets, use the same configured default. Windows password policy and
history can still reject a change; those failures are reported.

Option 12 applies the configured authorized-use logon warning automatically,
including a warning that unauthorized users must disconnect and that activity
may be monitored. No banner title/text entry is required. To customize these
defaults later, edit `DefaultLogonCaption`, `DefaultLogonText`, and
`DefaultNewPassword` in the main script's settings block.

The registry writer uses `Set-RegistryValue`; `R` is PowerShell's built-in history
alias and must not be used for registry changes. Failed writes and nonzero native
policy-command results are reported as errors. CIS references identify intended
settings; they do not constitute a verified compliance assessment.

Option 6 saves Domain, Private and Public firewall profiles to the local GPO
(`localhost`) and the local persistent store. It refreshes computer policy and
checks both the stored GPO profiles and the effective firewall configuration.
Profiles are enabled, inbound traffic defaults to Block, outbound traffic defaults
to Allow, and logging is enabled. A domain policy that overrides these values is
reported as a verification error.

Option 13 backs up local Group Policy and effective auditing, saves advanced audit
subcategories to the local GPO, refreshes policy, and compares the saved and
effective settings by GUID. It retains the toolkit's existing Success and Failure
configuration for every subcategory reported by Windows. It also persists the
advanced-audit override and process-command-line logging settings in Registry.pol.
Close and reopen `gpedit.msc` or `secpol.msc` afterward; the editor can cache values.
Global Object Access Auditing file/registry SACLs are a separate configuration and
are left unchanged by option 13. Option 25 provides a separate opt-in setup:
select Files/Registry, an account or group, and Read/Write/Both. It backs up the
existing entries and applies live `auditpol /resourceSACL` rules. Those global
resource-SACL entries are **not** saved in the local GPO definition; view them with
`auditpol /resourceSACL /view`. Domain/global-object policy can replace them.

Option 13 uses built-in `auditpol`, `secedit`, `gpupdate`, and Windows' documented
`IGroupPolicyObject` COM API. It does not download or require LGPO.exe. The API
saves Registry.pol and Group Policy revisions; audit/security extension IDs are
read from the installed Windows registry. Existing GPO files, unrelated template
sections, and per-user audit rows are preserved/backed up. Full option 13 also
configures and verifies the nine legacy `Local Policies > Audit Policy` categories
for visibility; the advanced subcategory override remains enabled for enforcement.
Individual walkthrough audit tasks change only their selected subcategory.

Options 4 and 5 back up account policy, apply the configured values, then read
back effective numeric settings using NetAPI and complexity/encryption settings
from `secedit /export /mergedpolicy`. A mismatch gets one repair attempt and a
fresh verification. Persistent overrides, missing values and rejected changes are
reported as failures. Option 4 also verifies and repairs password-required and
password-expiration flags on enabled local accounts, without resetting passwords
or enabling disabled accounts. Defaults remain history 24, maximum age 60 days,
minimum age 1 day, minimum length 14, complexity enabled, reversible encryption
disabled; lockout remains 5 attempts / 30 minutes / 30 minutes.

This update does not write unverified registry settings for "Relax minimum
password length limits" or "Minimum password length audit" just to fill in the
editor. Requests above 14 characters depend on the Windows version and supported
extended-length policy; rejected or ineffective settings fail verification.
Audit/password/lockout backup folders are printed even if a later check fails.

The native interface follows Microsoft's [Windows SDK gpedit.h](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/GPEdit.h)
and documented [IGroupPolicyObject.Save](https://learn.microsoft.com/windows/win32/api/gpedit/nf-gpedit-igrouppolicyobject-save).
Native GPO operations require elevated Windows with local Group Policy support.

Option 24 opens the guided Windows Warrior walkthrough. Keep
`Windows-Warrior.ps1` beside the main script; download and extract the complete
repository ZIP. All 50 task cards include a PowerShell example, an explanation,
and a GUI path. Example names such as `hacker`, `webdev`, and `EvilSvc` are teaching
examples; actions always request and confirm this image's actual targets.

Inside option 24:

- **R** loads the current README's authorized-user/admin lists after you confirm
  the parsed names. Option 23 also shares its confirmed account lists. Other README
  instructions remain subject to manual review; the tool never executes README text.
- **1–50** previews a task and asks before applying it. **A** walks through every
  task with confirmation for each; names/paths have no default sample target.
- **M** previews creation of a local group, additions, and optional removal of
  other local user memberships. It preserves accounts and the current user's
  membership.
- **P** lists installed apps and updates or removes one exact package ID selected
  from this image. Main option 18 also updates apps generally.
- **F** reads your actual question file when supplied, collects build/task/startup/
  listening-port/share evidence, and saves suggestions separately. Task/startup targets
  are selected per question; high ports are never automatically labeled malicious.
  It includes IPC$ reference/host evidence, PID 4 TCP listeners, and explicit
  reverse/ROT13/Atbash cipher transformations. Review and enter answers in the
  original question files yourself.
- **G** opens the same opt-in global object auditing setup as main option 25.

Task 3 disables the selected unauthorized account instead of deleting it, even
when the tutorial requests deletion. A grader that requires deletion may leave
that check incomplete. Targeted files and reviewed media are moved to
`%ProgramData%\CyberPatriot-Hardening\Quarantine` with a hash/path manifest instead
of being destroyed. Task/service/startup/share metadata is backed up before
targeted cleanup. Complete forensics before cleanup. No score or answer files are
modified automatically, and no point totals are guaranteed.

A timestamped, read-only TCP-listener snapshot is saved before this run's hardening
starts. It describes the machine at capture time, not an assumed untouched image.
The System-port helper uses PID 4 evidence and never invents port 139 when the
capture only shows 445. The provided cipher `lnj ehbl ab ren hbL` becomes
`You are on your way` when the explicitly selected transformation is reverse +
ROT13; that transformation is not assumed to solve every cipher. Answer files
remain unchanged.

Run regression checks from the repository directory without elevation:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Hardening.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Warrior.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Policy.ps1
```

Tests import function declarations only and simulate hardening operations. On
Windows, they also round-trip registry values in a temporary HKCU test key and
remove that key afterward. They never change system policy, accounts or services.
The simulated checks cover policy overrides, bounded repairs, missing read-back
fields, account flags, native interface identifiers/vtable order, preservation of
existing GPO files/settings, and forensic evidence handling. The C# bridge is
compiled during tests without executing native operations. Tests can also run
with `pwsh` on Linux; real registry integration is skipped there. Linux results
do not establish actual Windows COM/SAM/GPO/auditing behavior. Validate those on a
disposable Windows 11 VM before applying hardening to an image you need to keep.
