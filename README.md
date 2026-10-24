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

Persisting advanced auditing requires Microsoft's LGPO utility. Option 13 downloads
the official Microsoft archive on first use, verifies LGPO.exe's Microsoft
Authenticode signature, and caches it in
`%ProgramData%\CyberPatriot-Hardening\Tools`. Internet access to
`download.microsoft.com` is required for that download. For offline use, download
LGPO from the [Microsoft Security Compliance Toolkit](https://www.microsoft.com/download/details.aspx?id=55319)
and place its signed `LGPO.exe` in a `tools` folder beside the script. Invalid
signatures and missing prerequisites stop the audit step; validation is never
disabled. Policy backups and audit verification files are retained on the Desktop
alongside the transcript.

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
  listening-port evidence, and saves suggestions separately. Task/startup targets
  are selected per question; high ports are never automatically labeled malicious.
  Review and enter answers in the original question files yourself.
- **G** opens the same opt-in global object auditing setup as main option 25.

Task 3 disables the selected unauthorized account instead of deleting it, even
when the tutorial requests deletion. A grader that requires deletion may leave
that check incomplete. Targeted files and reviewed media are moved to
`%ProgramData%\CyberPatriot-Hardening\Quarantine` with a hash/path manifest instead
of being destroyed. Task/service/startup/share metadata is backed up before
targeted cleanup. Complete forensics before cleanup. No score or answer files are
modified automatically, and no point totals are guaranteed.

Run regression checks from the repository directory without elevation:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Hardening.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Warrior.ps1
```

Tests import function declarations only and simulate hardening operations. On
Windows, they also round-trip registry values in a temporary HKCU test key and
remove that key afterward. They never change system policy, accounts or services.
The simulated checks include local/effective firewall-policy mismatches, missing
persisted auditing, policy overrides, and LGPO-signature rejection. They can also
run with `pwsh` on Linux; real registry integration is skipped there. They do not
validate the Microsoft download or replace actual GPO/auditing/firewall testing
on a disposable Windows 11 VM.
