#Requires -Version 5.1
<# Built-in Windows policy support. Importing this file does not change policy. #>
function Initialize-WindowsPolicyApi {
    if ('CyberPatriot.WindowsPolicyApi' -as [type]) { return }
    # Interface order and constants follow Microsoft's gpedit.h and lmaccess.h.
    # Only compiling this type is portable; its methods require elevated Windows.
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.ComponentModel;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace CyberPatriot {
 [ComImport, Guid("EA502723-A23D-11D1-A7D3-0000F87571E3"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
 interface IGroupPolicyObject {
  [PreserveSig] int New([MarshalAs(UnmanagedType.LPWStr)] string domain, [MarshalAs(UnmanagedType.LPWStr)] string name, uint flags);
  [PreserveSig] int OpenDSGPO([MarshalAs(UnmanagedType.LPWStr)] string path, uint flags);
  [PreserveSig] int OpenLocalMachineGPO(uint flags);
  [PreserveSig] int OpenRemoteMachineGPO([MarshalAs(UnmanagedType.LPWStr)] string name, uint flags);
  [PreserveSig] int Save([MarshalAs(UnmanagedType.Bool)] bool machine, [MarshalAs(UnmanagedType.Bool)] bool add, ref Guid extension, ref Guid editor);
  [PreserveSig] int Delete();
  [PreserveSig] int GetName([MarshalAs(UnmanagedType.LPWStr)] StringBuilder name, int size);
  [PreserveSig] int GetDisplayName([MarshalAs(UnmanagedType.LPWStr)] StringBuilder name, int size);
  [PreserveSig] int SetDisplayName([MarshalAs(UnmanagedType.LPWStr)] string name);
  [PreserveSig] int GetPath([MarshalAs(UnmanagedType.LPWStr)] StringBuilder path, int size);
  [PreserveSig] int GetDSPath(uint section, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder path, int size);
  [PreserveSig] int GetFileSysPath(uint section, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder path, int size);
  [PreserveSig] int GetRegistryKey(uint section, out IntPtr key);
 }
 public static class WindowsPolicyApi {
  static readonly Guid GpoClass = new Guid("EA502722-A23D-11D1-A7D3-0000F87571E3");
  // This tool's own editor identity; not an invented Microsoft extension GUID.
  static readonly Guid Editor = new Guid("CB0E4DB0-DC6B-43C5-9A61-461DE3783264");
  static void Check(int hr) { if (hr < 0) Marshal.ThrowExceptionForHR(hr); }
  static IGroupPolicyObject Open() {
   if (Environment.OSVersion.Platform != PlatformID.Win32NT) throw new PlatformNotSupportedException("Windows policy APIs require Windows.");
   IGroupPolicyObject gpo = (IGroupPolicyObject)Activator.CreateInstance(Type.GetTypeFromCLSID(GpoClass));
   try { Check(gpo.OpenLocalMachineGPO(1)); return gpo; }
   catch { Marshal.FinalReleaseComObject(gpo); throw; }
  }
  static string MachinePath(IGroupPolicyObject gpo) {
   StringBuilder path = new StringBuilder(32768);
   Check(gpo.GetFileSysPath(2, path, path.Capacity)); return path.ToString();
  }
  public static string GetMachinePath() {
   IGroupPolicyObject gpo = Open();
   try { return MachinePath(gpo); } finally { Marshal.FinalReleaseComObject(gpo); }
  }
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern int RegCreateKeyEx(IntPtr root, string name, uint reserved, string cls, uint options, uint access, IntPtr security, out IntPtr key, out uint disposition);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern int RegSetValueEx(IntPtr key, string name, uint reserved, uint kind, ref uint value, uint length);
  [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
  static void Dword(IntPtr root, string path, string name, uint value) {
   IntPtr key; uint disposition;
   int error = RegCreateKeyEx(root, path, 0, null, 0, 0x0002, IntPtr.Zero, out key, out disposition);
   if (error != 0) throw new Win32Exception(error);
   try { error=RegSetValueEx(key,name,0,4,ref value,4); if(error!=0)throw new Win32Exception(error); }
   finally { RegCloseKey(key); }
  }
  static void Copy(string source, string target) {
   Directory.CreateDirectory(Path.GetDirectoryName(target)); File.Copy(source,target,true);
  }
  public static void SaveAudit(string csv, string legacyInf, Guid auditExtension, Guid securityExtension) {
   IGroupPolicyObject gpo = Open();
   try {
    string machine=MachinePath(gpo);
    Copy(csv,Path.Combine(machine,@"Microsoft\Windows NT\Audit\audit.csv"));
    if (!String.IsNullOrEmpty(legacyInf)) Copy(legacyInf,Path.Combine(machine,@"Microsoft\Windows NT\SecEdit\GptTmpl.inf"));
    IntPtr root; Check(gpo.GetRegistryKey(2,out root));
    try {
     Dword(root,@"SYSTEM\CurrentControlSet\Control\Lsa","SCENoApplyLegacyAuditPolicy",1);
     Dword(root,@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit","ProcessCreationIncludeCmdLine_Enabled",1);
    } finally { RegCloseKey(root); }
    Guid editor=Editor;
    Guid registry=new Guid("35378EAC-683F-11D2-A89A-00C04FBBCFA2");
    Check(gpo.Save(true,true,ref registry,ref editor));
    if(!String.IsNullOrEmpty(legacyInf)) Check(gpo.Save(true,true,ref securityExtension,ref editor));
    Check(gpo.Save(true,true,ref auditExtension,ref editor));
   } finally { Marshal.FinalReleaseComObject(gpo); }
  }
  [StructLayout(LayoutKind.Sequential)] struct Modals0 { public uint Length,MaximumAge,MinimumAge,ForceLogoff,History; }
  [StructLayout(LayoutKind.Sequential)] struct Modals3 { public uint Duration,Window,Threshold; }
  [DllImport("netapi32.dll",CharSet=CharSet.Unicode)] static extern int NetUserModalsGet(string server,uint level,out IntPtr data);
  [DllImport("netapi32.dll")] static extern int NetApiBufferFree(IntPtr data);
  [DllImport("netapi32.dll",CharSet=CharSet.Unicode)] static extern int NetUserModalsSet(string server,uint level,ref Modals0 data,out uint parameter);
  static int Days(uint value) { return value==UInt32.MaxValue ? 0 : checked((int)(value/86400)); }
  static int Minutes(uint value) { return value==UInt32.MaxValue ? 0 : checked((int)(value/60)); }
  public static Dictionary<string,int> ReadAccountPolicy() {
   IntPtr data=IntPtr.Zero; Modals0 password; Modals3 account;
   int error=NetUserModalsGet(null,0,out data); if(error!=0)throw new Win32Exception(error);
   try { password=(Modals0)Marshal.PtrToStructure(data,typeof(Modals0)); } finally { NetApiBufferFree(data); }
   error=NetUserModalsGet(null,3,out data); if(error!=0)throw new Win32Exception(error);
   try { account=(Modals3)Marshal.PtrToStructure(data,typeof(Modals3)); } finally { NetApiBufferFree(data); }
   return new Dictionary<string,int> {
    {"MinimumPasswordLength",checked((int)password.Length)}, {"MaximumPasswordAge",Days(password.MaximumAge)},
    {"MinimumPasswordAge",Days(password.MinimumAge)}, {"PasswordHistorySize",checked((int)password.History)},
    {"LockoutBadCount",checked((int)account.Threshold)}, {"LockoutDuration",Minutes(account.Duration)}, {"ResetLockoutCount",Minutes(account.Window)}
   };
  }
  public static void SetMinimumLength(uint length) {
   IntPtr data; int error=NetUserModalsGet(null,0,out data); if(error!=0)throw new Win32Exception(error);
   Modals0 policy; try { policy=(Modals0)Marshal.PtrToStructure(data,typeof(Modals0)); } finally { NetApiBufferFree(data); }
   policy.Length=length; uint parameter; error=NetUserModalsSet(null,0,ref policy,out parameter);
   if(error!=0)throw new Win32Exception(error,"Cannot set minimum password length (parameter "+parameter+"). For lengths above 14, configure the supported Relax minimum password length limits policy first.");
  }
 }
}
'@ -ErrorAction Stop
}

function Get-LocalGpoMachinePath {
    Initialize-WindowsPolicyApi
    [CyberPatriot.WindowsPolicyApi]::GetMachinePath()
}

function Get-PolicyExtensionGuid {
    param([ValidateSet('auditcse.dll','scecli.dll')][string]$Dll)
    $extensions = @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions' -ErrorAction Stop | Where-Object {
        $file = (Get-ItemProperty -LiteralPath $_.PSPath -Name DllName -ErrorAction SilentlyContinue).DllName
        $file -and ([IO.Path]::GetFileName([Environment]::ExpandEnvironmentVariables($file)) -ieq $Dll)
    })
    if ($extensions.Count -ne 1) { throw "Windows did not report exactly one $Dll Group Policy extension; no extension identifier was guessed." }
    [guid]$extensions[0].PSChildName
}

function Set-PolicyInfSection {
    param([string]$ExistingText = '', [string]$Section, [System.Collections.IDictionary]$Values)
    # Preserve unrelated sections and lines. Replace requested keys only.
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $inside=$false; $found=$false
    $remaining=@{}; foreach($key in $Values.Keys){$remaining[$key]=[string]$Values[$key]}
    foreach($line in ($ExistingText -split '\r?\n')) {
        if($line -match '^\s*\[([^\]]+)\]\s*$') {
            if($inside){foreach($key in @($remaining.Keys)){$lines.Add("$key = $($remaining[$key])");$remaining.Remove($key)}}
            $inside=($Matches[1] -ieq $Section); if($inside){$found=$true}
        }
        if($inside -and $line -match '^\s*([^;=]+?)\s*=') {
            $key=$Matches[1].Trim()
            if($Values.Contains($key)) { if($remaining.ContainsKey($key)){$lines.Add("$key = $($Values[$key])");$remaining.Remove($key)};continue }
        }
        $lines.Add($line)
    }
    if(-not $found){$lines.Add("[$Section]")}
    foreach($key in $remaining.Keys){$lines.Add("$key = $($remaining[$key])")}
    $lines -join "`r`n"
}

function Read-PolicyInfSection {
    param([string]$Text,[string]$Section)
    $values=@{}; $inside=$false
    foreach($line in ($Text -split '\r?\n')) {
        if($line -match '^\s*\[([^\]]+)\]\s*$'){$inside=($Matches[1] -ieq $Section);continue}
        if($inside -and $line -match '^\s*([^;=]+?)\s*=\s*(.*?)\s*$'){$values[$Matches[1].Trim()]=$Matches[2]}
    }
    $values
}

function Get-LegacyAuditValues {
    [ordered]@{AuditSystemEvents=3;AuditLogonEvents=3;AuditObjectAccess=3;AuditPrivilegeUse=3;AuditPolicyChange=3;AuditAccountManage=3;AuditProcessTracking=3;AuditDSAccess=3;AuditAccountLogon=3}
}

function New-SecurityPolicyInf {
    param([string]$Section,[System.Collections.IDictionary]$Values)
    Set-PolicyInfSection -ExistingText "[Unicode]`r`nUnicode=yes`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n" -Section $Section -Values $Values
}

function Invoke-NativeGpoAuditSave {
    param([string]$Csv,[string]$LegacyInf,[guid]$AuditExtension,[guid]$SecurityExtension)
    Initialize-WindowsPolicyApi
    [CyberPatriot.WindowsPolicyApi]::SaveAudit($Csv,$LegacyInf,$AuditExtension,$SecurityExtension)
}

function Save-LocalAuditPolicy {
    param([string]$Csv,[string]$Work,[switch]$Legacy)
    $machine=Get-LocalGpoMachinePath
    $root=Split-Path -Parent $machine
    if(Test-Path -LiteralPath $root){Copy-Item -LiteralPath $root -Destination (Join-Path $Work 'LocalGpoBackup') -Recurse -Force -ErrorAction Stop}
    $existingAudit=Join-Path $machine 'Microsoft\Windows NT\Audit\audit.csv'
    if(Test-Path -LiteralPath $existingAudit) {
        $headers='Machine Name','Policy Target','Subcategory','Subcategory GUID','Inclusion Setting','Exclusion Setting','Setting Value'
        $other=@(Get-Content -LiteralPath $existingAudit -ErrorAction Stop | Select-Object -Skip 1 | ConvertFrom-Csv -Header $headers | Where-Object {$_.'Policy Target' -ne 'System'})
        if($other.Count) {
            $rows=@(Import-Csv -LiteralPath $Csv -ErrorAction Stop)+$other
            $Csv=Join-Path $Work 'audit-with-existing-user-options.csv'
            $rows | Export-Csv -LiteralPath $Csv -NoTypeInformation -Encoding Unicode -ErrorAction Stop
        }
    }
    $audit=Get-PolicyExtensionGuid auditcse.dll
    $security=[guid]::Empty; $merged=$null
    if($Legacy) {
        $security=Get-PolicyExtensionGuid scecli.dll
        $existing=Join-Path $machine 'Microsoft\Windows NT\SecEdit\GptTmpl.inf'
        $text=if(Test-Path -LiteralPath $existing){Get-Content -LiteralPath $existing -Raw -ErrorAction Stop}else{New-SecurityPolicyInf -Section 'Event Audit' -Values @{}}
        $merged=Join-Path $Work 'legacy-gpo.inf'
        Set-PolicyInfSection -ExistingText $text -Section 'Event Audit' -Values (Get-LegacyAuditValues) | Set-Content -LiteralPath $merged -Encoding Unicode -ErrorAction Stop
    }
    Invoke-NativeGpoAuditSave -Csv $Csv -LegacyInf $merged -AuditExtension $audit -SecurityExtension $security
    Join-Path $machine 'Microsoft\Windows NT\Audit\audit.csv'
}

function Get-EffectiveAccountPolicy {
    param([string]$Work)
    $export=Join-Path $Work ('effective-'+[guid]::NewGuid()+'.inf')
    Invoke-NativeCommand secedit.exe @('/export','/mergedpolicy','/cfg',$export,'/areas','SECURITYPOLICY','/quiet') | Out-Null
    $values=Read-PolicyInfSection -Text (Get-Content -LiteralPath $export -Raw -ErrorAction Stop) -Section 'System Access'
    Initialize-WindowsPolicyApi
    # SAM numeric values are the effective local-account policy, not localized net.exe text.
    $sam=[CyberPatriot.WindowsPolicyApi]::ReadAccountPolicy()
    foreach($key in $sam.Keys){$values[$key]=[int]$sam[$key]}
    $values
}

function Set-AccountPolicyValues {
    param([System.Collections.IDictionary]$Values,[string]$Work)
    $cfg=Join-Path $Work ('desired-'+[guid]::NewGuid()+'.inf')
    New-SecurityPolicyInf -Section 'System Access' -Values $Values | Set-Content -LiteralPath $cfg -Encoding Unicode -ErrorAction Stop
    # Preserve current unrelated SAM settings when setting a longer minimum.
    if($Values.Contains('MinimumPasswordLength') -and [int]$Values['MinimumPasswordLength'] -le 14) {
        Initialize-WindowsPolicyApi
        [CyberPatriot.WindowsPolicyApi]::SetMinimumLength([uint32]$Values['MinimumPasswordLength'])
    }
    Invoke-NativeCommand secedit.exe @('/configure','/db',(Join-Path $Work 'policy.sdb'),'/cfg',$cfg,'/areas','SECURITYPOLICY','/quiet') | Out-Null
}

function Confirm-AccountPolicy {
    param([System.Collections.IDictionary]$Desired,[string]$Work)
    foreach($attempt in 0,1) {
        $actual=Get-EffectiveAccountPolicy -Work $Work
        $bad=@($Desired.Keys | Where-Object { -not $actual.Contains($_) -or [string]$actual[$_] -ne [string]$Desired[$_] })
        if(-not $bad.Count){return}
        if($attempt -eq 0) {
            Write-Warn ('Policy read-back differs; reapplying: '+($bad -join ', '))
            $repair=[ordered]@{};foreach($key in $bad){$repair[$key]=$Desired[$key]}
            Set-AccountPolicyValues -Values $repair -Work $Work
        }
        else { throw ('Effective account policy still differs: '+($bad -join ', ')+'. A domain policy or unsupported setting may override the local configuration.') }
    }
}

function Confirm-EnabledAccountPasswordFlags {
    $enabled=@(Get-LocalUser -ErrorAction Stop | Where-Object Enabled)
    foreach($attempt in 0,1) {
        $accounts=@(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
        $bad=New-Object 'System.Collections.Generic.List[object]'
        foreach($user in $enabled) {
            $state=@($accounts | Where-Object SID -eq $user.SID.Value)
            if($state.Count -ne 1 -or $null -eq $state[0].PasswordRequired -or $null -eq $state[0].PasswordExpires){throw "Cannot verify password flags for $($user.Name)."}
            if(-not $state[0].PasswordRequired -or -not $state[0].PasswordExpires){$bad.Add([pscustomobject]@{User=$user;State=$state[0]})}
        }
        if(-not $bad.Count){return}
        if($attempt -eq 1){throw ('Password-required/expiration flags remain incorrect: '+(($bad.User.Name) -join ', '))}
        foreach($item in $bad) {
            if(-not $item.State.PasswordExpires){Set-LocalUser -Name $item.User.Name -PasswordNeverExpires $false -ErrorAction Stop}
            if(-not $item.State.PasswordRequired){Invoke-NativeCommand net.exe @('user',$item.User.Name,'/passwordreq:yes') | Out-Null}
        }
    }
}
