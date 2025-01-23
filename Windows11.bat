@echo off
setlocal enabledelayedexpansion
net session
if %errorlevel%==0 (
    echo Admin rights granted!
) else (
    echo Failure, no rights
    pause
    exit
)

cls

set /p answer=Have you answered all the forensics questions?[y/n]: 
    if /I {%answer%}=={y} (
        goto :menu
    ) else (
        echo Please go and answer them.
        pause
        exit
    )
    
:menu
cls
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "   #####   ##   ##  #######  ###    ##  ####### "
echo "  ##       ##   ##  ##       ####   ##     ##   "
echo "  ##  ###  #######  #####    ## ##  ##     ##   "
echo "  ##   ##  ##   ##  ##       ##  ## ##     ##   "
echo "   #####   ##   ##  #######  ##   ####     ##   "
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "                              ~Written by: JASIAH.O~                            "
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "1) Set user properties       2) Create a user"
echo "3) Disable a user            4) Change all passwords"
echo "5) Disable guest/admin       6) Set password policy"
echo "7) Set lockout policy        8) Enable Firewall"
echo "9) Search for media files    10) Disable services"
echo "11) Turn on UAC              12) Remote Desktop Config"
echo "13) Enable auto update       14) Security options"
echo "15) Audit the machine        16) Edit groups"
echo "69) Exit                     70) Reboot"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
set /p answer=Please choose an option:

        if "%answer%"=="1" goto :userProp
        if "%answer%"=="2" goto :createUser
        if "%answer%"=="3" goto :disUser
        if "%answer%"=="4" goto :passwd
        if "%answer%"=="5" goto :disGueAdm
        if "%answer%"=="6" goto :passwdPol
        if "%answer%"=="7" goto :lockout
        if "%answer%"=="8" goto :firewall
        if "%answer%"=="9" goto :badFiles
        if "%answer%"=="10" goto :services
        if "%answer%"=="11" goto :UAC
        if "%answer%"=="12" goto :remDesk
        if "%answer%"=="13" goto :autoUpdate
        if "%answer%"=="14" goto :secOpt
        if "%answer%"=="15" goto :audit
        if "%answer%"=="16" goto :group
        if "%answer%"=="69" exit
        if "%answer%"=="70" shutdown /r
    pause

:userProp
    echo Setting password never expires
    wmic UserAccount set PasswordExpires=True
    wmic UserAccount set PasswordChangeable=True
    wmic UserAccount set PasswordRequired=True

    pause
    goto :menu

:passwd
echo Changing all user passwords to '1qaz!QAZ2wsx@WSX'...

:: Run the PowerShell script to change all local user passwords
powershell -command ^
    "$newPassword = '1qaz!QAZ2wsx@WSX';" ^
    "$users = Get-WmiObject -Class Win32_UserAccount -Filter 'LocalAccount=True AND Disabled=False';" ^
    "foreach ($user in $users) {" ^
    "    try {" ^
    "        $username = $user.Name;" ^
    "        ([ADSI]'WinNT://$env:COMPUTERNAME/$username,user').SetPassword($newPassword);" ^
    "        Write-Host 'Password for $username has been changed successfully.' -ForegroundColor Green;" ^
    "    } catch {" ^
    "        Write-Host 'Failed to change password for $username.' -ForegroundColor Red;" ^
    "    }" ^
    "}"

pause
goto :menu

    
:disUser
    cls
    net users
    set /p answer=Would you like to disable a user? [y/n]: 
    if /I "%answer%"=="y" (
        cls
        net users
        set /p DISABLE=What is the name of the user?:
        net user !DISABLE! /active:no
        echo !DISABLE! has been disabled
        pause
        goto :disUser
    )
    
    pause
    goto :menu
    
:createUser
    set /p answer=Would you like to create a user? [y/n]: 
    if /I "%answer%"=="y" (
        set /p NAME=What is the user you would like to create?:
        net user !NAME! /add
        echo !NAME! has been added
        pause 
        goto :createUser
    ) 
    goto :menu

:disGueAdm
    rem Disables the guest account
    net user Guest /active:no
    echo Guest account is disabled.
    
    rem Disables the Administrator account
    net user Administrator /active:no
    echo Admin account is disabled.
    pause
    goto :menu

:passwdPol
echo Configuring Password Policy...
:: Enforce password history to remember 24 passwords
net accounts /uniquepw:24

:: Set maximum password age to 20 days
net accounts /maxpwage:20

:: Set minimum password age to 10 days
net accounts /minpwage:10

:: Set minimum password length to 14 characters
net accounts /minpwlen:14

:: Enable password complexity requirements
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v PasswordComplexity /t REG_DWORD /d 1 /f

:: Disable storing passwords using reversible encryption
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v ClearTextPassword /t REG_DWORD /d 0 /f

:: Enable relaxing minimum password length limits
:: (This feature is specific to Windows 10/11 and may need manual adjustment in some systems)

echo Password Policy has been successfully configured!
pause
goto :menu


:lockout
echo Configuring Account Lockout Policy...

:: Set the account lockout duration to 30 minutes
net accounts /lockoutduration:30

:: Set the account lockout threshold to 5 invalid logon attempts
net accounts /lockoutthreshold:5

:: Set the reset lockout counter duration to 30 minutes
net accounts /lockoutwindow:30

echo Account Lockout Policy has been successfully configured!
pause
goto :menu


:firewall
echo Configuring Windows Defender Firewall...

:: Ensure the Windows Firewall service is running
sc start mpssvc >nul 2>&1
if %errorlevel% NEQ 0 (
    echo Failed to start the Windows Firewall service. Please ensure it is enabled.
    pause
    goto :menu
)

:: Turn on the firewall for Domain, Private, and Public profiles
netsh advfirewall set domainprofile state on
netsh advfirewall set privateprofile state on
netsh advfirewall set publicprofile state on

:: Configure firewall policy: block inbound, allow outbound
netsh advfirewall set domainprofile firewallpolicy blockinbound,allowoutbound
netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound
netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound

:: Enable logging for dropped connections
netsh advfirewall set domainprofile logging droppedconnections enable
netsh advfirewall set privateprofile logging droppedconnections enable
netsh advfirewall set publicprofile logging droppedconnections enable

:: Enable logging for allowed connections
netsh advfirewall set domainprofile logging allowedconnections enable
netsh advfirewall set privateprofile logging allowedconnections enable
netsh advfirewall set publicprofile logging allowedconnections enable

:: Specify log file size
netsh advfirewall set domainprofile logging maxfilesize 32767
netsh advfirewall set privateprofile logging maxfilesize 32767
netsh advfirewall set publicprofile logging maxfilesize 32767

echo Windows Defender Firewall has been successfully configured!
pause
goto :menu

:services
echo Disabling unnecessary services...

:: Windows Remote Management
sc config WinRM start= disabled
sc stop WinRM

:: SSDP Discovery
sc config SSDPSRV start= disabled
sc stop SSDPSRV

:: Remote Registry
sc config RemoteRegistry start= disabled
sc stop RemoteRegistry

:: Windows Error Reporting
sc config WerSvc start= disabled
sc stop WerSvc

:: Xbox Live Networking Service
sc config XboxNetApiSvc start= disabled
sc stop XboxNetApiSvc

:: Xbox Live Auth Manager
sc config XblAuthManager start= disabled
sc stop XblAuthManager

:: Xbox Game Save
sc config XblGameSave start= disabled
sc stop XblGameSave

:: Windows Media Player Network Sharing
sc config WMPNetworkSvc start= disabled
sc stop WMPNetworkSvc

:: Diagnostic Service Host
sc config WdiServiceHost start= disabled
sc stop WdiServiceHost

:: Additional Non-Critical Services
:: Bluetooth Support Service
sc config bthserv start= disabled
sc stop bthserv

:: AllJoyn Router Service
sc config AJRouter start= disabled
sc stop AJRouter

:: Downloaded Maps Manager
sc config MapsBroker start= disabled
sc stop MapsBroker

:: Internet Connection Sharing (ICS)
sc config SharedAccess start= disabled
sc stop SharedAccess

:: Fax Service
sc config Fax start= disabled
sc stop Fax

:: Device Management Enrollment Service
sc config DmEnrollmentSvc start= disabled
sc stop DmEnrollmentSvc

:: Windows Event Collector
sc config Wecsvc start= disabled
sc stop Wecsvc

:: Sensor Monitoring Service
sc config SensorService start= disabled
sc stop SensorService

:: Shell Hardware Detection
sc config ShellHWDetection start= disabled
sc stop ShellHWDetection

echo All unnecessary services have been stopped and disabled.
pause
goto :menu


:UAC
    echo Enabling User Account Control (UAC)
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    echo UAC has been enabled.
    pause
    goto :menu

:autoUpdate
echo Configuring Automatic Updates...

:: Set the Windows Update to Automatic (Registry)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f

:: Enable Automatic Updates Service
sc config wuauserv start= auto
net start wuauserv

:: Ensure Background Intelligent Transfer Service (BITS) is running
sc config bits start= auto
net start bits

echo Automatic Updates have been successfully enabled!
pause
goto :menu

:secOpt
	echo Changing security options now.

	rem Restrict CD ROM drive
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f

	rem Automatic Admin logon
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
	
	rem Logon message text
	set /p body=Please enter logon text: 
		reg ADD "HKLM\SYSTEM\microsoft\Windwos\CurrentVersion\Policies\System\legalnoticetext" /v LegalNoticeText /t REG_SZ /d "%body%"
	
	rem Logon message title bar
	set /p subject=Please enter the title of the message: 
		reg ADD "HKLM\SYSTEM\microsoft\Windwos\CurrentVersion\Policies\System\legalnoticecaption" /v LegalNoticeCaption /t REG_SZ /d "%subject%"
	
	rem Wipe page file from shutdown
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
	
	rem Disallow remote access to floppie disks
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
	
	rem Prevent print driver installs 
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
	
	rem Limit local account use of blank passwords to console
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
	
	rem Auditing access of Global System Objects
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v auditbaseobjects /t REG_DWORD /d 1 /f
	
	rem Auditing Backup and Restore
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v fullprivilegeauditing /t REG_DWORD /d 1 /f
	
	rem Do not display last user on logon
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
	
	rem UAC setting (Prompt on Secure Desktop)
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
	
	rem Enable Installer Detection
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
	
	rem Undock without logon
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
	
	rem Maximum Machine Password Age
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
	
	rem Disable machine account password changes
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
	
	rem Require Strong Session Key
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
	
	rem Require Sign/Seal
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
	
	rem Sign Channel
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
	
	rem Seal Channel
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
	
	rem Don't disable CTRL+ALT+DEL even though it serves no purpose
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f 
	
	rem Restrict Anonymous Enumeration #1
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f 
	
	rem Restrict Anonymous Enumeration #2
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f 
	
	rem Idle Time Limit - 45 mins
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f 
	
	rem Require Security Signature - Disabled pursuant to checklist
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f 
	
	rem Enable Security Signature - Disabled pursuant to checklist
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f 
	
	rem Disable Domain Credential Storage
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f 
	
	rem Don't Give Anons Everyone Permissions
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f 
	
	rem SMB Passwords unencrypted to third party
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
	
	rem Null Session Pipes Cleared
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
	
	rem remotely accessible registry paths cleared
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
	
	rem remotely accessible registry paths and sub-paths cleared
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
	
	rem Restict anonymous access to named pipes and shares
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
	
	rem Allow to use Machine ID for NTLM
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f

	rem Enables DEP
	bcdedit.exe /set {current} nx AlwaysOn
	pause
	goto :menu

:audit
	echo Auditing the maching now
	auditpol /set /category:* /success:enable
	auditpol /set /category:* /failure:enable
	
	pause
	goto :menu




:group
    echo Editing groups
    net localgroup
    pause
    goto :menu

:end
exit
