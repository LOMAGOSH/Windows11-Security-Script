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
    echo " _______  ______     ___     __      __     _____   _     _  _______  ______ "
    echo "[__   __][  ____]   [ _ ]   [  ]    [  ]   [  __ ] [ ]   [ ][__   __][  ____]"
    echo "   [ ]   [ ]___    [ [_] ]  [ _ ]  [ _ ]   [ ]__] ] [ ]_[ ]    [ ]   [ ]___  "
    echo "   [ ]   [  ___]  [ _____ ] [ ][ ][ ][ ]   [  __ ]   [   ]     [ ]   [  ___] "
    echo "   [ ]   [ ]____ [ ]     [ ][ ] [__] [ ]   [ ]__] ]   [ ]      [ ]   [ ]____ "
    echo "   [_]   [______][_]     [_][_]      [_]   [_____]    [_]      [_]   [______]"
    echo "                                                                             " 
    echo "~~~~~~~~~~~~~~~~~~~~~Written by: WC~~~~~~~~~~~~~~~~~~~~~~"
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    echo "1) Set user properties        2) Create a user"
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



:UAC
    echo Enabling User Account Control (UAC)
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    echo UAC has been enabled.
    pause
    goto :menu

:autoUpdate
    echo Enabling automatic updates
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
    pause
    goto :menu

:audit
echo Configuring Audit Policy...

:: Enable auditing for account logon events (Success and Failure)
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable

:: Enable auditing for account management (Success and Failure)
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable

:: Enable auditing for directory service access (Success and Failure)
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable

:: Enable auditing for logon events (Success and Failure)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

:: Enable auditing for object access (Success and Failure)
auditpol /set /subcategory:"Object Access" /success:enable /failure:enable

:: Enable auditing for policy change (Success and Failure)
auditpol /set /subcategory:"Policy Change" /success:enable /failure:enable

:: Enable auditing for privilege use (Success and Failure)
auditpol /set /subcategory:"Privilege Use" /success:enable /failure:enable

:: Enable auditing for process tracking (Success and Failure)
auditpol /set /subcategory:"Process Tracking" /success:enable /failure:enable

:: Enable auditing for system events (Success and Failure)
auditpol /set /subcategory:"System" /success:enable /failure:enable

echo Audit Policy has been successfully configured!
pause
goto :menu


:group
    echo Editing groups
    net localgroup
    pause
    goto :menu

:end
exit
