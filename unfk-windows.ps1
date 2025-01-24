################################################################################################################
###                                                                                                          ###
### WARNING: THIS TOOL IS MADE BY TUTOS the youtuber pharaoh, for everyone who struggles with windows..subscribe ###
###                                                                                                          ###
################################################################################################################
<#
.NOTES
    Author         : TUTOS @tut_os
    Version        : 25.01.11
#>

param (
    [switch]$Debug,
    [string]$Config,
    [switch]$Run
)

# Set DebugPreference based on the -Debug switch
if ($Debug) {
    $DebugPreference = "Continue"
}

if ($Config) {
    $PARAM_CONFIG = $Config
}

$PARAM_RUN = $false
# Handle the -Run switch
if ($Run) {
    Write-Host "Running config file tasks..."
    $PARAM_RUN = $true
}

# Load DLLs
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

# Variable to sync between runspaces
$sync = [Hashtable]::Synchronized(@{})
$sync.PSScriptRoot = $PSScriptRoot
$sync.version = "25.01.11"
$sync.configs = @{}
$sync.ProcessRunning = $false

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "Winutil needs to be run as Administrator. Attempting to relaunch."
    $argList = @()

    $PSBoundParameters.GetEnumerator() | ForEach-Object {
        $argList += if ($_.Value -is [switch] -and $_.Value) {
            "-$($_.Key)"
        } elseif ($_.Value) {
            "-$($_.Key) `"$($_.Value)`""
        }
    }

    $script = if ($MyInvocation.MyCommand.Path) {
        "& { & '$($MyInvocation.MyCommand.Path)' $argList }"
    } else {
        "iex '& { $(irm https://github.com/TUT-OS/TUT_OS/releases/latest/download/winutil.ps1) } $argList'"
    }

    $powershellcmd = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }
    $processCmd = if (Get-Command wt.exe -ErrorAction SilentlyContinue) { "wt.exe" } else { $powershellcmd }

    Start-Process $processCmd -ArgumentList "$powershellcmd -ExecutionPolicy Bypass -NoProfile -Command $script" -Verb RunAs

    break
}

$dateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

$logdir = "$env:localappdata\winutil\logs"
[System.IO.Directory]::CreateDirectory("$logdir") | Out-Null
Start-Transcript -Path "$logdir\winutil_$dateTime.log" -Append -NoClobber | Out-Null

# Set PowerShell window title
$Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Admin)"
clear-host
function Invoke-Microwin {
    <#
        .DESCRIPTION
        Invoke MicroWin routines...
    #>


    if($sync.ProcessRunning) {
        $msg = "GetIso process is currently running."
        [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    # Define the constants for Windows API
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class PowerManagement {
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern EXECUTION_STATE SetThreadExecutionState(EXECUTION_STATE esFlags);

    [FlagsAttribute]
    public enum EXECUTION_STATE : uint {
        ES_SYSTEM_REQUIRED = 0x00000001,
        ES_DISPLAY_REQUIRED = 0x00000002,
        ES_CONTINUOUS = 0x80000000,
    }
}
"@

    # Prevent the machine from sleeping
    [PowerManagement]::SetThreadExecutionState([PowerManagement]::EXECUTION_STATE::ES_CONTINUOUS -bor [PowerManagement]::EXECUTION_STATE::ES_SYSTEM_REQUIRED -bor [PowerManagement]::EXECUTION_STATE::ES_DISPLAY_REQUIRED)

    # Ask the user where to save the file
    $SaveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $SaveDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')
    $SaveDialog.Filter = "ISO images (*.iso)|*.iso"
    $SaveDialog.ShowDialog() | Out-Null

    if ($SaveDialog.FileName -eq "") {
        Write-Host "No file name for the target image was specified"
        Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
        return
    }

    Set-WinUtilTaskbaritem -state "Indeterminate" -overlay "logo"

    Write-Host "Target ISO location: $($SaveDialog.FileName)"

    $index = $sync.MicrowinWindowsFlavors.SelectedValue.Split(":")[0].Trim()
    Write-Host "Index chosen: '$index' from $($sync.MicrowinWindowsFlavors.SelectedValue)"

    $copyToUSB = $sync.WPFMicrowinCopyToUsb.IsChecked
    $injectDrivers = $sync.MicrowinInjectDrivers.IsChecked
    $importDrivers = $sync.MicrowinImportDrivers.IsChecked

    $importVirtIO = $sync.MicrowinCopyVirtIO.IsChecked

    $mountDir = $sync.MicrowinMountDir.Text
    $scratchDir = $sync.MicrowinScratchDir.Text

    # Detect if the Windows image is an ESD file and convert it to WIM
    if (-not (Test-Path -Path "$mountDir\sources\install.wim" -PathType Leaf) -and (Test-Path -Path "$mountDir\sources\install.esd" -PathType Leaf)) {
        Write-Host "Exporting Windows image to a WIM file, keeping the index we want to work on. This can take several minutes, depending on the performance of your computer..."
        Export-WindowsImage -SourceImagePath $mountDir\sources\install.esd -SourceIndex $index -DestinationImagePath $mountDir\sources\install.wim -CompressionType "Max"
        if ($?) {
            Remove-Item -Path "$mountDir\sources\install.esd" -Force
            # Since we've already exported the image index we wanted, switch to the first one
            $index = 1
        } else {
            $msg = "The export process has failed and MicroWin processing cannot continue"
            Write-Host "Failed to export the image"
            [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
            return
        }
    }

    $imgVersion = (Get-WindowsImage -ImagePath $mountDir\sources\install.wim -Index $index).Version
    Write-Host "The Windows Image Build Version is: $imgVersion"

    # Detect image version to avoid performing MicroWin processing on Windows 8 and earlier
    if ((Microwin-TestCompatibleImage $imgVersion $([System.Version]::new(10,0,10240,0))) -eq $false) {
        $msg = "This image is not compatible with MicroWin processing. Make sure it isn't a Windows 8 or earlier image."
        $dlg_msg = $msg + "`n`nIf you want more information, the version of the image selected is $($imgVersion)`n`nIf an image has been incorrectly marked as incompatible, report an issue to the developers."
        Write-Host $msg
        [System.Windows.MessageBox]::Show($dlg_msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Exclamation)
        Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
        return
    }

    # Detect whether the image to process contains Windows 10 and show warning
    if ((Microwin-TestCompatibleImage $imgVersion $([System.Version]::new(10,0,21996,1))) -eq $false) {
        $msg = "Windows 10 has been detected in the image you want to process. While you can continue, Windows 10 is not a recommended target for MicroWin, and you may not get the full experience."
        $dlg_msg = $msg
        Write-Host $msg
        [System.Windows.MessageBox]::Show($dlg_msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Exclamation)
    }

    $mountDirExists = Test-Path $mountDir
    $scratchDirExists = Test-Path $scratchDir
    if (-not $mountDirExists -or -not $scratchDirExists) {
        Write-Error "Required directories '$mountDirExists' '$scratchDirExists' and do not exist."
        Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
        return
    }

    try {

        Write-Host "Mounting Windows image. This may take a while."
        Mount-WindowsImage -ImagePath "$mountDir\sources\install.wim" -Index $index -Path "$scratchDir"
        if ($?) {
            Write-Host "The Windows image has been mounted successfully. Continuing processing..."
        } else {
            Write-Host "Could not mount image. Exiting..."
            Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
            return
        }

        if ($importDrivers) {
            Write-Host "Exporting drivers from active installation..."
            if (Test-Path "$env:TEMP\DRV_EXPORT") {
                Remove-Item "$env:TEMP\DRV_EXPORT" -Recurse -Force
            }
            if (($injectDrivers -and (Test-Path "$($sync.MicrowinDriverLocation.Text)"))) {
                Write-Host "Using specified driver source..."
                dism /english /online /export-driver /destination="$($sync.MicrowinDriverLocation.Text)" | Out-Host
                if ($?) {
                    # Don't add exported drivers yet, that is run later
                    Write-Host "Drivers have been exported successfully."
                } else {
                    Write-Host "Failed to export drivers."
                }
            } else {
                New-Item -Path "$env:TEMP\DRV_EXPORT" -ItemType Directory -Force
                dism /english /online /export-driver /destination="$env:TEMP\DRV_EXPORT" | Out-Host
                if ($?) {
                    Write-Host "Adding exported drivers..."
                    dism /english /image="$scratchDir" /add-driver /driver="$env:TEMP\DRV_EXPORT" /recurse | Out-Host
                } else {
                    Write-Host "Failed to export drivers. Continuing without importing them..."
                }
                if (Test-Path "$env:TEMP\DRV_EXPORT") {
                    Remove-Item "$env:TEMP\DRV_EXPORT" -Recurse -Force
                }
            }
        }

        if ($injectDrivers) {
            $driverPath = $sync.MicrowinDriverLocation.Text
            if (Test-Path $driverPath) {
                Write-Host "Adding Windows Drivers image($scratchDir) drivers($driverPath) "
                dism /English /image:$scratchDir /add-driver /driver:$driverPath /recurse | Out-Host
            } else {
                Write-Host "Path to drivers is invalid continuing without driver injection"
            }
        }

        if ($importVirtIO) {
            Write-Host "Copying VirtIO drivers..."
            Microwin-CopyVirtIO
        }

        Write-Host "Remove Features from the image"
        Microwin-RemoveFeatures -UseCmdlets $true
        Write-Host "Removing features complete!"
        Write-Host "Removing OS packages"
        Microwin-RemovePackages -UseCmdlets $true
        Write-Host "Removing Appx Bloat"
        Microwin-RemoveProvisionedPackages -UseCmdlets $true

        # Detect Windows 11 24H2 and add dependency to FileExp to prevent Explorer look from going back - thanks @WitherOrNot and @thecatontheceiling
        if ((Microwin-TestCompatibleImage $imgVersion $([System.Version]::new(10,0,26100,1))) -eq $true) {
            try {
                if (Test-Path "$scratchDir\Windows\SystemApps\MicrosoftWindows.Client.FileExp_cw5n1h2txyewy\appxmanifest.xml" -PathType Leaf) {
                    # Found the culprit. Do the following:
                    # 1. Take ownership of the file, from TrustedInstaller to Administrators
                    takeown /F "$scratchDir\Windows\SystemApps\MicrosoftWindows.Client.FileExp_cw5n1h2txyewy\appxmanifest.xml" /A
                    # 2. Set ACLs so that we can write to it
                    icacls "$scratchDir\Windows\SystemApps\MicrosoftWindows.Client.FileExp_cw5n1h2txyewy\appxmanifest.xml" /grant "$(Microwin-GetLocalizedUsers -admins $true):(M)" | Out-Host
                    # 3. Open the file and do the modification
                    $appxManifest = Get-Content -Path "$scratchDir\Windows\SystemApps\MicrosoftWindows.Client.FileExp_cw5n1h2txyewy\appxmanifest.xml"
                    $originalLine = $appxManifest[13]
                    $dependency = "`n        <PackageDependency Name=`"Microsoft.WindowsAppRuntime.CBS`" MinVersion=`"1.0.0.0`" Publisher=`"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US`" />"
                    $appxManifest[13] = "$originalLine$dependency"
                    Set-Content -Path "$scratchDir\Windows\SystemApps\MicrosoftWindows.Client.FileExp_cw5n1h2txyewy\appxmanifest.xml" -Value $appxManifest -Force -Encoding utf8
                }
            }
            catch {
                # Do nothing
            }
        }

        Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\System32\LogFiles\WMI\RtBackup" -Directory
        Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\DiagTrack" -Directory
        Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\InboxApps" -Directory
        Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\System32\LocationNotificationWindows.exe"
        Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files (x86)\Windows Media Player" -Directory
        Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files\Windows Media Player" -Directory
        Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files (x86)\Windows Mail" -Directory
        Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files\Windows Mail" -Directory
        Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files (x86)\Internet Explorer" -Directory
        Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files\Internet Explorer" -Directory
        Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\GameBarPresenceWriter"
        Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\System32\OneDriveSetup.exe"
        Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\System32\OneDrive.ico"
        Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\SystemApps" -mask "*narratorquickstart*" -Directory
        Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\SystemApps" -mask "*ParentalControls*" -Directory
        Write-Host "Removal complete!"

        Write-Host "Create unattend.xml"

        if ($sync.MicrowinUserName.Text -eq "")
        {
            Microwin-NewUnattend -userName "User"
        }
        else
        {
            if ($sync.MicrowinUserPassword.Password -eq "")
            {
                Microwin-NewUnattend -userName "$($sync.MicrowinUserName.Text)"
            }
            else
            {
                Microwin-NewUnattend -userName "$($sync.MicrowinUserName.Text)" -userPassword "$($sync.MicrowinUserPassword.Password)"
            }
        }
        Write-Host "Done Create unattend.xml"
        Write-Host "Copy unattend.xml file into the ISO"
        New-Item -ItemType Directory -Force -Path "$($scratchDir)\Windows\Panther"
        Copy-Item "$env:temp\unattend.xml" "$($scratchDir)\Windows\Panther\unattend.xml" -force
        New-Item -ItemType Directory -Force -Path "$($scratchDir)\Windows\System32\Sysprep"
        Copy-Item "$env:temp\unattend.xml" "$($scratchDir)\Windows\System32\Sysprep\unattend.xml" -force
        Copy-Item "$env:temp\unattend.xml" "$($scratchDir)\unattend.xml" -force
        Write-Host "Done Copy unattend.xml"

        Write-Host "Create FirstRun"
        Microwin-NewFirstRun
        Write-Host "Done create FirstRun"
        Write-Host "Copy FirstRun.ps1 into the ISO"
        Copy-Item "$env:temp\FirstStartup.ps1" "$($scratchDir)\Windows\FirstStartup.ps1" -force
        Write-Host "Done copy FirstRun.ps1"

        Write-Host "Copy link to winutil.ps1 into the ISO"
        $desktopDir = "$($scratchDir)\Windows\Users\Default\Desktop"
        New-Item -ItemType Directory -Force -Path "$desktopDir"
        dism /English /image:$($scratchDir) /set-profilepath:"$($scratchDir)\Windows\Users\Default"

        Write-Host "Copy checkinstall.cmd into the ISO"
        Microwin-NewCheckInstall
        Copy-Item "$env:temp\checkinstall.cmd" "$($scratchDir)\Windows\checkinstall.cmd" -force
        Write-Host "Done copy checkinstall.cmd"

        Write-Host "Creating a directory that allows to bypass Wifi setup"
        New-Item -ItemType Directory -Force -Path "$($scratchDir)\Windows\System32\OOBE\BYPASSNRO"

        Write-Host "Loading registry"
        reg load HKLM\zCOMPONENTS "$($scratchDir)\Windows\System32\config\COMPONENTS"
        reg load HKLM\zDEFAULT "$($scratchDir)\Windows\System32\config\default"
        reg load HKLM\zNTUSER "$($scratchDir)\Users\Default\ntuser.dat"
        reg load HKLM\zSOFTWARE "$($scratchDir)\Windows\System32\config\SOFTWARE"
        reg load HKLM\zSYSTEM "$($scratchDir)\Windows\System32\config\SYSTEM"

        Write-Host "Disabling Teams"
        reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall" /t REG_DWORD /d 0 /f   >$null 2>&1
        reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v ChatIcon /t REG_DWORD /d 2 /f                             >$null 2>&1
        reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d 0 /f        >$null 2>&1
        reg query "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall"                      >$null 2>&1
        # Write-Host Error code $LASTEXITCODE
        Write-Host "Done disabling Teams"

        Write-Host "Fix Windows Volume Mixer Issue"
        reg add "HKLM\zNTUSER\Software\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore" /f

        Write-Host "Bypassing system requirements (system image)"
        reg add "HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d 0 /f
        reg add "HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d 0 /f
        reg add "HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d 0 /f
        reg add "HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d 0 /f
        reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassCPUCheck" /t REG_DWORD /d 1 /f
        reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d 1 /f
        reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d 1 /f
        reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassStorageCheck" /t REG_DWORD /d 1 /f
        reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d 1 /f
        reg add "HKLM\zSYSTEM\Setup\MoSetup" /v "AllowUpgradesWithUnsupportedTPMOrCPU" /t REG_DWORD /d 1 /f

        # Prevent Windows Update Installing so called Expedited Apps - 24H2 and newer
        if ((Microwin-TestCompatibleImage $imgVersion $([System.Version]::new(10,0,26100,1))) -eq $true) {
            @(
                'EdgeUpdate',
                'DevHomeUpdate',
                'OutlookUpdate',
                'CrossDeviceUpdate'
            ) | ForEach-Object {
                Write-Host "Removing Windows Expedited App: $_"

                # Copied here After Installation (Online)
                # reg delete "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\$_" /f | Out-Null

                # When in Offline Image
                reg delete "HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\$_" /f | Out-Null
            }
        }

        reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
        Write-Host "Setting all services to start manually"
        reg add "HKLM\zSOFTWARE\CurrentControlSet\Services" /v Start /t REG_DWORD /d 3 /f
        # Write-Host $LASTEXITCODE

        Write-Host "Enabling Local Accounts on OOBE"
        reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "BypassNRO" /t REG_DWORD /d "1" /f

        Write-Host "Disabling Sponsored Apps"
        reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
        reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
        reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
        reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f
        reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "ConfigureStartPins" /t REG_SZ /d '{\"pinnedList\": [{}]}' /f
        Write-Host "Done removing Sponsored Apps"

        Write-Host "Disabling Reserved Storage"
        reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d 0 /f

        Write-Host "Changing theme to dark. This only works on Activated Windows"
        reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f
        reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f

        if ((Microwin-TestCompatibleImage $imgVersion $([System.Version]::new(10,0,21996,1))) -eq $false) {
            # We're dealing with Windows 10. Configure sane desktop settings. NOTE: even though stuff to disable News and Interests is there,
            # it doesn't seem to work, and I don't want to waste more time dealing with an operating system that will lose support in a year (2025)

            # I invite anyone to work on improving stuff for News and Interests, but that won't be me!

            Write-Host "Disabling Search Highlights..."
            reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds\DSB" /v "ShowDynamicContent" /t REG_DWORD /d 0 /f
            reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t REG_DWORD /d 0 /f
            reg add "HKLM\zSOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d 0 /f
            reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "TraySearchBoxVisible" /t REG_DWORD /d 1 /f
        }

    } catch {
        Write-Error "An unexpected error occurred: $_"
    } finally {
        Write-Host "Unmounting Registry..."
        reg unload HKLM\zCOMPONENTS
        reg unload HKLM\zDEFAULT
        reg unload HKLM\zNTUSER
        reg unload HKLM\zSOFTWARE
        reg unload HKLM\zSYSTEM

        Write-Host "Cleaning up image..."
        dism /English /image:$scratchDir /Cleanup-Image /StartComponentCleanup /ResetBase
        Write-Host "Cleanup complete."

        Write-Host "Unmounting image..."
        Dismount-WindowsImage -Path "$scratchDir" -Save
    }

    try {

        Write-Host "Exporting image into $mountDir\sources\install2.wim"
        Export-WindowsImage -SourceImagePath "$mountDir\sources\install.wim" -SourceIndex $index -DestinationImagePath "$mountDir\sources\install2.wim" -CompressionType "Max"
        Write-Host "Remove old '$mountDir\sources\install.wim' and rename $mountDir\sources\install2.wim"
        Remove-Item "$mountDir\sources\install.wim"
        Rename-Item "$mountDir\sources\install2.wim" "$mountDir\sources\install.wim"

        if (-not (Test-Path -Path "$mountDir\sources\install.wim")) {
            Write-Error "Something went wrong and '$mountDir\sources\install.wim' doesn't exist. Please report this bug to the devs"
            Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
            return
        }
        Write-Host "Windows image completed. Continuing with boot.wim."

        # Next step boot image
        Write-Host "Mounting boot image $mountDir\sources\boot.wim into $scratchDir"
        Mount-WindowsImage -ImagePath "$mountDir\sources\boot.wim" -Index 2 -Path "$scratchDir"

        if ($injectDrivers) {
            $driverPath = $sync.MicrowinDriverLocation.Text
            if (Test-Path $driverPath) {
                Write-Host "Adding Windows Drivers image($scratchDir) drivers($driverPath) "
                dism /English /image:$scratchDir /add-driver /driver:$driverPath /recurse | Out-Host
            } else {
                Write-Host "Path to drivers is invalid continuing without driver injection"
            }
        }

        Write-Host "Loading registry..."
        reg load HKLM\zCOMPONENTS "$($scratchDir)\Windows\System32\config\COMPONENTS" >$null
        reg load HKLM\zDEFAULT "$($scratchDir)\Windows\System32\config\default" >$null
        reg load HKLM\zNTUSER "$($scratchDir)\Users\Default\ntuser.dat" >$null
        reg load HKLM\zSOFTWARE "$($scratchDir)\Windows\System32\config\SOFTWARE" >$null
        reg load HKLM\zSYSTEM "$($scratchDir)\Windows\System32\config\SYSTEM" >$null
        Write-Host "Bypassing system requirements on the setup image"
        reg add "HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d 0 /f
        reg add "HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d 0 /f
        reg add "HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d 0 /f
        reg add "HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d 0 /f
        reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassCPUCheck" /t REG_DWORD /d 1 /f
        reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d 1 /f
        reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d 1 /f
        reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassStorageCheck" /t REG_DWORD /d 1 /f
        reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d 1 /f
        reg add "HKLM\zSYSTEM\Setup\MoSetup" /v "AllowUpgradesWithUnsupportedTPMOrCPU" /t REG_DWORD /d 1 /f
        # Fix Computer Restarted Unexpectedly Error on New Bare Metal Install
        reg add "HKLM\zSYSTEM\Setup\Status\ChildCompletion" /v "setup.exe" /t REG_DWORD /d 3 /f
    } catch {
        Write-Error "An unexpected error occurred: $_"
    } finally {
        Write-Host "Unmounting Registry..."
        reg unload HKLM\zCOMPONENTS
        reg unload HKLM\zDEFAULT
        reg unload HKLM\zNTUSER
        reg unload HKLM\zSOFTWARE
        reg unload HKLM\zSYSTEM

        Write-Host "Unmounting image..."
        Dismount-WindowsImage -Path "$scratchDir" -Save

        Write-Host "Creating ISO image"

        # if we downloaded oscdimg from github it will be in the temp directory so use it
        # if it is not in temp it is part of ADK and is in global PATH so just set it to oscdimg.exe
        $oscdimgPath = Join-Path $env:TEMP 'oscdimg.exe'
        $oscdImgFound = Test-Path $oscdimgPath -PathType Leaf
        if (!$oscdImgFound) {
            $oscdimgPath = "oscdimg.exe"
        }

        Write-Host "[INFO] Using oscdimg.exe from: $oscdimgPath"

        $oscdimgProc = Start-Process -FilePath "$oscdimgPath" -ArgumentList "-m -o -u2 -udfver102 -bootdata:2#p0,e,b`"$mountDir\boot\etfsboot.com`"#pEF,e,b`"$mountDir\efi\microsoft\boot\efisys.bin`" `"$mountDir`" `"$($SaveDialog.FileName)`"" -Wait -PassThru -NoNewWindow

        $LASTEXITCODE = $oscdimgProc.ExitCode

        Write-Host "OSCDIMG Error Level : $($oscdimgProc.ExitCode)"

        if ($copyToUSB) {
            Write-Host "Copying target ISO to the USB drive"
            Microwin-CopyToUSB("$($SaveDialog.FileName)")
            if ($?) { Write-Host "Done Copying target ISO to USB drive!" } else { Write-Host "ISO copy failed." }
        }

        Write-Host " _____                       "
        Write-Host "(____ \                      "
        Write-Host " _   \ \ ___  ____   ____    "
        Write-Host "| |   | / _ \|  _ \ / _  )   "
        Write-Host "| |__/ / |_| | | | ( (/ /    "
        Write-Host "|_____/ \___/|_| |_|\____)   "

        # Check if the ISO was successfully created - CTT edit
        if ($LASTEXITCODE -eq 0) {
            Write-Host "`n`nPerforming Cleanup..."
                Remove-Item -Recurse -Force "$($scratchDir)"
                Remove-Item -Recurse -Force "$($mountDir)"
            $msg = "Done. ISO image is located here: $($SaveDialog.FileName)"
            Write-Host $msg
            Set-WinUtilTaskbaritem -state "None" -overlay "checkmark"
            [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        } else {
            Write-Host "ISO creation failed. The "$($mountDir)" directory has not been removed."
            try {
                # This creates a new Win32 exception from which we can extract a message in the system language.
                # Now, this will NOT throw an exception
                $exitCode = New-Object System.ComponentModel.Win32Exception($LASTEXITCODE)
                Write-Host "Reason: $($exitCode.Message)"
            } catch {
                # Could not get error description from Windows APIs
            }
        }

        $sync.MicrowinOptionsPanel.Visibility = 'Collapsed'

        #$sync.MicrowinFinalIsoLocation.Text = "$env:temp\microwin.iso"
        $sync.MicrowinFinalIsoLocation.Text = "$($SaveDialog.FileName)"
        # Allow the machine to sleep again (optional)
        [PowerManagement]::SetThreadExecutionState(0)
        $sync.ProcessRunning = $false
    }
}
function Invoke-MicrowinGetIso {
    <#
    .DESCRIPTION
    Function to get the path to Iso file for MicroWin, unpack that isom=, read basic information and populate the UI Options
    #>

    Write-Host "Invoking WPFGetIso"

    if($sync.ProcessRunning) {
        $msg = "GetIso process is currently running."
        [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $sync.BusyMessage.Visibility="Visible"
    $sync.BusyText.Text="N Busy"



    Write-Host "         _                     __    __  _         "
    Write-Host "  /\/\  (_)  ___  _ __   ___  / / /\ \ \(_) _ __   "
    Write-Host " /    \ | | / __|| '__| / _ \ \ \/  \/ /| || '_ \  "
    Write-Host "/ /\/\ \| || (__ | |   | (_) | \  /\  / | || | | | "
    Write-Host "\/    \/|_| \___||_|    \___/   \/  \/  |_||_| |_| "

    $oscdimgPath = Join-Path $env:TEMP 'oscdimg.exe'
    $oscdImgFound = [bool] (Get-Command -ErrorAction Ignore -Type Application oscdimg.exe) -or (Test-Path $oscdimgPath -PathType Leaf)
    Write-Host "oscdimg.exe on system: $oscdImgFound"

    if (!$oscdImgFound) {
        $downloadFromGitHub = $sync.WPFMicrowinDownloadFromGitHub.IsChecked
        $sync.BusyMessage.Visibility="Hidden"

        if (!$downloadFromGitHub) {
            # only show the message to people who did check the box to download from github, if you check the box
            # you consent to downloading it, no need to show extra dialogs
            [System.Windows.MessageBox]::Show("oscdimge.exe is not found on the system, winutil will now attempt do download and install it using choco. This might take a long time.")
            # the step below needs choco to download oscdimg
            # Install Choco if not already present
            Install-WinUtilChoco
            $chocoFound = [bool] (Get-Command -ErrorAction Ignore -Type Application choco)
            Write-Host "choco on system: $chocoFound"
            if (!$chocoFound) {
                [System.Windows.MessageBox]::Show("choco.exe is not found on the system, you need choco to download oscdimg.exe")
                return
            }

            Start-Process -Verb runas -FilePath powershell.exe -ArgumentList "choco install windows-adk-oscdimg"
            [System.Windows.MessageBox]::Show("oscdimg is installed, now close, reopen PowerShell terminal and re-launch winutil.ps1")
            return
        } else {
            [System.Windows.MessageBox]::Show("oscdimge.exe is not found on the system, winutil will now attempt do download and install it from github. This might take a long time.")
            Microwin-GetOscdimg -oscdimgPath $oscdimgPath
            $oscdImgFound = Test-Path $oscdimgPath -PathType Leaf
            if (!$oscdImgFound) {
                $msg = "oscdimg was not downloaded can not proceed"
                [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                return
            } else {
                Write-Host "oscdimg.exe was successfully downloaded from github"
            }
        }
    }

    if ($sync["ISOmanual"].IsChecked) {
        # Open file dialog to let user choose the ISO file
        [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openFileDialog.initialDirectory = $initialDirectory
        $openFileDialog.filter = "ISO files (*.iso)| *.iso"
        $openFileDialog.ShowDialog() | Out-Null
        $filePath = $openFileDialog.FileName

        if ([string]::IsNullOrEmpty($filePath)) {
            Write-Host "No ISO is chosen"
            $sync.BusyMessage.Visibility="Hidden"
            return
        }
    } elseif ($sync["ISOdownloader"].IsChecked) {
        # Create folder browsers for user-specified locations
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        $isoDownloaderFBD = New-Object System.Windows.Forms.FolderBrowserDialog
        $isoDownloaderFBD.Description = "Please specify the path to download the ISO file to:"
        $isoDownloaderFBD.ShowNewFolderButton = $true
        if ($isoDownloaderFBD.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK)
        {
            return
        }

        # Grab the location of the selected path
        $targetFolder = $isoDownloaderFBD.SelectedPath

        # Auto download newest ISO
        # Credit: https://github.com/pbatard/Fido
        $fidopath = "$env:temp\Fido.ps1"
        $originalLocation = $PSScriptRoot

        Invoke-WebRequest "https://github.com/pbatard/Fido/raw/master/Fido.ps1" -OutFile $fidopath

        Set-Location -Path $env:temp
        # Detect if the first option ("System language") has been selected and get a Fido-approved language from the current culture
        $lang = if ($sync["ISOLanguage"].SelectedIndex -eq 0) {
            Microwin-GetLangFromCulture -langName (Get-Culture).Name
        } else {
            $sync["ISOLanguage"].SelectedItem
        }

        & $fidopath -Win 'Windows 11' -Rel $sync["ISORelease"].SelectedItem -Arch "x64" -Lang $lang -Ed "Windows 11 Home/Pro/Edu"
        if (-not $?)
        {
            Write-Host "Could not download the ISO file. Look at the output of the console for more information."
            $msg = "The ISO file could not be downloaded"
            [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            return
        }
        Set-Location $originalLocation
        # Use the FullName property to only grab the file names. Using this property is necessary as, without it, you're passing the usual output of Get-ChildItem
        # to the variable, and let's be honest, that does NOT exist in the file system
        $filePath = (Get-ChildItem -Path "$env:temp" -Filter "Win11*.iso").FullName | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $fileName = [IO.Path]::GetFileName("$filePath")

        if (($targetFolder -ne "") -and (Test-Path "$targetFolder"))
        {
            try
            {
                # "Let it download to $env:TEMP and then we **move** it to the file path." - CodingWonders
                $destinationFilePath = "$targetFolder\$fileName"
                Write-Host "Moving ISO file. Please wait..."
                Move-Item -Path "$filePath" -Destination "$destinationFilePath" -Force
                $filePath = $destinationFilePath
            }
            catch
            {
                Write-Host "Unable to move the ISO file to the location you specified. The downloaded ISO is in the `"$env:TEMP`" folder"
                Write-Host "Error information: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }

    Write-Host "File path $($filePath)"
    if (-not (Test-Path -Path "$filePath" -PathType Leaf)) {
        $msg = "File you've chosen doesn't exist"
        [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        return
    }

    Set-WinUtilTaskbaritem -state "Indeterminate" -overlay "logo"

    # Detect the file size of the ISO and compare it with the free space of the system drive
    $isoSize = (Get-Item -Path "$filePath").Length
    Write-Debug "Size of ISO file: $($isoSize) bytes"
    # Use this procedure to get the free space of the drive depending on where the user profile folder is stored.
    # This is done to guarantee a dynamic solution, as the installation drive may be mounted to a letter different than C
    $driveSpace = (Get-Volume -DriveLetter ([IO.Path]::GetPathRoot([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)).Replace(":\", "").Trim())).SizeRemaining
    Write-Debug "Free space on installation drive: $($driveSpace) bytes"
    if ($driveSpace -lt ($isoSize * 2)) {
        # It's not critical and we _may_ continue. Output a warning
        Write-Warning "You may not have enough space for this operation. Proceed at your own risk."
    }
    elseif ($driveSpace -lt $isoSize) {
        # It's critical and we can't continue. Output an error
        Write-Host "You don't have enough space for this operation. You need at least $([Math]::Round(($isoSize / ([Math]::Pow(1024, 2))) * 2, 2)) MB of free space to copy the ISO files to a temp directory and to be able to perform additional operations."
        Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
        return
    } else {
        Write-Host "You have enough space for this operation."
    }

    try {
        Write-Host "Mounting Iso. Please wait."
        $mountedISO = Mount-DiskImage -PassThru "$filePath"
        Write-Host "Done mounting Iso `"$($mountedISO.ImagePath)`""
        $driveLetter = (Get-Volume -DiskImage $mountedISO).DriveLetter
        Write-Host "Iso mounted to '$driveLetter'"
    } catch {
        # @tut-os  please copy this wiki and change the link below to your copy of the wiki
        Write-Error "Failed to mount the image. Error: $($_.Exception.Message)"
        Write-Error "This is NOT winutil's problem, your ISO might be corrupt, or there is a problem on the system"
        Write-Host "Please refer to this wiki for more details: https://tut-os.github.io/winutil/KnownIssues/#troubleshoot-errors-during-microwin-usage" -ForegroundColor Red
        Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
        return
    }
    # storing off values in hidden fields for further steps
    # there is probably a better way of doing this, I don't have time to figure this out
    $sync.MicrowinIsoDrive.Text = $driveLetter

    $mountedISOPath = (Split-Path -Path "$filePath")
     if ($sync.MicrowinScratchDirBox.Text.Trim() -eq "Scratch") {
        $sync.MicrowinScratchDirBox.Text =""
    }

    $UseISOScratchDir = $sync.WPFMicrowinISOScratchDir.IsChecked

    if ($UseISOScratchDir) {
        $sync.MicrowinScratchDirBox.Text=$mountedISOPath
    }

    if( -Not $sync.MicrowinScratchDirBox.Text.EndsWith('\') -And  $sync.MicrowinScratchDirBox.Text.Length -gt 1) {

         $sync.MicrowinScratchDirBox.Text = Join-Path   $sync.MicrowinScratchDirBox.Text.Trim() '\'

    }

    # Detect if the folders already exist and remove them
    if (($sync.MicrowinMountDir.Text -ne "") -and (Test-Path -Path $sync.MicrowinMountDir.Text)) {
        try {
            Write-Host "Deleting temporary files from previous run. Please wait..."
            Remove-Item -Path $sync.MicrowinMountDir.Text -Recurse -Force
            Remove-Item -Path $sync.MicrowinScratchDir.Text -Recurse -Force
        } catch {
            Write-Host "Could not delete temporary files. You need to delete those manually."
        }
    }

    Write-Host "Setting up mount dir and scratch dirs"
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $randomNumber = Get-Random -Minimum 1 -Maximum 9999
    $randomMicrowin = "Microwin_${timestamp}_${randomNumber}"
    $randomMicrowinScratch = "MicrowinScratch_${timestamp}_${randomNumber}"
    $sync.BusyText.Text=" - Mounting"
    Write-Host "Mounting Iso. Please wait."
    if ($sync.MicrowinScratchDirBox.Text -eq "") {
        $mountDir = Join-Path $env:TEMP $randomMicrowin
        $scratchDir = Join-Path $env:TEMP $randomMicrowinScratch
    } else {
        $scratchDir = $sync.MicrowinScratchDirBox.Text+"Scratch"
        $mountDir = $sync.MicrowinScratchDirBox.Text+"micro"
    }

    $sync.MicrowinMountDir.Text = $mountDir
    $sync.MicrowinScratchDir.Text = $scratchDir
    Write-Host "Done setting up mount dir and scratch dirs"
    Write-Host "Scratch dir is $scratchDir"
    Write-Host "Image dir is $mountDir"

    try {

        #$data = @($driveLetter, $filePath)
        New-Item -ItemType Directory -Force -Path "$($mountDir)" | Out-Null
        New-Item -ItemType Directory -Force -Path "$($scratchDir)" | Out-Null
        Write-Host "Copying Windows image. This will take awhile, please don't use UI or cancel this step!"

        # xcopy we can verify files and also not copy files that already exist, but hard to measure
        # xcopy.exe /E /I /H /R /Y /J $DriveLetter":" $mountDir >$null
        $totalTime = Measure-Command { Copy-Files "$($driveLetter):" "$mountDir" -Recurse -Force }
        Write-Host "Copy complete! Total Time: $($totalTime.Minutes) minutes, $($totalTime.Seconds) seconds"

        $wimFile = "$mountDir\sources\install.wim"
        Write-Host "Getting image information $wimFile"

        if ((-not (Test-Path -Path "$wimFile" -PathType Leaf)) -and (-not (Test-Path -Path "$($wimFile.Replace(".wim", ".esd").Trim())" -PathType Leaf))) {
            $msg = "Neither install.wim nor install.esd exist in the image, this could happen if you use unofficial Windows images. Please don't use shady images from the internet, use only official images. Here are instructions how to download ISO images if the Microsoft website is not showing the link to download and ISO. https://www.techrepublic.com/article/how-to-download-a-windows-10-iso-file-without-using-the-media-creation-tool/"
            Write-Host $msg
            [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
            throw
        }
        elseif ((-not (Test-Path -Path $wimFile -PathType Leaf)) -and (Test-Path -Path $wimFile.Replace(".wim", ".esd").Trim() -PathType Leaf)) {
            Write-Host "Install.esd found on the image. It needs to be converted to a WIM file in order to begin processing"
            $wimFile = $wimFile.Replace(".wim", ".esd").Trim()
        }
        $sync.MicrowinWindowsFlavors.Items.Clear()
        Get-WindowsImage -ImagePath $wimFile | ForEach-Object {
            $imageIdx = $_.ImageIndex
            $imageName = $_.ImageName
            $sync.MicrowinWindowsFlavors.Items.Add("$imageIdx : $imageName")
        }
        $sync.MicrowinWindowsFlavors.SelectedIndex = 0
        Write-Host "Finding suitable Pro edition. This can take some time. Do note that this is an automatic process that might not select the edition you want."
        Get-WindowsImage -ImagePath $wimFile | ForEach-Object {
            if ((Get-WindowsImage -ImagePath $wimFile -Index $_.ImageIndex).EditionId -eq "Professional") {
                # We have found the Pro edition
                $sync.MicrowinWindowsFlavors.SelectedIndex = $_.ImageIndex - 1
            }
        }
        Get-Volume $driveLetter | Get-DiskImage | Dismount-DiskImage
        Write-Host "Selected value '$($sync.MicrowinWindowsFlavors.SelectedValue)'....."

        $sync.MicrowinOptionsPanel.Visibility = 'Visible'
    } catch {
        Write-Host "Dismounting bad image..."
        Get-Volume $driveLetter | Get-DiskImage | Dismount-DiskImage
        Remove-Item -Recurse -Force "$($scratchDir)"
        Remove-Item -Recurse -Force "$($mountDir)"
    }

    Write-Host "Done reading and unpacking ISO"
    Write-Host ""
    Write-Host "*********************************"
    Write-Host "Check the UI for further steps!!!"

    $sync.BusyMessage.Visibility="Hidden"
    $sync.ProcessRunning = $false
    Set-WinUtilTaskbaritem -state "None" -overlay "checkmark"
}
class ErroredPackage {
    [string]$PackageName
    [string]$ErrorMessage
    ErroredPackage() { $this.Init(@{} )}
    # Constructor for packages that have errored out
    ErroredPackage([string]$pkgName, [string]$reason) {
        $this.PackageName = $pkgName
        $this.ErrorMessage = $reason
    }
}
function Microwin-CopyToUSB([string]$fileToCopy) {
    foreach ($volume in Get-Volume) {
        if ($volume -and $volume.FileSystemLabel -ieq "ventoy") {
            $destinationPath = "$($volume.DriveLetter):\"
            #Copy-Item -Path $fileToCopy -Destination $destinationPath -Force
            # Get the total size of the file
            $totalSize = (Get-Item "$fileToCopy").length

            Copy-Item -Path "$fileToCopy" -Destination "$destinationPath" -Verbose -Force -Recurse -Container -PassThru |
                ForEach-Object {
                    # Calculate the percentage completed
                    $completed = ($_.BytesTransferred / $totalSize) * 100

                    # Display the progress bar
                    Write-Progress -Activity "Copying File" -Status "Progress" -PercentComplete $completed -CurrentOperation ("{0:N2} MB / {1:N2} MB" -f ($_.BytesTransferred / 1MB), ($totalSize / 1MB))
                }

            Write-Host "File copied to Ventoy drive $($volume.DriveLetter)"

            # Detect if config files are present, move them if they are, and configure the Ventoy drive to not bypass the requirements
            $customVentoyConfig = @'
{
    "control":[
        { "VTOY_WIN11_BYPASS_CHECK": "0" },
        { "VTOY_WIN11_BYPASS_NRO": "0" }
    ],
    "control_legacy":[
        { "VTOY_WIN11_BYPASS_CHECK": "0" },
        { "VTOY_WIN11_BYPASS_NRO": "0" }
    ],
    "control_uefi":[
        { "VTOY_WIN11_BYPASS_CHECK": "0" },
        { "VTOY_WIN11_BYPASS_NRO": "0" }
    ],
    "control_ia32":[
        { "VTOY_WIN11_BYPASS_CHECK": "0" },
        { "VTOY_WIN11_BYPASS_NRO": "0" }
    ],
    "control_aa64":[
        { "VTOY_WIN11_BYPASS_CHECK": "0" },
        { "VTOY_WIN11_BYPASS_NRO": "0" }
    ],
    "control_mips":[
        { "VTOY_WIN11_BYPASS_CHECK": "0" },
        { "VTOY_WIN11_BYPASS_NRO": "0" }
    ]
}
'@

            try {
                Write-Host "Writing custom Ventoy configuration. Please wait..."
                if (Test-Path -Path "$($volume.DriveLetter):\ventoy\ventoy.json" -PathType Leaf) {
                    Write-Host "A Ventoy configuration file exists. Moving it..."
                    Move-Item -Path "$($volume.DriveLetter):\ventoy\ventoy.json" -Destination "$($volume.DriveLetter):\ventoy\ventoy.json.old" -Force
                    Write-Host "Existing Ventoy configuration has been moved to `"ventoy.json.old`". Feel free to put your config back into the `"ventoy.json`" file."
                }
                if (-not (Test-Path -Path "$($volume.DriveLetter):\ventoy")) {
                    New-Item -Path "$($volume.DriveLetter):\ventoy" -ItemType Directory -Force | Out-Null
                }
                $customVentoyConfig | Out-File -FilePath "$($volume.DriveLetter):\ventoy\ventoy.json" -Encoding utf8 -Force
                Write-Host "The Ventoy drive has been successfully configured."
            } catch {
                Write-Host "Could not configure Ventoy drive. Error: $($_.Exception.Message)`n"
                Write-Host "Be sure to add the following configuration to the Ventoy drive by either creating a `"ventoy.json`" file in the `"ventoy`" directory (create it if it doesn't exist) or by editing an existing one: `n`n$customVentoyConfig`n"
                Write-Host "Failure to do this will cause conflicts with your target ISO file."
            }
            return
        }
    }
    Write-Host "Ventoy USB Key is not inserted"
}
function Microwin-CopyVirtIO {
    <#
        .SYNOPSIS
            Downloads and copies the VirtIO Guest Tools drivers to the target MicroWin ISO
        .NOTES
            A network connection must be available and the servers of Fedora People must be up. Automatic driver installation will not be added yet - I want this implementation to be reliable.
    #>

    try {
        Write-Host "Checking existing files..."
        if (Test-Path -Path "$($env:TEMP)\virtio.iso" -PathType Leaf) {
            Write-Host "VirtIO ISO has been detected. Deleting..."
            Remove-Item -Path "$($env:TEMP)\virtio.iso" -Force
        }
        Write-Host "Getting latest VirtIO drivers. Please wait. This can take some time, depending on your network connection speed and the speed of the servers..."
        Start-BitsTransfer -Source "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso" -Destination "$($env:TEMP)\virtio.iso" -DisplayName "Downloading VirtIO drivers..."
        # Do everything else if the VirtIO ISO exists
        if (Test-Path -Path "$($env:TEMP)\virtio.iso" -PathType Leaf) {
            Write-Host "Mounting ISO. Please wait."
            $virtIO_ISO = Mount-DiskImage -PassThru "$($env:TEMP)\virtio.iso"
            $driveLetter = (Get-Volume -DiskImage $virtIO_ISO).DriveLetter
            # Create new directory for VirtIO on ISO
            New-Item -Path "$mountDir\VirtIO" -ItemType Directory | Out-Null
            $totalTime = Measure-Command { Copy-Files "$($driveLetter):" "$mountDir\VirtIO" -Recurse -Force }
            Write-Host "VirtIO contents have been successfully copied. Time taken: $($totalTime.Minutes) minutes, $($totalTime.Seconds) seconds`n"
            Get-Volume $driveLetter | Get-DiskImage | Dismount-DiskImage
            Remove-Item -Path "$($env:TEMP)\virtio.iso" -Force -ErrorAction SilentlyContinue
            Write-Host "To proceed with installation of the MicroWin image in QEMU/Proxmox VE:"
            Write-Host "1. Proceed with Setup until you reach the disk selection screen, in which you won't see any drives"
            Write-Host "2. Click `"Load Driver`" and click Browse"
            Write-Host "3. In the folder selection dialog, point to this path:`n`n    `"D:\VirtIO\vioscsi\w11\amd64`" (replace amd64 with ARM64 if you are using Windows on ARM, and `"D:`" with the drive letter of the ISO)`n"
            Write-Host "4. Select all drivers that will appear in the list box and click OK"
        } else {
            throw "Could not download VirtIO drivers"
        }
    } catch {
        Write-Host "We could not download and/or prepare the VirtIO drivers. Error information: $_`n"
        Write-Host "You will need to download these drivers manually. Location: https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
    }
}
function Microwin-GetLangFromCulture {

    param (
        [Parameter(Mandatory, Position = 0)] [string]$langName
    )

    switch -Wildcard ($langName)
    {
        "ar*" { return "Arabic" }
        "pt-BR" { return "Brazilian Portuguese" }
        "bg*" { return "Bulgarian" }
        {($_ -eq "zh-CH") -or ($_ -like "zh-Hans*") -or ($_ -eq "zh-SG") -or ($_ -eq "zh-CHS")} { return "Chinese (Simplified)" }
        {($_ -eq "zh") -or ($_ -eq "zh-Hant") -or ($_ -eq "zh-HK") -or ($_ -eq "zh-MO") -or ($_ -eq "zh-TW") -or ($_ -eq "zh-CHT")} { return "Chinese (Traditional)" }
        "hr*" { return "Croatian" }
        "cs*" { return "Czech" }
        "da*" { return "Danish" }
        "nl*" { return "Dutch" }
        "en-US" { return "English" }
        {($_ -like "en*") -and ($_ -ne "en-US")} { return "English International" }
        "et*" { return "Estonian" }
        "fi*" { return "Finnish" }
        {($_ -like "fr*") -and ($_ -ne "fr-CA")} { return "French" }
        "fr-CA" { return "French Canadian" }
        "de*" { return "German" }
        "el*" { return "Greek" }
        "he*" { return "Hebrew" }
        "hu*" { return "Hungarian" }
        "it*" { return "Italian" }
        "ja*" { return "Japanese" }
        "ko*" { return "Korean" }
        "lv*" { return "Latvian" }
        "lt*" { return "Lituanian" }
        "nb*" { return "Norwegian" }
        "pl*" { return "Polish" }
        {($_ -like "pt*") -and ($_ -ne "pt-BR")} { return "Portuguese" }
        "ro*" { return "Romanian" }
        "ru*" { return "Russian" }
        "sr-Latn*" { return "Serbian Latin" }
        "sk*" { return "Slovak" }
        "sl*" { return "Slovenian" }
        {($_ -like "es*") -and ($_ -ne "es-MX")} { return "Spanish" }
        "es-MX" { return "Spanish (Mexico)" }
        "sv*" { return "Swedish" }
        "th*" { return "Thai" }
        "tr*" { return "Turkish" }
        "uk*" { return "Ukrainian" }
        default { return "English" }
    }
}
function Microwin-GetLocalizedUsers
{
    <#
        .SYNOPSIS
            Gets a localized user group representation for ICACLS commands (Port from DISMTools PE Helper)
        .PARAMETER admins
            Determines whether to get a localized user group representation for the Administrators user group
        .OUTPUTS
            A string containing the localized user group
        .EXAMPLE
            Microwin-GetLocalizedUsers -admins $true
    #>
    param (
        [Parameter(Mandatory = $true, Position = 0)] [bool]$admins
    )
    if ($admins) {
        return (Get-LocalGroup | Where-Object { $_.SID.Value -like "S-1-5-32-544" }).Name
    } else {
        return (Get-LocalGroup | Where-Object { $_.SID.Value -like "S-1-5-32-545" }).Name
    }
}
function Microwin-GetOscdimg {
    <#
        .DESCRIPTION
        This function will download oscdimg file from github Release folders and put it into env:temp folder

        .EXAMPLE
        Microwin-GetOscdimg
    #>

    param(
        [Parameter(Mandatory, position=0)]
        [string]$oscdimgPath
    )

    $oscdimgPath = "$env:TEMP\oscdimg.exe"
    $downloadUrl = "https://github.com/tut-os/winutil/raw/main/releases/oscdimg.exe"
    Invoke-RestMethod -Uri $downloadUrl -OutFile $oscdimgPath
    $hashResult = Get-FileHash -Path $oscdimgPath -Algorithm SHA256
    $sha256Hash = $hashResult.Hash

    Write-Host "[INFO] oscdimg.exe SHA-256 Hash: $sha256Hash"

    $expectedHash = "AB9E161049D293B544961BFDF2D61244ADE79376D6423DF4F60BF9B147D3C78D"  # Replace with the actual expected hash
    if ($sha256Hash -eq $expectedHash) {
        Write-Host "Hashes match. File is verified."
    } else {
        Write-Host "Hashes do not match. File may be corrupted or tampered with."
    }
}
function Microwin-NewCheckInstall {

    # using here string to embedd firstrun
    $checkInstall = @'
    @echo off
    if exist "%HOMEDRIVE%\windows\cpu.txt" (
        echo %HOMEDRIVE%\windows\cpu.txt exists
    ) else (
        echo %HOMEDRIVE%\windows\cpu.txt does not exist
    )
    if exist "%HOMEDRIVE%\windows\SerialNumber.txt" (
        echo %HOMEDRIVE%\windows\SerialNumber.txt exists
    ) else (
        echo %HOMEDRIVE%\windows\SerialNumber.txt does not exist
    )
    if exist "%HOMEDRIVE%\unattend.xml" (
        echo %HOMEDRIVE%\unattend.xml exists
    ) else (
        echo %HOMEDRIVE%\unattend.xml does not exist
    )
    if exist "%HOMEDRIVE%\Windows\Setup\Scripts\SetupComplete.cmd" (
        echo %HOMEDRIVE%\Windows\Setup\Scripts\SetupComplete.cmd exists
    ) else (
        echo %HOMEDRIVE%\Windows\Setup\Scripts\SetupComplete.cmd does not exist
    )
    if exist "%HOMEDRIVE%\Windows\Panther\unattend.xml" (
        echo %HOMEDRIVE%\Windows\Panther\unattend.xml exists
    ) else (
        echo %HOMEDRIVE%\Windows\Panther\unattend.xml does not exist
    )
    if exist "%HOMEDRIVE%\Windows\System32\Sysprep\unattend.xml" (
        echo %HOMEDRIVE%\Windows\System32\Sysprep\unattend.xml exists
    ) else (
        echo %HOMEDRIVE%\Windows\System32\Sysprep\unattend.xml does not exist
    )
    if exist "%HOMEDRIVE%\Windows\FirstStartup.ps1" (
        echo %HOMEDRIVE%\Windows\FirstStartup.ps1 exists
    ) else (
        echo %HOMEDRIVE%\Windows\FirstStartup.ps1 does not exist
    )
    if exist "%HOMEDRIVE%\Windows\winutil.ps1" (
        echo %HOMEDRIVE%\Windows\winutil.ps1 exists
    ) else (
        echo %HOMEDRIVE%\Windows\winutil.ps1 does not exist
    )
    if exist "%HOMEDRIVE%\Windows\LogSpecialize.txt" (
        echo %HOMEDRIVE%\Windows\LogSpecialize.txt exists
    ) else (
        echo %HOMEDRIVE%\Windows\LogSpecialize.txt does not exist
    )
    if exist "%HOMEDRIVE%\Windows\LogAuditUser.txt" (
        echo %HOMEDRIVE%\Windows\LogAuditUser.txt exists
    ) else (
        echo %HOMEDRIVE%\Windows\LogAuditUser.txt does not exist
    )
    if exist "%HOMEDRIVE%\Windows\LogOobeSystem.txt" (
        echo %HOMEDRIVE%\Windows\LogOobeSystem.txt exists
    ) else (
        echo %HOMEDRIVE%\Windows\LogOobeSystem.txt does not exist
    )
    if exist "%HOMEDRIVE%\windows\csup.txt" (
        echo %HOMEDRIVE%\windows\csup.txt exists
    ) else (
        echo %HOMEDRIVE%\windows\csup.txt does not exist
    )
    if exist "%HOMEDRIVE%\windows\LogFirstRun.txt" (
        echo %HOMEDRIVE%\windows\LogFirstRun.txt exists
    ) else (
        echo %HOMEDRIVE%\windows\LogFirstRun.txt does not exist
    )
'@
    $checkInstall | Out-File -FilePath "$env:temp\checkinstall.cmd" -Force -Encoding Ascii
}
function Microwin-NewFirstRun {

    # using here string to embedd firstrun
    $firstRun = @'
    # Set the global error action preference to continue
    $ErrorActionPreference = "Continue"
    function Remove-RegistryValue {
        param (
            [Parameter(Mandatory = $true)]
            [string]$RegistryPath,

            [Parameter(Mandatory = $true)]
            [string]$ValueName
        )

        # Check if the registry path exists
        if (Test-Path -Path $RegistryPath) {
            $registryValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue

            # Check if the registry value exists
            if ($registryValue) {
                # Remove the registry value
                Remove-ItemProperty -Path $RegistryPath -Name $ValueName -Force
                Write-Host "Registry value '$ValueName' removed from '$RegistryPath'."
            } else {
                Write-Host "Registry value '$ValueName' not found in '$RegistryPath'."
            }
        } else {
            Write-Host "Registry path '$RegistryPath' not found."
        }
    }

    "FirstStartup has worked" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber

    $taskbarPath = "$env:AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    # Delete all files on the Taskbar
    Get-ChildItem -Path $taskbarPath -File | Remove-Item -Force
    Remove-RegistryValue -RegistryPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -ValueName "FavoritesRemovedChanges"
    Remove-RegistryValue -RegistryPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -ValueName "FavoritesChanges"
    Remove-RegistryValue -RegistryPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -ValueName "Favorites"

    # Delete Edge Icon from the desktop
    $edgeShortcutFiles = Get-ChildItem -Path $desktopPath -Filter "*Edge*.lnk"
    # Check if Edge shortcuts exist on the desktop
    if ($edgeShortcutFiles) {
        foreach ($shortcutFile in $edgeShortcutFiles) {
            # Remove each Edge shortcut
            Remove-Item -Path $shortcutFile.FullName -Force
            Write-Host "Edge shortcut '$($shortcutFile.Name)' removed from the desktop."
        }
    }
    Remove-Item -Path "$env:USERPROFILE\Desktop\*.lnk"
    Remove-Item -Path "$env:HOMEDRIVE\Users\Default\Desktop\*.lnk"

    try
    {
        if ((Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "Recall" }).Count -gt 0)
        {
            Disable-WindowsOptionalFeature -Online -FeatureName "Recall" -Remove
        }
    }
    catch
    {

    }

    # Get BCD entries and set bootmgr timeout accordingly
    try
    {
        # Check if the number of occurrences of "path" is 2 - this fixes the Boot Manager screen issue (#2562)
        if ((bcdedit | Select-String "path").Count -eq 2)
        {
            # Set bootmgr timeout to 0
            bcdedit /set `{bootmgr`} timeout 0
        }
    }
    catch
    {

    }

'@
    $firstRun | Out-File -FilePath "$env:temp\FirstStartup.ps1" -Force
}
function Microwin-NewUnattend {

    param (
        [Parameter(Mandatory, Position = 0)] [string]$userName,
        [Parameter(Position = 1)] [string]$userPassword
    )

    $unattend = @'
    <?xml version="1.0" encoding="utf-8"?>
    <unattend xmlns="urn:schemas-microsoft-com:unattend"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <#REPLACEME#>
        <settings pass="auditUser">
            <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <RunSynchronous>
                    <RunSynchronousCommand wcm:action="add">
                        <Order>1</Order>
                        <CommandLine>CMD /C echo LAU GG&gt;C:\Windows\LogAuditUser.txt</CommandLine>
                        <Description>StartMenu</Description>
                    </RunSynchronousCommand>
                </RunSynchronous>
            </component>
        </settings>
        <settings pass="oobeSystem">
            <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <UserAccounts>
                    <LocalAccounts>
                        <LocalAccount wcm:action="add">
                            <Name>USER-REPLACEME</Name>
                            <Group>Administrators</Group>
                            <Password>
                                <Value>PW-REPLACEME</Value>
                                <PlainText>PT-STATUS</PlainText>
                            </Password>
                        </LocalAccount>
                    </LocalAccounts>
                </UserAccounts>
                <AutoLogon>
                    <Username>USER-REPLACEME</Username>
                    <Enabled>true</Enabled>
                    <LogonCount>1</LogonCount>
                    <Password>
                        <Value>PW-REPLACEME</Value>
                        <PlainText>PT-STATUS</PlainText>
                    </Password>
                </AutoLogon>
                <OOBE>
                    <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                    <SkipUserOOBE>true</SkipUserOOBE>
                    <SkipMachineOOBE>true</SkipMachineOOBE>
                    <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                    <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                    <HideEULAPage>true</HideEULAPage>
                    <ProtectYourPC>3</ProtectYourPC>
                </OOBE>
                <FirstLogonCommands>
                    <SynchronousCommand wcm:action="add">
                        <Order>1</Order>
                        <CommandLine>reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoLogonCount /t REG_DWORD /d 0 /f</CommandLine>
                    </SynchronousCommand>
                    <SynchronousCommand wcm:action="add">
                        <Order>2</Order>
                        <CommandLine>cmd.exe /c echo 23&gt;c:\windows\csup.txt</CommandLine>
                    </SynchronousCommand>
                    <SynchronousCommand wcm:action="add">
                        <Order>3</Order>
                        <CommandLine>CMD /C echo GG&gt;C:\Windows\LogOobeSystem.txt</CommandLine>
                    </SynchronousCommand>
                    <SynchronousCommand wcm:action="add">
                        <Order>4</Order>
                        <CommandLine>powershell -ExecutionPolicy Bypass -File c:\windows\FirstStartup.ps1</CommandLine>
                    </SynchronousCommand>
                </FirstLogonCommands>
            </component>
        </settings>
    </unattend>
'@
    $specPass = @'
<settings pass="specialize">
        <component name="Microsoft-Windows-SQMApi" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <CEIPEnabled>0</CEIPEnabled>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ConfigureChatAutoInstall>false</ConfigureChatAutoInstall>
        </component>
        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <Path>reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v BypassNRO /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>2</Order>
                    <Path>reg.exe load "HKU\DefaultUser" "C:\Users\Default\NTUSER.DAT"</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>3</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Runonce" /v "UninstallCopilot" /t REG_SZ /d "powershell.exe -NoProfile -Command \"Get-AppxPackage -Name 'Microsoft.Windows.Ai.Copilot.Provider' | Remove-AppxPackage;\"" /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>4</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>5</Order>
                    <Path>reg.exe unload "HKU\DefaultUser"</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>6</Order>
                    <Path>reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>7</Order>
                    <Path>reg.exe load "HKU\DefaultUser" "C:\Users\Default\NTUSER.DAT"</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>8</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Notepad" /v ShowStoreBanner /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>9</Order>
                    <Path>reg.exe unload "HKU\DefaultUser"</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>10</Order>
                    <Path>cmd.exe /c "del "C:\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk""</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>11</Order>
                    <Path>cmd.exe /c "del "C:\Windows\System32\OneDriveSetup.exe""</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>12</Order>
                    <Path>cmd.exe /c "del "C:\Windows\SysWOW64\OneDriveSetup.exe""</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>13</Order>
                    <Path>reg.exe load "HKU\DefaultUser" "C:\Users\Default\NTUSER.DAT"</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>14</Order>
                    <Path>reg.exe delete "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSetup /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>15</Order>
                    <Path>reg.exe unload "HKU\DefaultUser"</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>16</Order>
                    <Path>reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>17</Order>
                    <Path>reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v ConfigureChatAutoInstall /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>18</Order>
                    <Path>powershell.exe -NoProfile -Command "$xml = [xml]::new(); $xml.Load('C:\Windows\Panther\unattend.xml'); $sb = [scriptblock]::Create( $xml.unattend.Extensions.ExtractScript ); Invoke-Command -ScriptBlock $sb -ArgumentList $xml;"</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>19</Order>
                    <Path>powershell.exe -NoProfile -Command "Get-Content -LiteralPath 'C:\Windows\Temp\Microwin-RemovePackages.ps1' -Raw | Invoke-Expression;"</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>20</Order>
                    <Path>powershell.exe -NoProfile -Command "Get-Content -LiteralPath 'C:\Windows\Temp\remove-caps.ps1' -Raw | Invoke-Expression;"</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>21</Order>
                    <Path>reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v ConfigureStartPins /t REG_SZ /d "{ \"pinnedList\": [] }" /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>22</Order>
                    <Path>reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v ConfigureStartPins_ProviderSet /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>23</Order>
                    <Path>reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v ConfigureStartPins_WinningProvider /t REG_SZ /d B5292708-1619-419B-9923-E5D9F3925E71 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>24</Order>
                    <Path>reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\providers\B5292708-1619-419B-9923-E5D9F3925E71\default\Device\Start" /v ConfigureStartPins /t REG_SZ /d "{ \"pinnedList\": [] }" /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>25</Order>
                    <Path>reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\providers\B5292708-1619-419B-9923-E5D9F3925E71\default\Device\Start" /v ConfigureStartPins_LastWrite /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>26</Order>
                    <Path>net.exe accounts /maxpwage:UNLIMITED</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>27</Order>
                    <Path>reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>28</Order>
                    <Path>reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>29</Order>
                    <Path>reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>30</Order>
                    <Path>reg.exe load "HKU\DefaultUser" "C:\Users\Default\NTUSER.DAT"</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>31</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>32</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>33</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OEMPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>34</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>35</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>36</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>37</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>38</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>39</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>40</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>41</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>42</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>43</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>44</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>45</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>46</Order>
                    <Path>reg.exe unload "HKU\DefaultUser"</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>47</Order>
                    <Path>reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>48</Order>
                    <Path>reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" /v "PreventDeviceEncryption" /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>49</Order>
                    <Path>reg.exe load "HKU\DefaultUser" "C:\Users\Default\NTUSER.DAT"</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>50</Order>
                    <Path>reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Runonce" /v "ClassicContextMenu" /t REG_SZ /d "reg.exe add \"HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32\" /ve /f" /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>51</Order>
                    <Path>reg.exe unload "HKU\DefaultUser"</Path>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
    </settings>
'@
    if ((Microwin-TestCompatibleImage $imgVersion $([System.Version]::new(10,0,22000,1))) -eq $false) {
        # Replace the placeholder text with an empty string to make it valid for Windows 10 Setup
        $unattend = $unattend.Replace("<#REPLACEME#>", "").Trim()
    } else {
        # Replace the placeholder text with the Specialize pass
        $unattend = $unattend.Replace("<#REPLACEME#>", $specPass).Trim()
    }

    # User password in Base64. According to Microsoft, this is the way you can hide this sensitive information.
    # More information can be found here: https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/wsim/hide-sensitive-data-in-an-answer-file
    # Yeah, I know this is not the best way to protect this kind of data, but we all know how Microsoft is - "the Apple of security" (in a sense, it takes them
    # an eternity to implement basic security features right. Just look at the NTLM and Kerberos situation!)

    $b64pass = ""

    # Replace default User and Password values with the provided parameters
    $unattend = $unattend.Replace("USER-REPLACEME", $userName).Trim()
    try {
        # I want to play it safe here - I don't want encoding mismatch problems like last time

        # NOTE: "Password" needs to be appended to the password specified by the user. Otherwise, a parse error will occur when processing oobeSystem.
        # This will not be added to the actual password stored in the target system's SAM file - only the provided password
        $b64pass = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("$($userPassword)Password"))
    } catch {
        $b64pass = ""
    }
    if ($b64pass -ne "") {
        # If we could encode the password with Base64, put it in the answer file and indicate that it's NOT in plain text
        $unattend = $unattend.Replace("PW-REPLACEME", $b64pass).Trim()
        $unattend = $unattend.Replace("PT-STATUS", "false").Trim()
        $b64pass = ""
    } else {
        $unattend = $unattend.Replace("PW-REPLACEME", $userPassword).Trim()
        $unattend = $unattend.Replace("PT-STATUS", "true").Trim()
    }

    # Save unattended answer file with UTF-8 encoding
    $unattend | Out-File -FilePath "$env:temp\unattend.xml" -Force -Encoding utf8
}
function Microwin-RemoveFeatures() {
    <#
        .SYNOPSIS
            Removes certain features from ISO image

        .PARAMETER UseCmdlets
            Determines whether or not to use the DISM cmdlets for processing.
            - If true, DISM cmdlets will be used
            - If false, calls to the DISM executable will be made whilst selecting bits and pieces from the output as a string (that was how MicroWin worked before
              the DISM conversion to cmdlets)

        .EXAMPLE
            Microwin-RemoveFeatures -UseCmdlets $true
    #>
    param (
        [Parameter(Mandatory = $true, Position = 0)] [bool]$UseCmdlets
    )
    try {
        if ($UseCmdlets) {
            $featlist = (Get-WindowsOptionalFeature -Path "$scratchDir")

            $featlist = $featlist | Where-Object {
                $_.FeatureName -NotLike "*Defender*" -AND
                $_.FeatureName -NotLike "*Printing*" -AND
                $_.FeatureName -NotLike "*TelnetClient*" -AND
                $_.FeatureName -NotLike "*PowerShell*" -AND
                $_.FeatureName -NotLike "*NetFx*" -AND
                $_.FeatureName -NotLike "*Media*" -AND
                $_.FeatureName -NotLike "*NFS*" -AND
                $_.FeatureName -NotLike "*SearchEngine*" -AND
                $_.FeatureName -NotLike "*RemoteDesktop*" -AND
                $_.State -ne "Disabled"
            }
        } else {
            $featList = dism /english /image="$scratchDir" /get-features | Select-String -Pattern "Feature Name : " -CaseSensitive -SimpleMatch
            if ($?) {
                $featList = $featList -split "Feature Name : " | Where-Object {$_}
                # Exclude the same items. Note: for now, this doesn't exclude those features that are disabled.
                # This will appear in the future
                $featList = $featList | Where-Object {
                    $_ -NotLike "*Defender*" -AND
                    $_ -NotLike "*Printing*" -AND
                    $_ -NotLike "*TelnetClient*" -AND
                    $_ -NotLike "*PowerShell*" -AND
                    $_ -NotLike "*NetFx*" -AND
                    $_ -NotLike "*Media*" -AND
                    $_ -NotLike "*NFS*" -AND
                    $_ -NotLike "*SearchEngine*" -AND
                    $_ -NotLike "*RemoteDesktop*"
                }
            } else {
                Write-Host "Features could not be obtained with DISM. MicroWin processing will continue, but features will be skipped."
                return
            }
        }

        if ($UseCmdlets) {
            foreach ($feature in $featList) {
                $status = "Removing feature $($feature.FeatureName)"
                Write-Progress -Activity "Removing features" -Status $status -PercentComplete ($counter++/$featlist.Count*100)
                Write-Debug "Removing feature $($feature.FeatureName)"
                Disable-WindowsOptionalFeature -Path "$scratchDir" -FeatureName $($feature.FeatureName) -Remove  -ErrorAction SilentlyContinue -NoRestart
            }
        } else {
            foreach ($feature in $featList) {
                $status = "Removing feature $feature"
                Write-Progress -Activity "Removing features" -Status $status -PercentComplete ($counter++/$featlist.Count*100)
                Write-Debug "Removing feature $feature"
                dism /english /image="$scratchDir" /disable-feature /featurename=$feature /remove /quiet /norestart | Out-Null
                if ($? -eq $false) {
                    Write-Host "Feature $feature could not be disabled."
                }
            }
        }
        Write-Progress -Activity "Removing features" -Status "Ready" -Completed
        Write-Host "You can re-enable the disabled features at any time, using either Windows Update or the SxS folder in <installation media>\Sources."
    } catch {
        Write-Host "Unable to get information about the features. A fallback will be used..."
        Write-Host "Error information: $($_.Exception.Message)" -ForegroundColor Yellow
        Microwin-RemoveFeatures -UseCmdlets $false
    }
}
function Microwin-RemoveFileOrDirectory([string]$pathToDelete, [string]$mask = "", [switch]$Directory = $false) {
    if(([string]::IsNullOrEmpty($pathToDelete))) { return }
    if (-not (Test-Path -Path "$($pathToDelete)")) { return }

    $yesNo = Get-LocalizedYesNo
    Write-Host "[INFO] In Your local takeown expects '$($yesNo[0])' as a Yes answer."

    $itemsToDelete = [System.Collections.ArrayList]::new()

    if ($mask -eq "") {
        Write-Debug "Adding $($pathToDelete) to array."
        [void]$itemsToDelete.Add($pathToDelete)
    } else {
        Write-Debug "Adding $($pathToDelete) to array and mask is $($mask)"
        if ($Directory) { $itemsToDelete = Get-ChildItem $pathToDelete -Include $mask -Recurse -Directory } else { $itemsToDelete = Get-ChildItem $pathToDelete -Include $mask -Recurse }
    }

    foreach($itemToDelete in $itemsToDelete) {
        $status = "Deleting $($itemToDelete)"
        Write-Progress -Activity "Removing Items" -Status $status -PercentComplete ($counter++/$itemsToDelete.Count*100)

        if (Test-Path -Path "$($itemToDelete)" -PathType Container) {
            $status = "Deleting directory: $($itemToDelete)"

            takeown /r /d $yesNo[0] /a /f "$($itemToDelete)"
            icacls "$($itemToDelete)" /q /c /t /reset
            icacls $itemToDelete /setowner "*S-1-5-32-544"
            icacls $itemToDelete /grant "*S-1-5-32-544:(OI)(CI)F" /t /c /q
            Remove-Item -Force -Recurse "$($itemToDelete)"
        }
        elseif (Test-Path -Path "$($itemToDelete)" -PathType Leaf) {
            $status = "Deleting file: $($itemToDelete)"

            takeown /a /f "$($itemToDelete)"
            icacls "$($itemToDelete)" /q /c /t /reset
            icacls "$($itemToDelete)" /setowner "*S-1-5-32-544"
            icacls "$($itemToDelete)" /grant "*S-1-5-32-544:(OI)(CI)F" /t /c /q
            Remove-Item -Force "$($itemToDelete)"
        }
    }
    Write-Progress -Activity "Removing Items" -Status "Ready" -Completed
}
function Microwin-RemovePackages {
    <#
        .SYNOPSIS
            Removes certain packages from ISO image

        .PARAMETER UseCmdlets
            Determines whether or not to use the DISM cmdlets for processing.
            - If true, DISM cmdlets will be used
            - If false, calls to the DISM executable will be made whilst selecting bits and pieces from the output as a string (that was how MicroWin worked before
              the DISM conversion to cmdlets)

        .EXAMPLE
            Microwin-RemovePackages -UseCmdlets $true
    #>
    param (
        [Parameter(Mandatory = $true, Position = 0)] [bool]$UseCmdlets
    )
    try {
        if ($useCmdlets) {
            $pkglist = (Get-WindowsPackage -Path "$scratchDir").PackageName

            $pkglist = $pkglist | Where-Object {
                    $_ -NotLike "*ApplicationModel*" -AND
                    $_ -NotLike "*indows-Client-LanguagePack*" -AND
                    $_ -NotLike "*LanguageFeatures-Basic*" -AND
                    $_ -NotLike "*Package_for_ServicingStack*" -AND
                    $_ -NotLike "*DotNet*" -AND
                    $_ -NotLike "*Notepad*" -AND
                    $_ -NotLike "*WMIC*" -AND
                    $_ -NotLike "*Ethernet*" -AND
                    $_ -NotLike "*Wifi*" -AND
                    $_ -NotLike "*FodMetadata*" -AND
                    $_ -NotLike "*Foundation*" -AND
                    $_ -NotLike "*LanguageFeatures*" -AND
                    $_ -NotLike "*VBSCRIPT*" -AND
                    $_ -NotLike "*License*" -AND
                    $_ -NotLike "*Hello-Face*" -AND
                    $_ -NotLike "*ISE*" -AND
                    $_ -NotLike "*OpenSSH*"
                }
        } else {
            $pkgList = dism /english /image="$scratchDir" /get-packages | Select-String -Pattern "Package Identity : " -CaseSensitive -SimpleMatch
            if ($?) {
                $pkgList = $pkgList -split "Package Identity : " | Where-Object {$_}
                # Exclude the same items.
                $pkgList = $pkgList | Where-Object {
                    $_ -NotLike "*ApplicationModel*" -AND
                    $_ -NotLike "*indows-Client-LanguagePack*" -AND
                    $_ -NotLike "*LanguageFeatures-Basic*" -AND
                    $_ -NotLike "*Package_for_ServicingStack*" -AND
                    $_ -NotLike "*DotNet*" -AND
                    $_ -NotLike "*Notepad*" -AND
                    $_ -NotLike "*WMIC*" -AND
                    $_ -NotLike "*Ethernet*" -AND
                    $_ -NotLike "*Wifi*" -AND
                    $_ -NotLike "*FodMetadata*" -AND
                    $_ -NotLike "*Foundation*" -AND
                    $_ -NotLike "*LanguageFeatures*" -AND
                    $_ -NotLike "*VBSCRIPT*" -AND
                    $_ -NotLike "*License*" -AND
                    $_ -NotLike "*Hello-Face*" -AND
                    $_ -NotLike "*ISE*" -AND
                    $_ -NotLike "*OpenSSH*"
                }
            } else {
                Write-Host "Packages could not be obtained with DISM. MicroWin processing will continue, but packages will be skipped."
                return
            }
        }

        if ($UseCmdlets) {
            $failedCount = 0

            $erroredPackages = [System.Collections.Generic.List[ErroredPackage]]::new()

            foreach ($pkg in $pkglist) {
                try {
                    $status = "Removing $pkg"
                    Write-Progress -Activity "Removing Packages" -Status $status -PercentComplete ($counter++/$pkglist.Count*100)
                    Remove-WindowsPackage -Path "$scratchDir" -PackageName $pkg -NoRestart -ErrorAction SilentlyContinue
                } catch {
                    # This can happen if the package that is being removed is a permanent one
                    $erroredPackages.Add([ErroredPackage]::new($pkg, $_.Exception.Message))
                    $failedCount += 1
                    continue
                }
            }
        } else {
            foreach ($package in $pkgList) {
                $status = "Removing package $package"
                Write-Progress -Activity "Removing features" -Status $status -PercentComplete ($counter++/$featlist.Count*100)
                Write-Debug "Removing package $package"
                dism /english /image="$scratchDir" /remove-package /packagename=$package /remove /quiet /norestart | Out-Null
                if ($? -eq $false) {
                    Write-Host "Package $package could not be removed."
                }
            }
        }
        Write-Progress -Activity "Removing Packages" -Status "Ready" -Completed
        if ($UseCmdlets -and $failedCount -gt 0)
        {
            Write-Host "$failedCount package(s) could not be removed. Your image will still work fine, however. Below is information on what packages failed to be removed and why."
            if ($erroredPackages.Count -gt 0)
            {
                $erroredPackages = $erroredPackages | Sort-Object -Property ErrorMessage

                $previousErroredPackage = $erroredPackages[0]
                $counter = 0
                Write-Host ""
                Write-Host "- $($previousErroredPackage.ErrorMessage)"
                foreach ($erroredPackage in $erroredPackages) {
                    if ($erroredPackage.ErrorMessage -ne $previousErroredPackage.ErrorMessage) {
                        Write-Host ""
                        $counter = 0
                        Write-Host "- $($erroredPackage.ErrorMessage)"
                    }
                    $counter += 1
                    Write-Host "  $counter) $($erroredPackage.PackageName)"
                    $previousErroredPackage = $erroredPackage
                }
                Write-Host ""
            }
        }
    } catch {
        Write-Host "Unable to get information about the packages. A fallback will be used..."
        Write-Host "Error information: $($_.Exception.Message)" -ForegroundColor Yellow
        Microwin-RemovePackages -UseCmdlets $false
    }
}
function Microwin-RemoveProvisionedPackages() {
    <#
        .SYNOPSIS
        Removes AppX packages from a Windows image during MicroWin processing

        .PARAMETER UseCmdlets
            Determines whether or not to use the DISM cmdlets for processing.
            - If true, DISM cmdlets will be used
            - If false, calls to the DISM executable will be made whilst selecting bits and pieces from the output as a string (that was how MicroWin worked before
              the DISM conversion to cmdlets)

        .EXAMPLE
        Microwin-RemoveProvisionedPackages
    #>
    param (
        [Parameter(Mandatory = $true, Position = 0)] [bool]$UseCmdlets
    )
    try
    {
        if ($UseCmdlets) {
            $appxProvisionedPackages = Get-AppxProvisionedPackage -Path "$($scratchDir)" | Where-Object {
                    $_.PackageName -NotLike "*AppInstaller*" -AND
                    $_.PackageName -NotLike "*Store*" -and
                    $_.PackageName -NotLike "*Notepad*" -and
                    $_.PackageName -NotLike "*Printing*" -and
                    $_.PackageName -NotLike "*YourPhone*" -and
                    $_.PackageName -NotLike "*Xbox*" -and
                    $_.PackageName -NotLike "*WindowsTerminal*" -and
                    $_.PackageName -NotLike "*Calculator*" -and
                    $_.PackageName -NotLike "*Photos*" -and
                    $_.PackageName -NotLike "*VCLibs*" -and
                    $_.PackageName -NotLike "*Paint*" -and
                    $_.PackageName -NotLike "*Gaming*" -and
                    $_.PackageName -NotLike "*Extension*" -and
                    $_.PackageName -NotLike "*SecHealthUI*" -and
                    $_.PackageName -NotLike "*ScreenSketch*"
            }
        } else {
            $appxProvisionedPackages = dism /english /image="$scratchDir" /get-provisionedappxpackages | Select-String -Pattern "PackageName : " -CaseSensitive -SimpleMatch
            if ($?) {
                $appxProvisionedPackages = $appxProvisionedPackages -split "PackageName : " | Where-Object {$_}
                # Exclude the same items.
                $appxProvisionedPackages = $appxProvisionedPackages | Where-Object {
                    $_ -NotLike "*AppInstaller*" -AND
                    $_ -NotLike "*Store*" -and
                    $_ -NotLike "*Notepad*" -and
                    $_ -NotLike "*Printing*" -and
                    $_ -NotLike "*YourPhone*" -and
                    $_ -NotLike "*Xbox*" -and
                    $_ -NotLike "*WindowsTerminal*" -and
                    $_ -NotLike "*Calculator*" -and
                    $_ -NotLike "*Photos*" -and
                    $_ -NotLike "*VCLibs*" -and
                    $_ -NotLike "*Paint*" -and
                    $_ -NotLike "*Gaming*" -and
                    $_ -NotLike "*Extension*" -and
                    $_ -NotLike "*SecHealthUI*" -and
                    $_ -NotLike "*ScreenSketch*"
                }
            } else {
                Write-Host "AppX packages could not be obtained with DISM. MicroWin processing will continue, but AppX packages will be skipped."
                return
            }
        }

        $counter = 0
        if ($UseCmdlets) {
            foreach ($appx in $appxProvisionedPackages) {
                $status = "Removing Provisioned $($appx.PackageName)"
                Write-Progress -Activity "Removing Provisioned Apps" -Status $status -PercentComplete ($counter++/$appxProvisionedPackages.Count*100)
                try {
                    Remove-AppxProvisionedPackage -Path "$scratchDir" -PackageName $appx.PackageName -ErrorAction SilentlyContinue
                } catch {
                    Write-Host "Application $($appx.PackageName) could not be removed"
                    continue
                }
            }
        } else {
            foreach ($appx in $appxProvisionedPackages) {
                $status = "Removing Provisioned $appx"
                Write-Progress -Activity "Removing Provisioned Apps" -Status $status -PercentComplete ($counter++/$appxProvisionedPackages.Count*100)
                dism /english /image="$scratchDir" /remove-provisionedappxpackage /packagename=$appx /quiet /norestart | Out-Null
                if ($? -eq $false) {
                    Write-Host "AppX package $appx could not be removed."
                }
            }
        }
        Write-Progress -Activity "Removing Provisioned Apps" -Status "Ready" -Completed
    }
    catch
    {
        Write-Host "Unable to get information about the AppX packages. A fallback will be used..."
        Write-Host "Error information: $($_.Exception.Message)" -ForegroundColor Yellow
        Microwin-RemoveProvisionedPackages -UseCmdlets $false
    }
}
function Microwin-TestCompatibleImage() {
    <#
        .SYNOPSIS
            Checks the version of a Windows image and determines whether or not it is compatible with a specific feature depending on a desired version

        .PARAMETER Name
            imgVersion - The version of the Windows image
            desiredVersion - The version to compare the image version with
    #>

    param
    (
    [Parameter(Mandatory, position=0)]
    [string]$imgVersion,

    [Parameter(Mandatory, position=1)]
    [Version]$desiredVersion
    )

    try {
        $version = [Version]$imgVersion
        return $version -ge $desiredVersion
    } catch {
        return $False
    }
}
function Copy-Files {
    <#

        .DESCRIPTION
            Copies the contents of a given ISO file to a given destination
        .PARAMETER Path
            The source of the files to copy
        .PARAMETER Destination
            The destination to copy the files to
        .PARAMETER Recurse
            Determines whether or not to copy all files of the ISO file, including those in subdirectories
        .PARAMETER Force
            Determines whether or not to overwrite existing files
        .EXAMPLE
            Copy-Files "D:" "C:\ISOFile" -Recurse -Force

    #>
    param (
        [string]$Path,
        [string]$Destination,
        [switch]$Recurse = $false,
        [switch]$Force = $false
    )

    try {

        $files = Get-ChildItem -Path $path -Recurse:$recurse
        Write-Host "Copy $($files.Count) file(s) from $path to $destination"

        foreach ($file in $files) {
            $status = "Copying file {0} of {1}: {2}" -f $counter, $files.Count, $file.Name
            Write-Progress -Activity "Copy disc image files" -Status $status -PercentComplete ($counter++/$files.count*100)
            $restpath = $file.FullName -Replace $path, ''

            if ($file.PSIsContainer -eq $true) {
                Write-Debug "Creating $($destination + $restpath)"
                New-Item ($destination+$restpath) -Force:$force -Type Directory -ErrorAction SilentlyContinue
            } else {
                Write-Debug "Copy from $($file.FullName) to $($destination+$restpath)"
                Copy-Item $file.FullName ($destination+$restpath) -ErrorAction SilentlyContinue -Force:$force
                Set-ItemProperty -Path ($destination+$restpath) -Name IsReadOnly -Value $false
            }
        }
        Write-Progress -Activity "Copy disc image files" -Status "Ready" -Completed
    } catch {
        Write-Host "Unable to Copy all the files due to an unhandled exception" -ForegroundColor Yellow
        Write-Host "Error information: $($_.Exception.Message)`n" -ForegroundColor Yellow
        Write-Host "Additional information:" -ForegroundColor Yellow
        Write-Host $PSItem.Exception.StackTrace
        # Write possible suggestions
        Write-Host "`nIf you are using an antivirus, try configuring exclusions"
    }
}
function Get-LocalizedYesNo {
    <#
    .SYNOPSIS
    This function runs choice.exe and captures its output to extract yes no in a localized Windows

    .DESCRIPTION
    The function retrieves the output of the command 'cmd /c "choice <nul 2>nul"' and converts the default output for Yes and No
    in the localized format, such as "Yes=<first character>, No=<second character>".

    .EXAMPLE
    $yesNoArray = Get-LocalizedYesNo
    Write-Host "Yes=$($yesNoArray[0]), No=$($yesNoArray[1])"
    #>

    # Run choice and capture its options as output
    # The output shows the options for Yes and No as "[Y,N]?" in the (partitially) localized format.
    # eg. English: [Y,N]?
    # Dutch: [Y,N]?
    # German: [J,N]?
    # French: [O,N]?
    # Spanish: [S,N]?
    # Italian: [S,N]?
    # Russian: [Y,N]?

    $line = cmd /c "choice <nul 2>nul"
    $charactersArray = @()
    $regexPattern = '([a-zA-Z])'
    $charactersArray = [regex]::Matches($line, $regexPattern) | ForEach-Object { $_.Groups[1].Value }

    Write-Debug "According to takeown.exe local Yes is $charactersArray[0]"
    # Return the array of characters
    return $charactersArray

  }
Function Get-WinUtilCheckBoxes {

    <#

    .SYNOPSIS
        Finds all checkboxes that are checked on the specific tab and inputs them into a script.

    .PARAMETER unCheck
        Whether to uncheck the checkboxes that are checked. Defaults to true

    .OUTPUTS
        A List containing the name of each checked checkbox

    .EXAMPLE
        Get-WinUtilCheckBoxes "WPFInstall"

    #>

    Param(
        [boolean]$unCheck = $false
    )

    $Output = @{
        Install      = @()
        WPFTweaks     = @()
        WPFFeature    = @()
        WPFInstall    = @()
    }

    $CheckBoxes = $sync.GetEnumerator() | Where-Object { $_.Value -is [System.Windows.Controls.CheckBox] }

    # First check and add WPFTweaksRestorePoint if checked
    $RestorePoint = $CheckBoxes | Where-Object { $_.Key -eq 'WPFTweaksRestorePoint' -and $_.Value.IsChecked -eq $true }
    if ($RestorePoint) {
        $Output["WPFTweaks"] = @('WPFTweaksRestorePoint')
        Write-Debug "Adding WPFTweaksRestorePoint as first in WPFTweaks"

        if ($unCheck) {
            $RestorePoint.Value.IsChecked = $false
        }
    }

    foreach ($CheckBox in $CheckBoxes) {
        if ($CheckBox.Key -eq 'WPFTweaksRestorePoint') { continue }  # Skip since it's already handled

        $group = if ($CheckBox.Key.StartsWith("WPFInstall")) { "Install" }
                elseif ($CheckBox.Key.StartsWith("WPFTweaks")) { "WPFTweaks" }
                elseif ($CheckBox.Key.StartsWith("WPFFeature")) { "WPFFeature" }
        if ($group) {
            if ($CheckBox.Value.IsChecked -eq $true) {
                $feature = switch ($group) {
                    "Install" {
                        # Get the winget value
                        [PsCustomObject]@{
                            winget="$($sync.configs.applications.$($CheckBox.Name).winget)";
                            choco="$($sync.configs.applications.$($CheckBox.Name).choco)";
                        }

                    }
                    default {
                        $CheckBox.Name
                    }
                }

                if (-not $Output.ContainsKey($group)) {
                    $Output[$group] = @()
                }
                if ($group -eq "Install") {
                    $Output["WPFInstall"] += $CheckBox.Name
                    Write-Debug "Adding: $($CheckBox.Name) under: WPFInstall"
                }

                Write-Debug "Adding: $($feature) under: $($group)"
                $Output[$group] += $feature

                if ($unCheck) {
                    $CheckBox.Value.IsChecked = $false
                }
            }
        }
    }
    return  $Output
}
function Get-WinUtilInstallerProcess {
    <#

    .SYNOPSIS
        Checks if the given process is running

    .PARAMETER Process
        The process to check

    .OUTPUTS
        Boolean - True if the process is running

    #>

    param($Process)

    if ($Null -eq $Process) {
        return $false
    }
    if (Get-Process -Id $Process.Id -ErrorAction SilentlyContinue) {
        return $true
    }
    return $false
}
Function Get-WinUtilToggleStatus {
    <#

    .SYNOPSIS
        Pulls the registry keys for the given toggle switch and checks whether the toggle should be checked or unchecked

    .PARAMETER ToggleSwitch
        The name of the toggle to check

    .OUTPUTS
        Boolean to set the toggle's status to

    #>

    Param($ToggleSwitch)

    $ToggleSwitchReg = $sync.configs.tweaks.$ToggleSwitch.registry

    try {
        if (($ToggleSwitchReg.path -imatch "hku") -and !(Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
            $null = (New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS)
            if (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue) {
                Write-Debug "HKU drive created successfully"
            } else {
                Write-Debug "Failed to create HKU drive"
            }
        }
    } catch {
        Write-Error "An error occurred regarding the HKU Drive: $_"
        return $false
    }

    if ($ToggleSwitchReg) {
        $count = 0

        foreach ($regentry in $ToggleSwitchReg) {
            try {
                if (!(Test-Path $regentry.Path)) {
                    New-Item -Path $regentry.Path -Force | Out-Null
                }
                $regstate = (Get-ItemProperty -path $regentry.Path).$($regentry.Name)
                if ($regstate -eq $regentry.Value) {
                    $count += 1
                    Write-Debug "$($regentry.Name) is true (state: $regstate, value: $($regentry.Value), original: $($regentry.OriginalValue))"
                } else {
                    Write-Debug "$($regentry.Name) is false (state: $regstate, value: $($regentry.Value), original: $($regentry.OriginalValue))"
                }
                if (!$regstate) {
                    switch ($regentry.DefaultState) {
                        "true" {
                            $regstate = $regentry.Value
                            $count += 1
                        }
                        "false" {
                            $regstate = $regentry.OriginalValue
                        }
                        default {
                            Write-Error "Entry for $($regentry.Name) does not exist and no DefaultState is defined."
                            $regstate = $regentry.OriginalValue
                        }
                    }
                }
            } catch {
                Write-Error "An unexpected error occurred: $_"
            }
        }

        if ($count -eq $ToggleSwitchReg.Count) {
            Write-Debug "$($ToggleSwitchReg.Name) is true (count: $count)"
            return $true
        } else {
            Write-Debug "$($ToggleSwitchReg.Name) is false (count: $count)"
            return $false
        }
    } else {
        return $false
    }
}
function Get-WinUtilVariables {

    <#
    .SYNOPSIS
        Gets every form object of the provided type

    .OUTPUTS
        List containing every object that matches the provided type
    #>
    param (
        [Parameter()]
        [string[]]$Type
    )
    $keys = ($sync.keys).where{ $_ -like "WPF*" }
    if ($Type) {
        $output = $keys | ForEach-Object {
            try {
                $objType = $sync["$psitem"].GetType().Name
                if ($Type -contains $objType) {
                    Write-Output $psitem
                }
            } catch {
                <#I am here so errors don't get outputted for a couple variables that don't have the .GetType() attribute#>
            }
        }
        return $output
    }
    return $keys
}
function Get-WinUtilWingetLatest {
    [CmdletBinding()]
    param()

    <#
    .SYNOPSIS
        Uses GitHub API to check for the latest release of Winget.
    .DESCRIPTION
        This function first attempts to update WinGet using winget itself, then falls back to manual installation if needed.
    #>
    $ProgressPreference = "SilentlyContinue"
    $InformationPreference = 'Continue'

    try {
        $wingetCmd = Get-Command winget -ErrorAction Stop
        Write-Information "Attempting to update WinGet using WinGet..."
        $result = Start-Process -FilePath "`"$($wingetCmd.Source)`"" -ArgumentList "install -e --accept-source-agreements --accept-package-agreements Microsoft.AppInstaller" -Wait -NoNewWindow -PassThru
        if ($result.ExitCode -ne 0) {
            throw "WinGet update failed with exit code: $($result.ExitCode)"
        }
        return $true
    }
    catch {
        Write-Information "WinGet not found or update failed. Attempting to install from Microsoft Store..."
        try {
            # Try to close any running WinGet processes
            Get-Process -Name "DesktopAppInstaller", "winget" -ErrorAction SilentlyContinue | ForEach-Object {
                Write-Information "Stopping running WinGet process..."
                $_.Kill()
                Start-Sleep -Seconds 2
            }

            # Try to load Windows Runtime assemblies more reliably
            $null = [System.Runtime.WindowsRuntime.WindowsRuntimeSystemExtensions]
            Add-Type -AssemblyName System.Runtime.WindowsRuntime

            # Load required assemblies from Windows SDK
            $null = @(
                [Windows.Management.Deployment.PackageManager, Windows.Management.Deployment, ContentType = WindowsRuntime]
                [Windows.Foundation.Uri, Windows.Foundation, ContentType = WindowsRuntime]
                [Windows.Management.Deployment.DeploymentOptions, Windows.Management.Deployment, ContentType = WindowsRuntime]
            )

            # Initialize PackageManager
            $packageManager = New-Object Windows.Management.Deployment.PackageManager

            # Rest of the Microsoft Store installation logic
            $appxPackage = "https://aka.ms/getwinget"
            $uri = New-Object Windows.Foundation.Uri($appxPackage)
            $deploymentOperation = $packageManager.AddPackageAsync($uri, $null, "Add")

            # Add timeout check for deployment operation
            $timeout = 300
            $timer = [System.Diagnostics.Stopwatch]::StartNew()

            while ($deploymentOperation.Status -eq 0) {
                if ($timer.Elapsed.TotalSeconds -gt $timeout) {
                    throw "Installation timed out after $timeout seconds"
                }
                Start-Sleep -Milliseconds 100
            }

            if ($deploymentOperation.Status -eq 1) {
                Write-Information "Successfully installed WinGet from Microsoft Store"
                return $true
            } else {
                throw "Installation failed with status: $($deploymentOperation.Status)"
            }
        }
        catch [System.Management.Automation.RuntimeException] {
            Write-Information "Windows Runtime components not available. Attempting manual download..."
            try {
                # Try to close any running WinGet processes
                Get-Process -Name "DesktopAppInstaller", "winget" -ErrorAction SilentlyContinue | ForEach-Object {
                    Write-Information "Stopping running WinGet process..."
                    $_.Kill()
                    Start-Sleep -Seconds 2
                }

                # Fallback to direct download from GitHub
                $apiUrl = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
                $release = Invoke-RestMethod -Uri $apiUrl
                $msixBundleUrl = ($release.assets | Where-Object { $_.name -like "*.msixbundle" }).browser_download_url

                $tempFile = Join-Path $env:TEMP "Microsoft.DesktopAppInstaller.msixbundle"
                Invoke-WebRequest -Uri $msixBundleUrl -OutFile $tempFile

                Add-AppxPackage -Path $tempFile -ErrorAction Stop
                Remove-Item $tempFile -Force

                Write-Information "Successfully installed WinGet from GitHub release"
                return $true
            }
            catch {
                Write-Error "Failed to install WinGet: $_"
                return $false
            }
        }
        catch {
            Write-Error "Failed to install WinGet: $_"
            return $false
        }
    }
}
function Get-WPFObjectName {
    <#
        .SYNOPSIS
            This is a helper function that generates an objectname with the prefix WPF that can be used as a Powershell Variable after compilation.
            To achieve this, all characters that are not a-z, A-Z or 0-9 are simply removed from the name.

        .PARAMETER type
            The type of object for which the name should be generated. (e.g. Label, Button, CheckBox...)

        .PARAMETER name
            The name or description to be used for the object. (invalid characters are removed)

        .OUTPUTS
            A string that can be used as a object/variable name in powershell.
            For example: WPFLabelMicrosoftTools

        .EXAMPLE
            Get-WPFObjectName -type Label -name "Microsoft Tools"
    #>

    param(
        [Parameter(Mandatory, position=0)]
        [string]$type,

        [Parameter(position=1)]
        [string]$name
    )

    $Output = $("WPF"+$type+$name) -replace '[^a-zA-Z0-9]', ''
    return $Output
}
function Install-WinUtilChoco {

    <#

    .SYNOPSIS
        Installs Chocolatey if it is not already installed

    #>

    try {
        Write-Host "Checking if Chocolatey is Installed..."

        if((Test-WinUtilPackageManager -choco) -eq "installed") {
            return
        }
        # Install logic taken from https://chocolatey.org/install#individual
        Write-Host "Seems Chocolatey is not installed, installing now."
        Set-ExecutionPolicy Bypass -Scope Process -Force;
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

    } catch {
        Write-Host "===========================================" -Foregroundcolor Red
        Write-Host "--     Chocolatey failed to install     ---" -Foregroundcolor Red
        Write-Host "===========================================" -Foregroundcolor Red
    }

}
function Install-WinUtilProgramChoco {
    <#
    .SYNOPSIS
    Manages the installation or uninstallation of a list of Chocolatey packages.

    .PARAMETER Programs
    A string array containing the programs to be installed or uninstalled.

    .PARAMETER Action
    Specifies the action to perform: "Install" or "Uninstall". The default value is "Install".

    .DESCRIPTION
    This function processes a list of programs to be managed using Chocolatey. Depending on the specified action, it either installs or uninstalls each program in the list, updating the taskbar progress accordingly. After all operations are completed, temporary output files are cleaned up.

    .EXAMPLE
    Install-WinUtilProgramChoco -Programs @("7zip","chrome") -Action "Uninstall"
    #>

    param(
        [Parameter(Mandatory, Position = 0)]
        [string[]]$Programs,

        [Parameter(Position = 1)]
        [String]$Action = "Install"
    )

    function Initialize-OutputFile {
        <#
        .SYNOPSIS
        Initializes an output file by removing any existing file and creating a new, empty file at the specified path.

        .PARAMETER filePath
        The full path to the file to be initialized.

        .DESCRIPTION
        This function ensures that the specified file is reset by removing any existing file at the provided path and then creating a new, empty file. It is useful when preparing a log or output file for subsequent operations.

        .EXAMPLE
        Initialize-OutputFile -filePath "C:\temp\output.txt"
        #>

        param ($filePath)
        Remove-Item -Path $filePath -Force -ErrorAction SilentlyContinue
        New-Item -ItemType File -Path $filePath | Out-Null
    }

    function Invoke-ChocoCommand {
        <#
        .SYNOPSIS
        Executes a Chocolatey command with the specified arguments and returns the exit code.

        .PARAMETER arguments
        The arguments to be passed to the Chocolatey command.

        .DESCRIPTION
        This function runs a specified Chocolatey command by passing the provided arguments to the `choco` executable. It waits for the process to complete and then returns the exit code, allowing the caller to determine success or failure based on the exit code.

        .RETURNS
        [int]
        The exit code of the Chocolatey command.

        .EXAMPLE
        $exitCode = Invoke-ChocoCommand -arguments "install 7zip -y"
        #>

        param ($arguments)
        return (Start-Process -FilePath "choco" -ArgumentList $arguments -Wait -PassThru).ExitCode
    }

    function Test-UpgradeNeeded {
        <#
        .SYNOPSIS
        Checks if an upgrade is needed for a Chocolatey package based on the content of a log file.

        .PARAMETER filePath
        The path to the log file that contains the output of a Chocolatey install command.

        .DESCRIPTION
        This function reads the specified log file and checks for keywords that indicate whether an upgrade is needed. It returns a boolean value indicating whether the terms "reinstall" or "already installed" are present, which suggests that the package might need an upgrade.

        .RETURNS
        [bool]
        True if the log file indicates that an upgrade is needed; otherwise, false.

        .EXAMPLE
        $isUpgradeNeeded = Test-UpgradeNeeded -filePath "C:\temp\install-output.txt"
        #>

        param ($filePath)
        return Get-Content -Path $filePath | Select-String -Pattern "reinstall|already installed" -Quiet
    }

    function Update-TaskbarProgress {
        <#
        .SYNOPSIS
        Updates the taskbar progress based on the current installation progress.

        .PARAMETER currentIndex
        The current index of the program being installed or uninstalled.

        .PARAMETER totalPrograms
        The total number of programs to be installed or uninstalled.

        .DESCRIPTION
        This function calculates the progress of the installation or uninstallation process and updates the taskbar accordingly. The taskbar is set to "Normal" if all programs have been processed, otherwise, it is set to "Error" as a placeholder.

        .EXAMPLE
        Update-TaskbarProgress -currentIndex 3 -totalPrograms 10
        #>

        param (
            [int]$currentIndex,
            [int]$totalPrograms
        )
        $progressState = if ($currentIndex -eq $totalPrograms) { "Normal" } else { "Error" }
        $sync.form.Dispatcher.Invoke([action] { Set-WinUtilTaskbaritem -state $progressState -value ($currentIndex / $totalPrograms) })
    }

    function Install-ChocoPackage {
        <#
        .SYNOPSIS
        Installs a Chocolatey package and optionally upgrades it if needed.

        .PARAMETER Program
        A string containing the name of the Chocolatey package to be installed.

        .PARAMETER currentIndex
        The current index of the program in the list of programs to be managed.

        .PARAMETER totalPrograms
        The total number of programs to be installed.

        .DESCRIPTION
        This function installs a Chocolatey package by running the `choco install` command. If the installation output indicates that an upgrade might be needed, the function will attempt to upgrade the package. The taskbar progress is updated after each package is processed.

        .EXAMPLE
        Install-ChocoPackage -Program $Program -currentIndex 0 -totalPrograms 5
        #>

        param (
            [string]$Program,
            [int]$currentIndex,
            [int]$totalPrograms
        )

        $installOutputFile = "$env:TEMP\Install-WinUtilProgramChoco.install-command.output.txt"
        Initialize-OutputFile $installOutputFile

        Write-Host "Starting installation of $Program with Chocolatey."

        try {
            $installStatusCode = Invoke-ChocoCommand "install $Program -y --log-file $installOutputFile"
            if ($installStatusCode -eq 0) {

                if (Test-UpgradeNeeded $installOutputFile) {
                    $upgradeStatusCode = Invoke-ChocoCommand "upgrade $Program -y"
                    Write-Host "$Program was" $(if ($upgradeStatusCode -eq 0) { "upgraded successfully." } else { "not upgraded." })
                }
                else {
                    Write-Host "$Program installed successfully."
                }
            }
            else {
                Write-Host "Failed to install $Program."
            }
        }
        catch {
            Write-Host "Failed to install $Program due to an error: $_"
        }
        finally {
            Update-TaskbarProgress $currentIndex $totalPrograms
        }
    }

    function Uninstall-ChocoPackage {
        <#
        .SYNOPSIS
        Uninstalls a Chocolatey package and any related metapackages.

        .PARAMETER Program
        A string containing the name of the Chocolatey package to be uninstalled.

        .PARAMETER currentIndex
        The current index of the program in the list of programs to be managed.

        .PARAMETER totalPrograms
        The total number of programs to be uninstalled.

        .DESCRIPTION
        This function uninstalls a Chocolatey package and any related metapackages (e.g., .install or .portable variants). It updates the taskbar progress after processing each package.

        .EXAMPLE
        Uninstall-ChocoPackage -Program $Program -currentIndex 0 -totalPrograms 5
        #>

        param (
            [string]$Program,
            [int]$currentIndex,
            [int]$totalPrograms
        )

        $uninstallOutputFile = "$env:TEMP\Install-WinUtilProgramChoco.uninstall-command.output.txt"
        Initialize-OutputFile $uninstallOutputFile

        Write-Host "Searching for metapackages of $Program (.install or .portable)"
        $chocoPackages = ((choco list | Select-String -Pattern "$Program(\.install|\.portable)?").Matches.Value) -join " "
        if ($chocoPackages) {
            Write-Host "Starting uninstallation of $chocoPackages with Chocolatey."
            try {
                $uninstallStatusCode = Invoke-ChocoCommand "uninstall $chocoPackages -y"
                Write-Host "$Program" $(if ($uninstallStatusCode -eq 0) { "uninstalled successfully." } else { "failed to uninstall." })
            }
            catch {
                Write-Host "Failed to uninstall $Program due to an error: $_"
            }
            finally {
                Update-TaskbarProgress $currentIndex $totalPrograms
            }
        }
        else {
            Write-Host "$Program is not installed."
        }
    }

    $totalPrograms = $Programs.Count
    if ($totalPrograms -le 0) {
        throw "Parameter 'Programs' must have at least one item."
    }

    Write-Host "==========================================="
    Write-Host "--   Configuring Chocolatey packages   ---"
    Write-Host "==========================================="

    for ($currentIndex = 0; $currentIndex -lt $totalPrograms; $currentIndex++) {
        $Program = $Programs[$currentIndex]
        Set-WinUtilProgressBar -label "$Action $($Program)" -percent ($currentIndex / $totalPrograms * 100)
        $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -value ($currentIndex / $totalPrograms)})

        switch ($Action) {
            "Install" {
                Install-ChocoPackage -Program $Program  -currentIndex $currentIndex -totalPrograms $totalPrograms
            }
            "Uninstall" {
                Uninstall-ChocoPackage -Program $Program -currentIndex $currentIndex -totalPrograms $totalPrograms
            }
            default {
                throw "Invalid action parameter value: '$Action'."
            }
        }
    }
    Set-WinUtilProgressBar -label "$($Action)ation done" -percent 100
    # Cleanup Output Files
    $outputFiles = @("$env:TEMP\Install-WinUtilProgramChoco.install-command.output.txt", "$env:TEMP\Install-WinUtilProgramChoco.uninstall-command.output.txt")
    foreach ($filePath in $outputFiles) {
        Remove-Item -Path $filePath -Force -ErrorAction SilentlyContinue
    }
}

Function Install-WinUtilProgramWinget {
    <#
    .SYNOPSIS
    Runs the designated action on the provided programs using Winget

    .PARAMETER Programs
    A list of programs to process

    .PARAMETER action
    The action to perform on the programs, can be either 'Install' or 'Uninstall'

    .NOTES
    The triple quotes are required any time you need a " in a normal script block.
    The winget Return codes are documented here: https://github.com/microsoft/winget-cli/blob/master/doc/windows/package-actionr/winget/returnCodes.md
    #>

    param(
        [Parameter(Mandatory, Position=0)]$Programs,

        [Parameter(Mandatory, Position=1)]
        [ValidateSet("Install", "Uninstall")]
        [String]$Action
    )

    Function Invoke-Winget {
    <#
    .SYNOPSIS
    Invokes the winget.exe with the provided arguments and return the exit code

    .PARAMETER wingetId
    The Id of the Program that Winget should Install/Uninstall

    .PARAMETER scope
    Determines the installation mode. Can be "user" or "machine" (For more info look at the winget documentation)

    .PARAMETER credential
    The PSCredential Object of the user that should be used to run winget

    .NOTES
    Invoke Winget uses the public variable $Action defined outside the function to determine if a Program should be installed or removed
    #>
        param (
            [string]$wingetId,
            [string]$scope = "",
            [PScredential]$credential = $null
        )

        $commonArguments = "--id $wingetId --silent"
        $arguments = if ($Action -eq "Install") {
            "install $commonArguments --accept-source-agreements --accept-package-agreements $(if ($scope) {" --scope $scope"})"
        } else {
            "uninstall $commonArguments"
        }

        $processParams = @{
            FilePath = "winget"
            ArgumentList = $arguments
            Wait = $true
            PassThru = $true
            NoNewWindow = $true
        }

        if ($credential) {
            $processParams.credential = $credential
        }

        return (Start-Process @processParams).ExitCode
    }

    Function Invoke-Install {
    <#
    .SYNOPSIS
    Contains the Install Logic and return code handling from winget

    .PARAMETER Program
    The Winget ID of the Program that should be installed
    #>
        param (
            [string]$Program
        )
        $status = Invoke-Winget -wingetId $Program
        if ($status -eq 0) {
            Write-Host "$($Program) installed successfully."
            return $true
        } elseif ($status -eq -1978335189) {
            Write-Host "$($Program) No applicable update found"
            return $true
        }

        Write-Host "Attempt installation of $($Program) with User scope"
        $status = Invoke-Winget -wingetId $Program -scope "user"
        if ($status -eq 0) {
            Write-Host "$($Program) installed successfully with User scope."
            return $true
        } elseif ($status -eq -1978335189) {
            Write-Host "$($Program) No applicable update found"
            return $true
        }

        $userChoice = [System.Windows.MessageBox]::Show("Do you want to attempt $($Program) installation with specific user credentials? Select 'Yes' to proceed or 'No' to skip.", "User credential Prompt", [System.Windows.MessageBoxButton]::YesNo)
        if ($userChoice -eq 'Yes') {
            $getcreds = Get-Credential
            $status = Invoke-Winget -wingetId $Program -credential $getcreds
            if ($status -eq 0) {
                Write-Host "$($Program) installed successfully with User prompt."
                return $true
            }
        } else {
            Write-Host "Skipping installation with specific user credentials."
        }

        Write-Host "Failed to install $($Program)."
        return $false
    }

    Function Invoke-Uninstall {
        <#
        .SYNOPSIS
        Contains the Uninstall Logic and return code handling from winget

        .PARAMETER Program
        The Winget ID of the Program that should be uninstalled
        #>
        param (
            [psobject]$Program
        )

        try {
            $status = Invoke-Winget -wingetId $Program
            if ($status -eq 0) {
                Write-Host "$($Program) uninstalled successfully."
                return $true
            } else {
                Write-Host "Failed to uninstall $($Program)."
                return $false
            }
        } catch {
            Write-Host "Failed to uninstall $($Program) due to an error: $_"
            return $false
        }
    }

    $count = $Programs.Count
    $failedPackages = @()

    Write-Host "==========================================="
    Write-Host "--    Configuring winget packages       ---"
    Write-Host "==========================================="

    for ($i = 0; $i -lt $count; $i++) {
        $Program = $Programs[$i]
        $result = $false
        Set-WinUtilProgressBar -label "$Action $($Program)" -percent ($i / $count * 100)
        $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -value ($i / $count)})

        $result = switch ($Action) {
            "Install" {Invoke-Install -Program $Program}
            "Uninstall" {Invoke-Uninstall -Program $Program}
            default {throw "[Install-WinUtilProgramWinget] Invalid action: $Action"}
        }

        if (-not $result) {
            $failedPackages += $Program
        }
    }

    Set-WinUtilProgressBar -label "$($Action)ation done" -percent 100
    return $failedPackages
}
function Install-WinUtilWinget {
    <#

    .SYNOPSIS
        Installs Winget if it is not already installed.

    .DESCRIPTION
        This function will download the latest version of Winget and install it. If Winget is already installed, it will do nothing.
    #>
    $isWingetInstalled = Test-WinUtilPackageManager -winget

    try {
        if ($isWingetInstalled -eq "installed") {
            Write-Host "`nWinget is already installed.`r" -ForegroundColor Green
            return
        } elseif ($isWingetInstalled -eq "outdated") {
            Write-Host "`nWinget is Outdated. Continuing with install.`r" -ForegroundColor Yellow
        } else {
            Write-Host "`nWinget is not Installed. Continuing with install.`r" -ForegroundColor Red
        }


        # Gets the computer's information
        if ($null -eq $sync.ComputerInfo) {
            $ComputerInfo = Get-ComputerInfo -ErrorAction Stop
        } else {
            $ComputerInfo = $sync.ComputerInfo
        }

        if (($ComputerInfo.WindowsVersion) -lt "1809") {
            # Checks if Windows Version is too old for Winget
            Write-Host "Winget is not supported on this version of Windows (Pre-1809)" -ForegroundColor Red
            return
        }

        # Install Winget via GitHub method.
        # Used part of my own script with some modification: ruxunderscore/windows-initialization
        Write-Host "Downloading Winget and License File`r"
        Get-WinUtilWingetLatest
        Write-Host "Enabling NuGet and Module..."
        Install-PackageProvider -Name NuGet -Force
        Install-Module -Name Microsoft.WinGet.Client -Force
        # Winget only needs a refresh of the environment variables to be used.
        Write-Output "Refreshing Environment Variables...`n"
        $ENV:PATH = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    } catch {
        Write-Error "Failed to install Winget: $($_.Exception.Message)"
    }

}
function Invoke-WinUtilAssets {
  param (
      $type,
      $Size,
      [switch]$render
  )

  # Create the Viewbox and set its size
  $LogoViewbox = New-Object Windows.Controls.Viewbox
  $LogoViewbox.Width = $Size
  $LogoViewbox.Height = $Size

  # Create a Canvas to hold the paths
  $canvas = New-Object Windows.Controls.Canvas
  $canvas.Width = 100
  $canvas.Height = 100

  # Define a scale factor for the content inside the Canvas
  $scaleFactor = $Size / 100

  # Apply a scale transform to the Canvas content
  $scaleTransform = New-Object Windows.Media.ScaleTransform($scaleFactor, $scaleFactor)
  $canvas.LayoutTransform = $scaleTransform

  switch ($type) {
      'logo' {
          $LogoPathData1 = @"
M 18.00,14.00
C 18.00,14.00 45.00,27.74 45.00,27.74
45.00,27.74 57.40,34.63 57.40,34.63
57.40,34.63 59.00,43.00 59.00,43.00
59.00,43.00 59.00,83.00 59.00,83.00
55.35,81.66 46.99,77.79 44.72,74.79
41.17,70.10 42.01,59.80 42.00,54.00
42.00,51.62 42.20,48.29 40.98,46.21
38.34,41.74 25.78,38.60 21.28,33.79
16.81,29.02 18.00,20.20 18.00,14.00 Z
"@
          $LogoPath1 = New-Object Windows.Shapes.Path
          $LogoPath1.Data = [Windows.Media.Geometry]::Parse($LogoPathData1)
          $LogoPath1.Fill = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#0567ff")

          $LogoPathData2 = @"
M 107.00,14.00
C 109.01,19.06 108.93,30.37 104.66,34.21
100.47,37.98 86.38,43.10 84.60,47.21
83.94,48.74 84.01,51.32 84.00,53.00
83.97,57.04 84.46,68.90 83.26,72.00
81.06,77.70 72.54,81.42 67.00,83.00
67.00,83.00 67.00,43.00 67.00,43.00
67.00,43.00 67.99,35.63 67.99,35.63
67.99,35.63 80.00,28.26 80.00,28.26
80.00,28.26 107.00,14.00 107.00,14.00 Z
"@
          $LogoPath2 = New-Object Windows.Shapes.Path
          $LogoPath2.Data = [Windows.Media.Geometry]::Parse($LogoPathData2)
          $LogoPath2.Fill = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#0567ff")

          $LogoPathData3 = @"
M 19.00,46.00
C 21.36,47.14 28.67,50.71 30.01,52.63
31.17,54.30 30.99,57.04 31.00,59.00
31.04,65.41 30.35,72.16 33.56,78.00
38.19,86.45 46.10,89.04 54.00,93.31
56.55,94.69 60.10,97.20 63.00,97.22
65.50,97.24 68.77,95.36 71.00,94.25
76.42,91.55 84.51,87.78 88.82,83.68
94.56,78.20 95.96,70.59 96.00,63.00
96.01,60.24 95.59,54.63 97.02,52.39
98.80,49.60 103.95,47.87 107.00,47.00
107.00,47.00 107.00,67.00 107.00,67.00
106.90,87.69 96.10,93.85 80.00,103.00
76.51,104.98 66.66,110.67 63.00,110.52
60.33,110.41 55.55,107.53 53.00,106.25
46.21,102.83 36.63,98.57 31.04,93.68
16.88,81.28 19.00,62.88 19.00,46.00 Z
"@
          $LogoPath3 = New-Object Windows.Shapes.Path
          $LogoPath3.Data = [Windows.Media.Geometry]::Parse($LogoPathData3)
          $LogoPath3.Fill = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#a3a4a6")

          $canvas.Children.Add($LogoPath1) | Out-Null
          $canvas.Children.Add($LogoPath2) | Out-Null
          $canvas.Children.Add($LogoPath3) | Out-Null
      }
      'checkmark' {
          $canvas.Width = 512
          $canvas.Height = 512

          $scaleFactor = $Size / 2.54
          $scaleTransform = New-Object Windows.Media.ScaleTransform($scaleFactor, $scaleFactor)
          $canvas.LayoutTransform = $scaleTransform

          # Define the circle path
          $circlePathData = "M 1.27,0 A 1.27,1.27 0 1,0 1.27,2.54 A 1.27,1.27 0 1,0 1.27,0"
          $circlePath = New-Object Windows.Shapes.Path
          $circlePath.Data = [Windows.Media.Geometry]::Parse($circlePathData)
          $circlePath.Fill = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#39ba00")

          # Define the checkmark path
          $checkmarkPathData = "M 0.873 1.89 L 0.41 1.391 A 0.17 0.17 0 0 1 0.418 1.151 A 0.17 0.17 0 0 1 0.658 1.16 L 1.016 1.543 L 1.583 1.013 A 0.17 0.17 0 0 1 1.599 1 L 1.865 0.751 A 0.17 0.17 0 0 1 2.105 0.759 A 0.17 0.17 0 0 1 2.097 0.999 L 1.282 1.759 L 0.999 2.022 L 0.874 1.888 Z"
          $checkmarkPath = New-Object Windows.Shapes.Path
          $checkmarkPath.Data = [Windows.Media.Geometry]::Parse($checkmarkPathData)
          $checkmarkPath.Fill = [Windows.Media.Brushes]::White

          # Add the paths to the Canvas
          $canvas.Children.Add($circlePath) | Out-Null
          $canvas.Children.Add($checkmarkPath) | Out-Null
      }
      'warning' {
          $canvas.Width = 512
          $canvas.Height = 512

          # Define a scale factor for the content inside the Canvas
          $scaleFactor = $Size / 512  # Adjust scaling based on the canvas size
          $scaleTransform = New-Object Windows.Media.ScaleTransform($scaleFactor, $scaleFactor)
          $canvas.LayoutTransform = $scaleTransform

          # Define the circle path
          $circlePathData = "M 256,0 A 256,256 0 1,0 256,512 A 256,256 0 1,0 256,0"
          $circlePath = New-Object Windows.Shapes.Path
          $circlePath.Data = [Windows.Media.Geometry]::Parse($circlePathData)
          $circlePath.Fill = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#f41b43")

          # Define the exclamation mark path
          $exclamationPathData = "M 256 307.2 A 35.89 35.89 0 0 1 220.14 272.74 L 215.41 153.3 A 35.89 35.89 0 0 1 251.27 116 H 260.73 A 35.89 35.89 0 0 1 296.59 153.3 L 291.86 272.74 A 35.89 35.89 0 0 1 256 307.2 Z"
          $exclamationPath = New-Object Windows.Shapes.Path
          $exclamationPath.Data = [Windows.Media.Geometry]::Parse($exclamationPathData)
          $exclamationPath.Fill = [Windows.Media.Brushes]::White

          # Get the bounds of the exclamation mark path
          $exclamationBounds = $exclamationPath.Data.Bounds

          # Calculate the center position for the exclamation mark path
          $exclamationCenterX = ($canvas.Width - $exclamationBounds.Width) / 2 - $exclamationBounds.X
          $exclamationPath.SetValue([Windows.Controls.Canvas]::LeftProperty, $exclamationCenterX)

          # Define the rounded rectangle at the bottom (dot of exclamation mark)
          $roundedRectangle = New-Object Windows.Shapes.Rectangle
          $roundedRectangle.Width = 80
          $roundedRectangle.Height = 80
          $roundedRectangle.RadiusX = 30
          $roundedRectangle.RadiusY = 30
          $roundedRectangle.Fill = [Windows.Media.Brushes]::White

          # Calculate the center position for the rounded rectangle
          $centerX = ($canvas.Width - $roundedRectangle.Width) / 2
          $roundedRectangle.SetValue([Windows.Controls.Canvas]::LeftProperty, $centerX)
          $roundedRectangle.SetValue([Windows.Controls.Canvas]::TopProperty, 324.34)

          # Add the paths to the Canvas
          $canvas.Children.Add($circlePath) | Out-Null
          $canvas.Children.Add($exclamationPath) | Out-Null
          $canvas.Children.Add($roundedRectangle) | Out-Null
      }
      default {
          Write-Host "Invalid type: $type"
      }
  }

  # Add the Canvas to the Viewbox
  $LogoViewbox.Child = $canvas

  if ($render) {
      # Measure and arrange the canvas to ensure proper rendering
      $canvas.Measure([Windows.Size]::new($canvas.Width, $canvas.Height))
      $canvas.Arrange([Windows.Rect]::new(0, 0, $canvas.Width, $canvas.Height))
      $canvas.UpdateLayout()

      # Initialize RenderTargetBitmap correctly with dimensions
      $renderTargetBitmap = New-Object Windows.Media.Imaging.RenderTargetBitmap($canvas.Width, $canvas.Height, 96, 96, [Windows.Media.PixelFormats]::Pbgra32)

      # Render the canvas to the bitmap
      $renderTargetBitmap.Render($canvas)

      # Create a BitmapFrame from the RenderTargetBitmap
      $bitmapFrame = [Windows.Media.Imaging.BitmapFrame]::Create($renderTargetBitmap)

      # Create a PngBitmapEncoder and add the frame
      $bitmapEncoder = [Windows.Media.Imaging.PngBitmapEncoder]::new()
      $bitmapEncoder.Frames.Add($bitmapFrame)

      # Save to a memory stream
      $imageStream = New-Object System.IO.MemoryStream
      $bitmapEncoder.Save($imageStream)
      $imageStream.Position = 0

      # Load the stream into a BitmapImage
      $bitmapImage = [Windows.Media.Imaging.BitmapImage]::new()
      $bitmapImage.BeginInit()
      $bitmapImage.StreamSource = $imageStream
      $bitmapImage.CacheOption = [Windows.Media.Imaging.BitmapCacheOption]::OnLoad
      $bitmapImage.EndInit()

      return $bitmapImage
  } else {
      return $LogoViewbox
  }
}
Function Invoke-WinUtilCurrentSystem {

    <#

    .SYNOPSIS
        Checks to see what tweaks have already been applied and what programs are installed, and checks the according boxes

    .EXAMPLE
        Get-WinUtilCheckBoxes "WPFInstall"

    #>

    param(
        $CheckBox
    )
    if ($CheckBox -eq "choco") {
        $apps = (choco list | Select-String -Pattern "^\S+").Matches.Value
        $filter = Get-WinUtilVariables -Type Checkbox | Where-Object {$psitem -like "WPFInstall*"}
        $sync.GetEnumerator() | Where-Object {$psitem.Key -in $filter} | ForEach-Object {
            $dependencies = @($sync.configs.applications.$($psitem.Key).choco -split ";")
            if ($dependencies -in $apps) {
                Write-Output $psitem.name
            }
        }
    }

    if ($checkbox -eq "winget") {

        $originalEncoding = [Console]::OutputEncoding
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
        $Sync.InstalledPrograms = winget list -s winget | Select-Object -skip 3 | ConvertFrom-String -PropertyNames "Name", "Id", "Version", "Available" -Delimiter '\s{2,}'
        [Console]::OutputEncoding = $originalEncoding

        $filter = Get-WinUtilVariables -Type Checkbox | Where-Object {$psitem -like "WPFInstall*"}
        $sync.GetEnumerator() | Where-Object {$psitem.Key -in $filter} | ForEach-Object {
            $dependencies = @($sync.configs.applications.$($psitem.Key).winget -split ";")

            if ($dependencies[-1] -in $sync.InstalledPrograms.Id) {
                Write-Output $psitem.name
            }
        }
    }

    if($CheckBox -eq "tweaks") {

        if(!(Test-Path 'HKU:\')) {$null = (New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS)}
        $ScheduledTasks = Get-ScheduledTask

        $sync.configs.tweaks | Get-Member -MemberType NoteProperty | ForEach-Object {

            $Config = $psitem.Name
            #WPFEssTweaksTele
            $registryKeys = $sync.configs.tweaks.$Config.registry
            $scheduledtaskKeys = $sync.configs.tweaks.$Config.scheduledtask
            $serviceKeys = $sync.configs.tweaks.$Config.service

            if($registryKeys -or $scheduledtaskKeys -or $serviceKeys) {
                $Values = @()


                Foreach ($tweaks in $registryKeys) {
                    Foreach($tweak in $tweaks) {

                        if(test-path $tweak.Path) {
                            $actualValue = Get-ItemProperty -Name $tweak.Name -Path $tweak.Path -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $($tweak.Name)
                            $expectedValue = $tweak.Value
                            if ($expectedValue -notlike $actualValue) {
                                $values += $False
                            }
                        } else {
                            $values += $False
                        }
                    }
                }

                Foreach ($tweaks in $scheduledtaskKeys) {
                    Foreach($tweak in $tweaks) {
                        $task = $ScheduledTasks | Where-Object {$($psitem.TaskPath + $psitem.TaskName) -like "\$($tweak.name)"}

                        if($task) {
                            $actualValue = $task.State
                            $expectedValue = $tweak.State
                            if ($expectedValue -ne $actualValue) {
                                $values += $False
                            }
                        }
                    }
                }

                Foreach ($tweaks in $serviceKeys) {
                    Foreach($tweak in $tweaks) {
                        $Service = Get-Service -Name $tweak.Name

                        if($Service) {
                            $actualValue = $Service.StartType
                            $expectedValue = $tweak.StartupType
                            if ($expectedValue -ne $actualValue) {
                                $values += $False
                            }
                        }
                    }
                }

                if($values -notcontains $false) {
                    Write-Output $Config
                }
            }
        }
    }
}
function Invoke-WinUtilExplorerUpdate {
    <#
    .SYNOPSIS
        Refreshes the Windows Explorer
    #>

    param (
        [string]$action = "refresh"
    )

    if ($action -eq "refresh") {
        Invoke-WPFRunspace -DebugPreference $DebugPreference -ScriptBlock {
            # Send the WM_SETTINGCHANGE message to all windows
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd,
        uint Msg,
        IntPtr wParam,
        string lParam,
        uint fuFlags,
        uint uTimeout,
        out IntPtr lpdwResult);
}
"@

            $HWND_BROADCAST = [IntPtr]0xffff
            $WM_SETTINGCHANGE = 0x1A
            $SMTO_ABORTIFHUNG = 0x2
            $timeout = 100

            # Send the broadcast message to all windows
            [Win32]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [IntPtr]::Zero, "ImmersiveColorSet", $SMTO_ABORTIFHUNG, $timeout, [ref]([IntPtr]::Zero))
        }
    } elseif ($action -eq "restart") {
        # Restart the Windows Explorer
        taskkill.exe /F /IM "explorer.exe"
        Start-Process "explorer.exe"
    }
}
function Invoke-WinUtilFeatureInstall {
    <#

    .SYNOPSIS
        Converts all the values from the tweaks.json and routes them to the appropriate function

    #>

    param(
        $CheckBox
    )

    $x = 0

    $CheckBox | ForEach-Object {
        if($sync.configs.feature.$psitem.feature) {
            Foreach( $feature in $sync.configs.feature.$psitem.feature ) {
                try {
                    Write-Host "Installing $feature"
                    Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart
                } catch {
                    if ($psitem.Exception.Message -like "*requires elevation*") {
                        Write-Warning "Unable to Install $feature due to permissions. Are you running as admin?"
                        $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Error" })
                    } else {

                        Write-Warning "Unable to Install $feature due to unhandled exception"
                        Write-Warning $psitem.Exception.StackTrace
                    }
                }
            }
        }
        if($sync.configs.feature.$psitem.InvokeScript) {
            Foreach( $script in $sync.configs.feature.$psitem.InvokeScript ) {
                try {
                    $Scriptblock = [scriptblock]::Create($script)

                    Write-Host "Running Script for $psitem"
                    Invoke-Command $scriptblock -ErrorAction stop
                } catch {
                    if ($psitem.Exception.Message -like "*requires elevation*") {
                        Write-Warning "Unable to Install $feature due to permissions. Are you running as admin?"
                        $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Error" })
                    } else {
                        $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Error" })
                        Write-Warning "Unable to Install $feature due to unhandled exception"
                        Write-Warning $psitem.Exception.StackTrace
                    }
                }
            }
        }
        $X++
        $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -value ($x/$CheckBox.Count) })
    }
}
function Invoke-WinUtilGPU {
    $gpuInfo = Get-CimInstance Win32_VideoController

    # GPUs to blacklist from using Demanding Theming
    $lowPowerGPUs = (
        "*NVIDIA GeForce*M*",
        "*NVIDIA GeForce*Laptop*",
        "*NVIDIA GeForce*GT*",
        "*AMD Radeon(TM)*",
        "*Intel(R) HD Graphics*",
        "*UHD*"

    )

    foreach ($gpu in $gpuInfo) {
        foreach ($gpuPattern in $lowPowerGPUs) {
            if ($gpu.Name -like $gpuPattern) {
                return $false
            }
        }
    }
    return $true
}
function Invoke-WinUtilInstallPSProfile {
    <#
    .SYNOPSIS
        Backs up your original profile then installs and applies the CTT PowerShell profile.
    #>

    Invoke-WPFRunspace -ArgumentList $PROFILE -DebugPreference $DebugPreference -ScriptBlock {
        # Remap the automatic built-in $PROFILE variable to the parameter named $PSProfile.
        param ($PSProfile)

        function Invoke-PSSetup {
            # Define the URL used to download Chris Titus Tech's PowerShell profile.
            $url = "https://raw.githubusercontent.com/tut-os/powershell-profile/main/Microsoft.PowerShell_profile.ps1"

            # Get the file hash for the user's current PowerShell profile.
            $OldHash = Get-FileHash $PSProfile -ErrorAction SilentlyContinue

            # Download Chris Titus Tech's PowerShell profile to the 'TEMP' folder.
            Invoke-RestMethod $url -OutFile "$env:TEMP/Microsoft.PowerShell_profile.ps1"

            # Get the file hash for Chris Titus Tech's PowerShell profile.
            $NewHash = Get-FileHash "$env:TEMP/Microsoft.PowerShell_profile.ps1"

            # Store the file hash of Chris Titus Tech's PowerShell profile.
            if (!(Test-Path "$PSProfile.hash")) {
                $NewHash.Hash | Out-File "$PSProfile.hash"
            }

            # Check if the new profile's hash doesn't match the old profile's hash.
            if ($NewHash.Hash -ne $OldHash.Hash) {
                # Check if oldprofile.ps1 exists and use it as a profile backup source.
                if (Test-Path "$env:USERPROFILE\oldprofile.ps1") {
                    Write-Host "===> Backup File Exists... <===" -ForegroundColor Yellow
                    Write-Host "===> Moving Backup File... <===" -ForegroundColor Yellow
                    Copy-Item "$env:USERPROFILE\oldprofile.ps1" "$PSProfile.bak"
                    Write-Host "===> Profile Backup: Done. <===" -ForegroundColor Yellow
                } else {
                    # If oldprofile.ps1 does not exist use $PSProfile as a profile backup source.
                    # Check if the profile backup file has not already been created on the disk.
                    if ((Test-Path $PSProfile) -and (-not (Test-Path "$PSProfile.bak"))) {
                        # Let the user know their PowerShell profile is being backed up.
                        Write-Host "===> Backing Up Profile... <===" -ForegroundColor Yellow

                        # Copy the user's current PowerShell profile to the backup file path.
                        Copy-Item -Path $PSProfile -Destination "$PSProfile.bak"

                        # Let the user know the profile backup has been completed successfully.
                        Write-Host "===> Profile Backup: Done. <===" -ForegroundColor Yellow
                    }
                }

                # Let the user know Chris Titus Tech's PowerShell profile is being installed.
                Write-Host "===> Installing Profile... <===" -ForegroundColor Yellow

                # Start a new hidden PowerShell instance because setup.ps1 does not work in runspaces.
                Start-Process -FilePath "pwsh" -ArgumentList "-ExecutionPolicy Bypass -NoProfile -Command `"Invoke-Expression (Invoke-WebRequest `'https://github.com/tut-os/powershell-profile/raw/main/setup.ps1`')`"" -WindowStyle Hidden -Wait

                # Let the user know Chris Titus Tech's PowerShell profile has been installed successfully.
                Write-Host "Profile has been installed. Please restart your shell to reflect the changes!" -ForegroundColor Magenta

                # Let the user know Chris Titus Tech's PowerShell profile has been setup successfully.
                Write-Host "===> Finished Profile Setup <===" -ForegroundColor Yellow
            } else {
                # Let the user know Chris Titus Tech's PowerShell profile is already fully up-to-date.
                Write-Host "Profile is up to date" -ForegroundColor Magenta
            }
        }

        # Check if PowerShell Core is currently installed as a program and is available as a command.
        if (Get-Command "pwsh" -ErrorAction SilentlyContinue) {
            # Check if the version of PowerShell Core currently in use is version 7 or higher.
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                # Invoke the PowerShell Profile setup script to install Chris Titus Tech's PowerShell Profile.
                Invoke-PSSetup
            } else {
                # Let the user know that PowerShell 7 is installed but is not currently in use.
                Write-Host "This profile requires Powershell 7, which is currently installed but not used!" -ForegroundColor Red

                # Load the necessary .NET library required to use Windows Forms to show dialog boxes.
                Add-Type -AssemblyName System.Windows.Forms

                # Display the message box asking if the user wants to install PowerShell 7 or not.
                $question = [System.Windows.Forms.MessageBox]::Show(
                    "Profile requires Powershell 7, which is currently installed but not used! Do you want to install the profile for Powershell 7?",
                    "Question",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )

                # Proceed with the installation and setup of the profile as the user pressed the 'Yes' button.
                if ($question -eq [System.Windows.Forms.DialogResult]::Yes) {
                    Invoke-PSSetup
                } else {
                    # Let the user know the setup of the profile will not proceed as they pressed the 'No' button.
                    Write-Host "Not proceeding with the profile setup!" -ForegroundColor Magenta
                }
            }
        } else {
            # Let the user know that the profile requires PowerShell Core but it is not currently installed.
            Write-Host "This profile requires Powershell Core, which is currently not installed!" -ForegroundColor Red
        }
    }
}
function Invoke-WinUtilpsProfile {
    <#
    .SYNOPSIS
        Installs & applies the CTT Powershell Profile
    #>
    Invoke-WPFRunspace -Argumentlist $PROFILE -DebugPreference $DebugPreference -ScriptBlock {
        param ( $psprofile)
        function Invoke-PSSetup {
            $url = "https://raw.githubusercontent.com/tut-os/powershell-profile/main/Microsoft.PowerShell_profile.ps1"
            $oldhash = Get-FileHash $psprofile -ErrorAction SilentlyContinue
            Invoke-RestMethod $url -OutFile "$env:temp/Microsoft.PowerShell_profile.ps1"
            $newhash = Get-FileHash "$env:temp/Microsoft.PowerShell_profile.ps1"
            if ($newhash.Hash -ne $oldhash.Hash) {
                    write-host "===> Installing Profile.. <===" -ForegroundColor Yellow
                    # Starting new hidden shell process bc setup does not work in a runspace
                    Start-Process -FilePath "pwsh" -ArgumentList "-ExecutionPolicy Bypass -NoProfile -Command `"Invoke-Expression (Invoke-WebRequest `'https://github.com/tut-os/powershell-profile/raw/main/setup.ps1`')`"" -WindowStyle Hidden -Wait
                    Write-Host "Profile has been installed. Please restart your shell to reflect changes!" -ForegroundColor Magenta
                    write-host "===> Finished <===" -ForegroundColor Yellow
            } else {
                Write-Host "Profile is up to date" -ForegroundColor Green
            }
        }

        if (Get-Command "pwsh" -ErrorAction SilentlyContinue) {
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                Invoke-PSSetup
            }
            else {
                write-host "Profile requires Powershell 7, which is currently installed but not used!" -ForegroundColor Red
                # Load the necessary assembly for Windows Forms
                Add-Type -AssemblyName System.Windows.Forms
                # Display the Yes/No message box
                $question = [System.Windows.Forms.MessageBox]::Show("Profile requires Powershell 7, which is currently installed but not used! Do you want to install Profile for Powershell 7?", "Question",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question)

                # Check the result
                if ($question -eq [System.Windows.Forms.DialogResult]::Yes) {
                    Invoke-PSSetup
                }
                else {
                    Write-Host "Not proceeding with the profile setup!"
                }
            }
        }
        else {
            write-host "Profile requires Powershell 7, which is not installed!" -ForegroundColor Red
        }
    }
}
function Invoke-WinUtilScript {
    <#

    .SYNOPSIS
        Invokes the provided scriptblock. Intended for things that can't be handled with the other functions.

    .PARAMETER Name
        The name of the scriptblock being invoked

    .PARAMETER scriptblock
        The scriptblock to be invoked

    .EXAMPLE
        $Scriptblock = [scriptblock]::Create({"Write-output 'Hello World'"})
        Invoke-WinUtilScript -ScriptBlock $scriptblock -Name "Hello World"

    #>
    param (
        $Name,
        [scriptblock]$scriptblock
    )

    try {
        Write-Host "Running Script for $name"
        Invoke-Command $scriptblock -ErrorAction Stop
    } catch [System.Management.Automation.CommandNotFoundException] {
        Write-Warning "The specified command was not found."
        Write-Warning $PSItem.Exception.message
    } catch [System.Management.Automation.RuntimeException] {
        Write-Warning "A runtime exception occurred."
        Write-Warning $PSItem.Exception.message
    } catch [System.Security.SecurityException] {
        Write-Warning "A security exception occurred."
        Write-Warning $PSItem.Exception.message
    } catch [System.UnauthorizedAccessException] {
        Write-Warning "Access denied. You do not have permission to perform this operation."
        Write-Warning $PSItem.Exception.message
    } catch {
        # Generic catch block to handle any other type of exception
        Write-Warning "Unable to run script for $name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }

}
Function Invoke-WinUtilSponsors {
    <#
    .SYNOPSIS
        Lists Sponsors from tut-os
    .DESCRIPTION
        Lists Sponsors from tut-os
    .EXAMPLE
        Invoke-WinUtilSponsors
    .NOTES
        This function is used to list sponsors from tut-os
    #>
    try {
        # Define the URL and headers
        $url = "https://github.com/sponsors/tut-os"
        $headers = @{
            "User-Agent" = "Chrome/58.0.3029.110"
        }

        # Fetch the webpage content
        try {
            $html = Invoke-RestMethod -Uri $url -Headers $headers
        } catch {
            Write-Output $_.Exception.Message
            exit
        }

        # Use regex to extract the content between "Current sponsors" and "Past sponsors"
        $currentSponsorsPattern = '(?s)(?<=Current sponsors).*?(?=Past sponsors)'
        $currentSponsorsHtml = [regex]::Match($html, $currentSponsorsPattern).Value

        # Use regex to extract the sponsor usernames from the alt attributes in the "Current Sponsors" section
        $sponsorPattern = '(?<=alt="@)[^"]+'
        $sponsors = [regex]::Matches($currentSponsorsHtml, $sponsorPattern) | ForEach-Object { $_.Value }

        # Exclude "tut-os" from the sponsors
        $sponsors = $sponsors | Where-Object { $_ -ne "tut-os" }

        # Return the sponsors
        return $sponsors
    } catch {
        Write-Error "An error occurred while fetching or processing the sponsors: $_"
        return $null
    }
}
function Invoke-WinUtilSSHServer {
    <#
    .SYNOPSIS
        Enables OpenSSH server to remote into your windows device
    #>

    # Get the latest version of OpenSSH Server
    $FeatureName = Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Server*" }

    # Install the OpenSSH Server feature if not already installed
    if ($FeatureName.State -ne "Installed") {
        Write-Host "Enabling OpenSSH Server"
        Add-WindowsCapability -Online -Name $FeatureName.Name
    }

    # Sets up the OpenSSH Server service
    Write-Host "Starting the services"
    Start-Service -Name sshd
    Set-Service -Name sshd -StartupType Automatic

    # Sets up the ssh-agent service
    Start-Service 'ssh-agent'
    Set-Service -Name 'ssh-agent' -StartupType 'Automatic'

    # Confirm the required services are running
    $SSHDaemonService = Get-Service -Name sshd
    $SSHAgentService = Get-Service -Name 'ssh-agent'

    if ($SSHDaemonService.Status -eq 'Running') {
        Write-Host "OpenSSH Server is running."
    } else {
        try {
            Write-Host "OpenSSH Server is not running. Attempting to restart..."
            Restart-Service -Name sshd -Force
            Write-Host "OpenSSH Server has been restarted successfully."
        } catch {
            Write-Host "Failed to restart OpenSSH Server: $_"
        }
    }
    if ($SSHAgentService.Status -eq 'Running') {
        Write-Host "ssh-agent is running."
    } else {
        try {
            Write-Host "ssh-agent is not running. Attempting to restart..."
            Restart-Service -Name sshd -Force
            Write-Host "ssh-agent has been restarted successfully."
        } catch {
            Write-Host "Failed to restart ssh-agent : $_"
        }
    }

    #Adding Firewall rule for port 22
    Write-Host "Setting up firewall rules"
    $firewallRule = (Get-NetFirewallRule -Name 'sshd').Enabled
    if ($firewallRule) {
        Write-Host "Firewall rule for OpenSSH Server (sshd) already exists."
    } else {
        New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
        Write-Host "Firewall rule for OpenSSH Server created and enabled."
    }

    # Check for the authorized_keys file
    $sshFolderPath = "$env:HOMEDRIVE\$env:HOMEPATH\.ssh"
    $authorizedKeysPath = "$sshFolderPath\authorized_keys"

    if (-not (Test-Path -Path $sshFolderPath)) {
        Write-Host "Creating ssh directory..."
        New-Item -Path $sshFolderPath -ItemType Directory -Force
    }

    if (-not (Test-Path -Path $authorizedKeysPath)) {
        Write-Host "Creating authorized_keys file..."
        New-Item -Path $authorizedKeysPath -ItemType File -Force
        Write-Host "authorized_keys file created at $authorizedKeysPath."
    } else {
        Write-Host "authorized_keys file already exists at $authorizedKeysPath."
    }
    Write-Host "OpenSSH server was successfully enabled."
    Write-Host "The config file can be located at C:\ProgramData\ssh\sshd_config "
    Write-Host "Add your public keys to this file -> $authorizedKeysPath"
}
function Invoke-WinutilThemeChange {
    <#
    .SYNOPSIS
        Toggles between light and dark themes for a Windows utility application.

    .DESCRIPTION
        This function toggles the theme of the user interface between 'Light' and 'Dark' modes,
        modifying various UI elements such as colors, margins, corner radii, font families, etc.
        If the '-init' switch is used, it initializes the theme based on the system's current dark mode setting.

    .PARAMETER init
        A switch parameter. If set to $true, the function initializes the theme based on the system?s current dark mode setting.

    .EXAMPLE
        Invoke-WinutilThemeChange
        # Toggles the theme between 'Light' and 'Dark'.

    .EXAMPLE
        Invoke-WinutilThemeChange -init
        # Initializes the theme based on the system's dark mode and applies the shared theme.
    #>
    param (
        [switch]$init = $false,
        [string]$theme
    )

    function Set-WinutilTheme {
        <#
        .SYNOPSIS
            Applies the specified theme to the application's user interface.

        .DESCRIPTION
            This internal function applies the given theme by setting the relevant properties
            like colors, font families, corner radii, etc., in the UI. It uses the
            'Set-ThemeResourceProperty' helper function to modify the application's resources.

        .PARAMETER currentTheme
            The name of the theme to be applied. Common values are "Light", "Dark", or "shared".
        #>
        param (
            [string]$currentTheme
        )

        function Set-ThemeResourceProperty {
            <#
            .SYNOPSIS
                Sets a specific UI property in the application's resources.

            .DESCRIPTION
                This helper function sets a property (e.g., color, margin, corner radius) in the
                application's resources, based on the provided type and value. It includes
                error handling to manage potential issues while setting a property.

            .PARAMETER Name
                The name of the resource property to modify (e.g., "MainBackgroundColor", "ButtonBackgroundMouseoverColor").

            .PARAMETER Value
                The value to assign to the resource property (e.g., "#FFFFFF" for a color).

            .PARAMETER Type
                The type of the resource, such as "ColorBrush", "CornerRadius", "GridLength", or "FontFamily".
            #>
            param($Name, $Value, $Type)
            try {
                # Set the resource property based on its type
                $sync.Form.Resources[$Name] = switch ($Type) {
                    "ColorBrush" { [Windows.Media.SolidColorBrush]::new($Value) }
                    "Color" {
                        # Convert hex string to RGB values
                        $hexColor = $Value.TrimStart("#")
                        $r = [Convert]::ToInt32($hexColor.Substring(0,2), 16)
                        $g = [Convert]::ToInt32($hexColor.Substring(2,2), 16)
                        $b = [Convert]::ToInt32($hexColor.Substring(4,2), 16)
                        [Windows.Media.Color]::FromRgb($r, $g, $b)
                    }
                    "CornerRadius" { [System.Windows.CornerRadius]::new($Value) }
                    "GridLength" { [System.Windows.GridLength]::new($Value) }
                    "Thickness" {
                        # Parse the Thickness value (supports 1, 2, or 4 inputs)
                        $values = $Value -split ","
                        switch ($values.Count) {
                            1 { [System.Windows.Thickness]::new([double]$values[0]) }
                            2 { [System.Windows.Thickness]::new([double]$values[0], [double]$values[1]) }
                            4 { [System.Windows.Thickness]::new([double]$values[0], [double]$values[1], [double]$values[2], [double]$values[3]) }
                        }
                    }
                    "FontFamily" { [Windows.Media.FontFamily]::new($Value) }
                    "Double" { [double]$Value }
                    default { $Value }
                }
            }
            catch {
                # Log a warning if there's an issue setting the property
                Write-Warning "Failed to set property $($Name): $_"
            }
        }

        # Retrieve all theme properties from the theme configuration
        $themeProperties = $sync.configs.themes.$currentTheme.PSObject.Properties
        foreach ($_ in $themeProperties) {
            # Apply properties that deal with colors
            if ($_.Name -like "*color*") {
                Set-ThemeResourceProperty -Name $_.Name -Value $_.Value -Type "ColorBrush"
                # For certain color properties, also set complementary values (e.g., BorderColor -> CBorderColor) This is required because e.g DropShadowEffect requires a <Color> and not a <SolidColorBrush> object
                if ($_.Name -in @("BorderColor", "ButtonBackgroundMouseoverColor")) {
                    Set-ThemeResourceProperty -Name "C$($_.Name)" -Value $_.Value -Type "Color"
                }
            }
            # Apply corner radius properties
            elseif ($_.Name -like "*Radius*") {
                Set-ThemeResourceProperty -Name $_.Name -Value $_.Value -Type "CornerRadius"
            }
            # Apply row height properties
            elseif ($_.Name -like "*RowHeight*") {
                Set-ThemeResourceProperty -Name $_.Name -Value $_.Value -Type "GridLength"
            }
            # Apply thickness or margin properties
            elseif (($_.Name -like "*Thickness*") -or ($_.Name -like "*margin")) {
                Set-ThemeResourceProperty -Name $_.Name -Value $_.Value -Type "Thickness"
            }
            # Apply font family properties
            elseif ($_.Name -like "*FontFamily*") {
                Set-ThemeResourceProperty -Name $_.Name -Value $_.Value -Type "FontFamily"
            }
            # Apply any other properties as doubles (numerical values)
            else {
                Set-ThemeResourceProperty -Name $_.Name -Value $_.Value -Type "Double"
            }
        }
    }

    $LightPreferencePath = "$env:LOCALAPPDATA\winutil\LightTheme.ini"
    $DarkPreferencePath = "$env:LOCALAPPDATA\winutil\DarkTheme.ini"

    if ($init) {
        Set-WinutilTheme -currentTheme "shared"
        if (Test-Path $LightPreferencePath) {
            $theme = "Light"
        }
        elseif (Test-Path $DarkPreferencePath) {
            $theme = "Dark"
        }
        else {
            $theme = "Auto"
        }
    }

    switch ($theme) {
        "Auto" {
            $systemUsesDarkMode = Get-WinUtilToggleStatus WPFToggleDarkMode
            if ($systemUsesDarkMode) {
                Set-WinutilTheme  -currentTheme "Dark"
            }
            else{
                Set-WinutilTheme  -currentTheme "Light"
            }


            $themeButtonIcon = [char]0xF08C
            Remove-Item $LightPreferencePath -Force -ErrorAction SilentlyContinue
            Remove-Item $DarkPreferencePath -Force -ErrorAction SilentlyContinue
        }
        "Dark" {
            Set-WinutilTheme  -currentTheme $theme
            $themeButtonIcon = [char]0xE708
            $null = New-Item $DarkPreferencePath -Force
            Remove-Item $LightPreferencePath -Force -ErrorAction SilentlyContinue
           }
        "Light" {
            Set-WinutilTheme  -currentTheme $theme
            $themeButtonIcon = [char]0xE706
            $null = New-Item $LightPreferencePath -Force
            Remove-Item $DarkPreferencePath -Force -ErrorAction SilentlyContinue
        }
    }

    # Update the theme selector button with the appropriate icon
    $ThemeButton = $sync.Form.FindName("ThemeButton")
    $ThemeButton.Content = [string]$themeButtonIcon
}
function Invoke-WinUtilTweaks {
    <#

    .SYNOPSIS
        Invokes the function associated with each provided checkbox

    .PARAMETER CheckBox
        The checkbox to invoke

    .PARAMETER undo
        Indicates whether to undo the operation contained in the checkbox

    .PARAMETER KeepServiceStartup
        Indicates whether to override the startup of a service with the one given from WinUtil,
        or to keep the startup of said service, if it was changed by the user, or another program, from its default value.
    #>

    param(
        $CheckBox,
        $undo = $false,
        $KeepServiceStartup = $true
    )

    if ($Checkbox -contains "Toggle") {
        $CheckBox = $sync.configs.tweaks.$CheckBox
    }

    Write-Debug "Tweaks: $($CheckBox)"
    if($undo) {
        $Values = @{
            Registry = "OriginalValue"
            ScheduledTask = "OriginalState"
            Service = "OriginalType"
            ScriptType = "UndoScript"
        }

    } else {
        $Values = @{
            Registry = "Value"
            ScheduledTask = "State"
            Service = "StartupType"
            OriginalService = "OriginalType"
            ScriptType = "InvokeScript"
        }
    }
    if($sync.configs.tweaks.$CheckBox.ScheduledTask) {
        $sync.configs.tweaks.$CheckBox.ScheduledTask | ForEach-Object {
            Write-Debug "$($psitem.Name) and state is $($psitem.$($values.ScheduledTask))"
            Set-WinUtilScheduledTask -Name $psitem.Name -State $psitem.$($values.ScheduledTask)
        }
    }
    if($sync.configs.tweaks.$CheckBox.service) {
        Write-Debug "KeepServiceStartup is $KeepServiceStartup"
        $sync.configs.tweaks.$CheckBox.service | ForEach-Object {
            $changeservice = $true

        # The check for !($undo) is required, without it the script will throw an error for accessing unavailable memeber, which's the 'OriginalService' Property
            if($KeepServiceStartup -AND !($undo)) {
                try {
                    # Check if the service exists
                    $service = Get-Service -Name $psitem.Name -ErrorAction Stop
                    if(!($service.StartType.ToString() -eq $psitem.$($values.OriginalService))) {
                        Write-Debug "Service $($service.Name) was changed in the past to $($service.StartType.ToString()) from it's original type of $($psitem.$($values.OriginalService)), will not change it to $($psitem.$($values.service))"
                        $changeservice = $false
                    }
                } catch [System.ServiceProcess.ServiceNotFoundException] {
                    Write-Warning "Service $($psitem.Name) was not found"
                }
            }

            if($changeservice) {
                Write-Debug "$($psitem.Name) and state is $($psitem.$($values.service))"
                Set-WinUtilService -Name $psitem.Name -StartupType $psitem.$($values.Service)
            }
        }
    }
    if($sync.configs.tweaks.$CheckBox.registry) {
        $sync.configs.tweaks.$CheckBox.registry | ForEach-Object {
            Write-Debug "$($psitem.Name) and state is $($psitem.$($values.registry))"
            if (($psitem.Path -imatch "hku") -and !(Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
                $null = (New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS)
                if (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue) {
                    Write-Debug "HKU drive created successfully"
                } else {
                    Write-Debug "Failed to create HKU drive"
                }
            }
            Set-WinUtilRegistry -Name $psitem.Name -Path $psitem.Path -Type $psitem.Type -Value $psitem.$($values.registry)
        }
    }
    if($sync.configs.tweaks.$CheckBox.$($values.ScriptType)) {
        $sync.configs.tweaks.$CheckBox.$($values.ScriptType) | ForEach-Object {
            Write-Debug "$($psitem) and state is $($psitem.$($values.ScriptType))"
            $Scriptblock = [scriptblock]::Create($psitem)
            Invoke-WinUtilScript -ScriptBlock $scriptblock -Name $CheckBox
        }
    }

    if(!$undo) {
        if($sync.configs.tweaks.$CheckBox.appx) {
            $sync.configs.tweaks.$CheckBox.appx | ForEach-Object {
                Write-Debug "UNDO $($psitem.Name)"
                Remove-WinUtilAPPX -Name $psitem
            }
        }

    }
}
function Invoke-WinUtilUninstallPSProfile {
    <#
    .SYNOPSIS
        # Uninstalls the CTT PowerShell profile then restores the original profile.
    #>

    Invoke-WPFRunspace -ArgumentList $PROFILE -DebugPreference $DebugPreference -ScriptBlock {
        # Remap the automatic built-in $PROFILE variable to the parameter named $PSProfile.
        param ($PSProfile)

        # Helper function used to uninstall a specific Nerd Fonts font package.
        function Uninstall-NerdFonts {
            # Define the parameters block for the Uninstall-NerdFonts function.
            param (
                [string]$FontsPath = "$env:LOCALAPPDATA\Microsoft\Windows\Fonts",
                [string]$FontFamilyName = "CaskaydiaCoveNerdFont"
            )

            # Get the list of installed fonts as specified by the FontFamilyName parameter.
            $Fonts = Get-ChildItem $FontsPath -Recurse -Filter "*.ttf" | Where-Object { $_.Name -match $FontFamilyName }

            # Check if the specified fonts are currently installed on the system.
            if ($Fonts) {
                # Let the user know that the Nerd Fonts are currently being uninstalled.
                Write-Host "===> Uninstalling: Nerd Fonts... <===" -ForegroundColor Yellow

                # Loop over the font files and remove each installed font file one-by-one.
                $Fonts | ForEach-Object {
                    # Check if the font file exists on the disk before attempting to remove it.
                    if (Test-Path "$($_.FullName)") {
                        # Remove the found font files from the disk; uninstalling the font.
                        Remove-Item "$($_.FullName)"
                    }
                }
            }

            # Let the user know that the Nerd Fonts package has been uninstalled from the system.
            if (-not $Fonts) {
                Write-Host "===> Successfully Uninstalled: Nerd Fonts. <===" -ForegroundColor Yellow
            }
        }

        # Check if Chris Titus Tech's PowerShell profile is currently available in the PowerShell profile folder.
        if (Test-Path $PSProfile -PathType Leaf) {
            # Set the GitHub repo path used for looking up the name of Chris Titus Tech's powershell-profile repo.
            $GitHubRepoPath = "tut-os/powershell-profile"

            # Get the unique identifier used to test for the presence of Chris Titus Tech's PowerShell profile.
            $PSProfileIdentifier = (Invoke-RestMethod "https://api.github.com/repos/$GitHubRepoPath").full_name

            # Check if Chris Titus Tech's PowerShell profile is currently installed in the PowerShell profile folder.
            if ((Get-Content $PSProfile) -match $PSProfileIdentifier) {
                # Attempt to uninstall Chris Titus Tech's PowerShell profile from the PowerShell profile folder.
                try {
                    # Get the content of the backup PowerShell profile and store it in-memory.
                    $PSProfileContent = Get-Content "$PSProfile.bak"

                    # Store the flag used to check if OhMyPosh is in use by the backup PowerShell profile.
                    $OhMyPoshInUse = $PSProfileContent -match "oh-my-posh init"

                    # Check if OhMyPosh is not currently in use by the backup PowerShell profile.
                    if (-not $OhMyPoshInUse) {
                        # If OhMyPosh is currently installed attempt to uninstall it from the system.
                        if (Get-Command oh-my-posh -ErrorAction SilentlyContinue) {
                            # Let the user know that OhMyPosh is currently being uninstalled from their system.
                            Write-Host "===> Uninstalling: OhMyPosh... <===" -ForegroundColor Yellow

                            # Attempt to uninstall OhMyPosh from the system with the WinGet package manager.
                            winget uninstall -e --id JanDeDobbeleer.OhMyPosh
                        }
                    } else {
                        # Let the user know that the uninstallation of OhMyPosh has been skipped because it is in use.
                        Write-Host "===> Skipped Uninstall: OhMyPosh In-Use. <===" -ForegroundColor Yellow
                    }
                } catch {
                    # Let the user know that an error was encountered when uninstalling OhMyPosh.
                    Write-Host "Failed to uninstall OhMyPosh. Error: $_" -ForegroundColor Red
                }

                # Attempt to uninstall the specified Nerd Fonts package from the system.
                try {
                    # Specify the directory that the specified font package will be uninstalled from.
                    [string]$FontsPath = "$env:LOCALAPPDATA\Microsoft\Windows\Fonts"

                    # Specify the name of the font package that is to be uninstalled from the system.
                    [string]$FontFamilyName = "CaskaydiaCoveNerdFont"

                    # Call the function used to uninstall the specified Nerd Fonts package from the system.
                    Uninstall-NerdFonts -FontsPath $FontsPath -FontFamilyName $FontFamilyName
                } catch {
                    # Let the user know that an error was encountered when uninstalling Nerd Fonts.
                    Write-Host "Failed to uninstall Nerd Fonts. Error: $_" -ForegroundColor Red
                }

                # Attempt to uninstall the Terminal-Icons PowerShell module from the system.
                try {
                    # Get the content of the backup PowerShell profile and store it in-memory.
                    $PSProfileContent = Get-Content "$PSProfile.bak"

                    # Store the flag used to check if Terminal-Icons is in use by the backup PowerShell profile.
                    $TerminalIconsInUse = $PSProfileContent -match "Import-Module" -and $PSProfileContent -match "Terminal-Icons"

                    # Check if Terminal-Icons is not currently in use by the backup PowerShell profile.
                    if (-not $TerminalIconsInUse) {
                        # If Terminal-Icons is currently installed attempt to uninstall it from the system.
                        if (Get-Module -ListAvailable Terminal-Icons) {
                            # Let the user know that Terminal-Icons is currently being uninstalled from their system.
                            Write-Host "===> Uninstalling: Terminal-Icons... <===" -ForegroundColor Yellow

                            # Attempt to uninstall Terminal-Icons from the system with Uninstall-Module.
                            Uninstall-Module -Name Terminal-Icons
                        }
                    } else {
                        # Let the user know that the uninstallation of Terminal-Icons has been skipped because it is in use.
                        Write-Host "===> Skipped Uninstall: Terminal-Icons In-Use. <===" -ForegroundColor Yellow
                    }
                } catch {
                    # Let the user know that an error was encountered when uninstalling Terminal-Icons.
                    Write-Host "Failed to uninstall Terminal-Icons. Error: $_" -ForegroundColor Red
                }

                # Attempt to uninstall the Zoxide application from the system.
                try {
                    # Get the content of the backup PowerShell profile and store it in-memory.
                    $PSProfileContent = Get-Content "$PSProfile.bak"

                    # Store the flag used to check if Zoxide is in use by the backup PowerShell profile.
                    $ZoxideInUse = $PSProfileContent -match "zoxide init"

                    # Check if Zoxide is not currently in use by the backup PowerShell profile.
                    if (-not $ZoxideInUse) {
                        # If Zoxide is currently installed attempt to uninstall it from the system.
                        if (Get-Command zoxide -ErrorAction SilentlyContinue) {
                            # Let the user know that Zoxide is currently being uninstalled from their system.
                            Write-Host "===> Uninstalling: Zoxide... <===" -ForegroundColor Yellow

                            # Attempt to uninstall Zoxide from the system with the WinGet package manager.
                            winget uninstall -e --id ajeetdsouza.zoxide
                        }
                    } else {
                        # Let the user know that the uninstallation of Zoxide been skipped because it is in use.
                        Write-Host "===> Skipped Uninstall: Zoxide In-Use. <===" -ForegroundColor Yellow
                    }
                } catch {
                    # Let the user know that an error was encountered when uninstalling Zoxide.
                    Write-Host "Failed to uninstall Zoxide. Error: $_" -ForegroundColor Red
                }

                # Attempt to uninstall the CTT PowerShell profile from the system.
                try {
                    # Try and remove the CTT PowerShell Profile file from the disk with Remove-Item.
                    Remove-Item $PSProfile

                    # Let the user know that the CTT PowerShell profile has been uninstalled from the system.
                    Write-Host "Profile has been uninstalled. Please restart your shell to reflect the changes!" -ForegroundColor Magenta
                } catch {
                    # Let the user know that an error was encountered when uninstalling the profile.
                    Write-Host "Failed to uninstall profile. Error: $_" -ForegroundColor Red
                }

                # Attempt to move the user's original PowerShell profile backup back to its original location.
                try {
                    # Check if the backup PowerShell profile exists before attempting to restore the backup.
                    if (Test-Path "$PSProfile.bak") {
                        # Restore the backup PowerShell profile and move it to its original location.
                        Move-Item "$PSProfile.bak" $PSProfile

                        # Let the user know that their PowerShell profile backup has been successfully restored.
                        Write-Host "===> Restored Profile Backup. <===" -ForegroundColor Yellow
                    }
                } catch {
                    # Let the user know that an error was encountered when restoring the profile backup.
                    Write-Host "Failed to restore profile backup. Error: $_" -ForegroundColor Red
                }

                # Silently cleanup the oldprofile.ps1 file that was created when the CTT PowerShell profile was installed.
                Remove-Item "$env:USERPROFILE\oldprofile.ps1" | Out-Null
            } else {
                # Let the user know that the CTT PowerShell profile is not installed and that the uninstallation was skipped.
                Write-Host "===> Chris Titus Tech's PowerShell Profile Not Found. Skipped Uninstallation. <===" -ForegroundColor Magenta
            }
        } else {
            # Let the user know that no PowerShell profile was found and that the uninstallation was skipped.
            Write-Host "===> No PowerShell Profile Found. Skipped Uninstallation. <===" -ForegroundColor Magenta
        }
    }
}
function Remove-WinUtilAPPX {
    <#

    .SYNOPSIS
        Removes all APPX packages that match the given name

    .PARAMETER Name
        The name of the APPX package to remove

    .EXAMPLE
        Remove-WinUtilAPPX -Name "Microsoft.Microsoft3DViewer"

    #>
    param (
        $Name
    )

    try {
        Write-Host "Removing $Name"
        Get-AppxPackage "*$Name*" | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$Name*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    } catch [System.Exception] {
        if ($psitem.Exception.Message -like "*The requested operation requires elevation*") {
            Write-Warning "Unable to uninstall $name due to a Security Exception"
        } else {
            Write-Warning "Unable to uninstall $name due to unhandled exception"
            Write-Warning $psitem.Exception.StackTrace
        }
    } catch {
        Write-Warning "Unable to uninstall $name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Set-WinUtilDNS {
    <#

    .SYNOPSIS
        Sets the DNS of all interfaces that are in the "Up" state. It will lookup the values from the DNS.Json file

    .PARAMETER DNSProvider
        The DNS provider to set the DNS server to

    .EXAMPLE
        Set-WinUtilDNS -DNSProvider "google"

    #>
    param($DNSProvider)
    if($DNSProvider -eq "Default") {return}
    try {
        $Adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        Write-Host "Ensuring DNS is set to $DNSProvider on the following interfaces"
        Write-Host $($Adapters | Out-String)

        Foreach ($Adapter in $Adapters) {
            if($DNSProvider -eq "DHCP") {
                Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ResetServerAddresses
            } else {
                Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ServerAddresses ("$($sync.configs.dns.$DNSProvider.Primary)", "$($sync.configs.dns.$DNSProvider.Secondary)")
                Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ServerAddresses ("$($sync.configs.dns.$DNSProvider.Primary6)", "$($sync.configs.dns.$DNSProvider.Secondary6)")
            }
        }
    } catch {
        Write-Warning "Unable to set DNS Provider due to an unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Set-WinUtilProgressbar{
    <#
    .SYNOPSIS
        This function is used to Update the Progress Bar displayed in the winutil GUI.
        It will be automatically hidden if the user clicks something and no process is running
    .PARAMETER Label
        The Text to be overlayed onto the Progress Bar
    .PARAMETER PERCENT
        The percentage of the Progress Bar that should be filled (0-100)
    .PARAMETER Hide
        If provided, the Progress Bar and the label will be hidden
    #>
    param(
        [string]$Label,
        [ValidateRange(0,100)]
        [int]$Percent,
        $Hide
    )
    if ($hide) {
        $sync.form.Dispatcher.Invoke([action]{$sync.ProgressBarLabel.Visibility = "Collapsed"})
        $sync.form.Dispatcher.Invoke([action]{$sync.ProgressBar.Visibility = "Collapsed"})
    } else {
        $sync.form.Dispatcher.Invoke([action]{$sync.ProgressBarLabel.Visibility = "Visible"})
        $sync.form.Dispatcher.Invoke([action]{$sync.ProgressBar.Visibility = "Visible"})
    }
    $sync.form.Dispatcher.Invoke([action]{$sync.ProgressBarLabel.Content.Text = $label})
    $sync.form.Dispatcher.Invoke([action]{$sync.ProgressBarLabel.Content.ToolTip = $label})
    $sync.form.Dispatcher.Invoke([action]{ $sync.ProgressBar.Value = $percent})

}
function Set-WinUtilRegistry {
    <#

    .SYNOPSIS
        Modifies the registry based on the given inputs

    .PARAMETER Name
        The name of the key to modify

    .PARAMETER Path
        The path to the key

    .PARAMETER Type
        The type of value to set the key to

    .PARAMETER Value
        The value to set the key to

    .EXAMPLE
        Set-WinUtilRegistry -Name "PublishUserActivities" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Type "DWord" -Value "0"

    #>
    param (
        $Name,
        $Path,
        $Type,
        $Value
    )

    try {
        if(!(Test-Path 'HKU:\')) {New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS}

        If (!(Test-Path $Path)) {
            Write-Host "$Path was not found, Creating..."
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }

        if ($Value -ne "<RemoveEntry>") {
            Write-Host "Set $Path\$Name to $Value"
            Set-ItemProperty -Path $Path -Name $Name -Type $Type -Value $Value -Force -ErrorAction Stop | Out-Null
        }
        else{
            Write-Host "Remove $Path\$Name"
            Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop | Out-Null
        }
    } catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Value due to a Security Exception"
    } catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    } catch [System.UnauthorizedAccessException] {
       Write-Warning $psitem.Exception.Message
    } catch {
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Set-WinUtilScheduledTask {
    <#

    .SYNOPSIS
        Enables/Disables the provided Scheduled Task

    .PARAMETER Name
        The path to the Scheduled Task

    .PARAMETER State
        The State to set the Task to

    .EXAMPLE
        Set-WinUtilScheduledTask -Name "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" -State "Disabled"

    #>
    param (
        $Name,
        $State
    )

    try {
        if($State -eq "Disabled") {
            Write-Host "Disabling Scheduled Task $Name"
            Disable-ScheduledTask -TaskName $Name -ErrorAction Stop
        }
        if($State -eq "Enabled") {
            Write-Host "Enabling Scheduled Task $Name"
            Enable-ScheduledTask -TaskName $Name -ErrorAction Stop
        }
    } catch [System.Exception] {
        if($psitem.Exception.Message -like "*The system cannot find the file specified*") {
            Write-Warning "Scheduled Task $name was not Found"
        } else {
            Write-Warning "Unable to set $Name due to unhandled exception"
            Write-Warning $psitem.Exception.Message
        }
    } catch {
        Write-Warning "Unable to run script for $name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
Function Set-WinUtilService {
    <#

    .SYNOPSIS
        Changes the startup type of the given service

    .PARAMETER Name
        The name of the service to modify

    .PARAMETER StartupType
        The startup type to set the service to

    .EXAMPLE
        Set-WinUtilService -Name "HomeGroupListener" -StartupType "Manual"

    #>
    param (
        $Name,
        $StartupType
    )
    try {
        Write-Host "Setting Service $Name to $StartupType"

        # Check if the service exists
        $service = Get-Service -Name $Name -ErrorAction Stop

        # Service exists, proceed with changing properties
        $service | Set-Service -StartupType $StartupType -ErrorAction Stop
    } catch [System.ServiceProcess.ServiceNotFoundException] {
        Write-Warning "Service $Name was not found"
    } catch {
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $_.Exception.Message
    }

}
function Set-WinUtilTaskbaritem {
    <#

    .SYNOPSIS
        Modifies the Taskbaritem of the WPF Form

    .PARAMETER value
        Value can be between 0 and 1, 0 being no progress done yet and 1 being fully completed
        Value does not affect item without setting the state to 'Normal', 'Error' or 'Paused'
        Set-WinUtilTaskbaritem -value 0.5

    .PARAMETER state
        State can be 'None' > No progress, 'Indeterminate' > inf. loading gray, 'Normal' > Gray, 'Error' > Red, 'Paused' > Yellow
        no value needed:
        - Set-WinUtilTaskbaritem -state "None"
        - Set-WinUtilTaskbaritem -state "Indeterminate"
        value needed:
        - Set-WinUtilTaskbaritem -state "Error"
        - Set-WinUtilTaskbaritem -state "Normal"
        - Set-WinUtilTaskbaritem -state "Paused"

    .PARAMETER overlay
        Overlay icon to display on the taskbar item, there are the presets 'None', 'logo' and 'checkmark' or you can specify a path/link to an image file.
        CTT logo preset:
        - Set-WinUtilTaskbaritem -overlay "logo"
        Checkmark preset:
        - Set-WinUtilTaskbaritem -overlay "checkmark"
        Warning preset:
        - Set-WinUtilTaskbaritem -overlay "warning"
        No overlay:
        - Set-WinUtilTaskbaritem -overlay "None"
        Custom icon (needs to be supported by WPF):
        - Set-WinUtilTaskbaritem -overlay "C:\path\to\icon.png"

    .PARAMETER description
        Description to display on the taskbar item preview
        Set-WinUtilTaskbaritem -description "This is a description"
    #>
    param (
        [string]$state,
        [double]$value,
        [string]$overlay,
        [string]$description
    )

    if ($value) {
        $sync["Form"].taskbarItemInfo.ProgressValue = $value
    }

    if ($state) {
        switch ($state) {
            'None' { $sync["Form"].taskbarItemInfo.ProgressState = "None" }
            'Indeterminate' { $sync["Form"].taskbarItemInfo.ProgressState = "Indeterminate" }
            'Normal' { $sync["Form"].taskbarItemInfo.ProgressState = "Normal" }
            'Error' { $sync["Form"].taskbarItemInfo.ProgressState = "Error" }
            'Paused' { $sync["Form"].taskbarItemInfo.ProgressState = "Paused" }
            default { throw "[Set-WinUtilTaskbarItem] Invalid state" }
        }
    }

    if ($overlay) {
        switch ($overlay) {
            'logo' {
                $sync["Form"].taskbarItemInfo.Overlay = $sync["logorender"]
            }
            'checkmark' {
                $sync["Form"].taskbarItemInfo.Overlay = $sync["checkmarkrender"]
            }
            'warning' {
                $sync["Form"].taskbarItemInfo.Overlay = $sync["warningrender"]
            }
            'None' {
                $sync["Form"].taskbarItemInfo.Overlay = $null
            }
            default {
                if (Test-Path $overlay) {
                    $sync["Form"].taskbarItemInfo.Overlay = $overlay
                }
            }
        }
    }

    if ($description) {
        $sync["Form"].taskbarItemInfo.Description = $description
    }
}
function Show-CustomDialog {
    <#
    .SYNOPSIS
    Displays a custom dialog box with an image, heading, message, and an OK button.

    .DESCRIPTION
    This function creates a custom dialog box with the specified message and additional elements such as an image, heading, and an OK button. The dialog box is designed with a green border, rounded corners, and a black background.

    .PARAMETER Title
    The Title to use for the dialog window's Title Bar, this will not be visible by the user, as window styling is set to None.

    .PARAMETER Message
    The message to be displayed in the dialog box.

    .PARAMETER Width
    The width of the custom dialog window.

    .PARAMETER Height
    The height of the custom dialog window.

    .PARAMETER FontSize
    The Font Size of message shown inside custom dialog window.

    .PARAMETER HeaderFontSize
    The Font Size for the Header of custom dialog window.

    .PARAMETER LogoSize
    The Size of the Logo used inside the custom dialog window.

    .PARAMETER ForegroundColor
    The Foreground Color of dialog window title & message.

    .PARAMETER BackgroundColor
    The Background Color of dialog window.

    .PARAMETER BorderColor
    The Color for dialog window border.

    .PARAMETER ButtonBackgroundColor
    The Background Color for Buttons in dialog window.

    .PARAMETER ButtonForegroundColor
    The Foreground Color for Buttons in dialog window.

    .PARAMETER ShadowColor
    The Color used when creating the Drop-down Shadow effect for dialog window.

    .PARAMETER LogoColor
    The Color of WinUtil Text found next to WinUtil's Logo inside dialog window.

    .PARAMETER LinkForegroundColor
    The Foreground Color for Links inside dialog window.

    .PARAMETER LinkHoverForegroundColor
    The Foreground Color for Links when the mouse pointer hovers over them inside dialog window.

    .PARAMETER EnableScroll
    A flag indicating whether to enable scrolling if the content exceeds the window size.

    .EXAMPLE
    Show-CustomDialog -Title "My Custom Dialog" -Message "This is a custom dialog with a message and an image above." -Width 300 -Height 200

    Makes a new Custom Dialog with the title 'My Custom Dialog' and a message 'This is a custom dialog with a message and an image above.', with dimensions of 300 by 200 pixels.
    Other styling options are grabbed from '$sync.Form.Resources' global variable.

    .EXAMPLE
    $foregroundColor = New-Object System.Windows.Media.SolidColorBrush("#0088e5")
    $backgroundColor = New-Object System.Windows.Media.SolidColorBrush("#1e1e1e")
    $linkForegroundColor = New-Object System.Windows.Media.SolidColorBrush("#0088e5")
    $linkHoverForegroundColor = New-Object System.Windows.Media.SolidColorBrush("#005289")
    Show-CustomDialog -Title "My Custom Dialog" -Message "This is a custom dialog with a message and an image above." -Width 300 -Height 200 -ForegroundColor $foregroundColor -BackgroundColor $backgroundColor -LinkForegroundColor $linkForegroundColor -LinkHoverForegroundColor $linkHoverForegroundColor

    Makes a new Custom Dialog with the title 'My Custom Dialog' and a message 'This is a custom dialog with a message and an image above.', with dimensions of 300 by 200 pixels, with a link foreground (and general foreground) colors of '#0088e5', background color of '#1e1e1e', and Link Color on Hover of '005289', all of which are in Hexadecimal (the '#' Symbol is required by SolidColorBrush Constructor).
    Other styling options are grabbed from '$sync.Form.Resources' global variable.

    #>
    param(
        [string]$Title,
        [string]$Message,
        [int]$Width = $sync.Form.Resources.CustomDialogWidth,
        [int]$Height = $sync.Form.Resources.CustomDialogHeight,

        [System.Windows.Media.FontFamily]$FontFamily = $sync.Form.Resources.FontFamily,
        [int]$FontSize = $sync.Form.Resources.CustomDialogFontSize,
        [int]$HeaderFontSize = $sync.Form.Resources.CustomDialogFontSizeHeader,
        [int]$LogoSize = $sync.Form.Resources.CustomDialogLogoSize,

        [System.Windows.Media.Color]$ShadowColor = "#AAAAAAAA",
        [System.Windows.Media.SolidColorBrush]$LogoColor = $sync.Form.Resources.LabelboxForegroundColor,
        [System.Windows.Media.SolidColorBrush]$BorderColor = $sync.Form.Resources.BorderColor,
        [System.Windows.Media.SolidColorBrush]$ForegroundColor = $sync.Form.Resources.MainForegroundColor,
        [System.Windows.Media.SolidColorBrush]$BackgroundColor = $sync.Form.Resources.MainBackgroundColor,
        [System.Windows.Media.SolidColorBrush]$ButtonForegroundColor = $sync.Form.Resources.ButtonInstallForegroundColor,
        [System.Windows.Media.SolidColorBrush]$ButtonBackgroundColor = $sync.Form.Resources.ButtonInstallBackgroundColor,
        [System.Windows.Media.SolidColorBrush]$LinkForegroundColor = $sync.Form.Resources.LinkForegroundColor,
        [System.Windows.Media.SolidColorBrush]$LinkHoverForegroundColor = $sync.Form.Resources.LinkHoverForegroundColor,

        [bool]$EnableScroll = $false
    )

    # Create a custom dialog window
    $dialog = New-Object Windows.Window
    $dialog.Title = $Title
    $dialog.Height = $Height
    $dialog.Width = $Width
    $dialog.Margin = New-Object Windows.Thickness(10)  # Add margin to the entire dialog box
    $dialog.WindowStyle = [Windows.WindowStyle]::None  # Remove title bar and window controls
    $dialog.ResizeMode = [Windows.ResizeMode]::NoResize  # Disable resizing
    $dialog.WindowStartupLocation = [Windows.WindowStartupLocation]::CenterScreen  # Center the window
    $dialog.Foreground = $ForegroundColor
    $dialog.Background = $BackgroundColor
    $dialog.FontFamily = $FontFamily
    $dialog.FontSize = $FontSize

    # Create a Border for the green edge with rounded corners
    $border = New-Object Windows.Controls.Border
    $border.BorderBrush = $BorderColor
    $border.BorderThickness = New-Object Windows.Thickness(1)  # Adjust border thickness as needed
    $border.CornerRadius = New-Object Windows.CornerRadius(10)  # Adjust the radius for rounded corners

    # Create a drop shadow effect
    $dropShadow = New-Object Windows.Media.Effects.DropShadowEffect
    $dropShadow.Color = $shadowColor
    $dropShadow.Direction = 270
    $dropShadow.ShadowDepth = 5
    $dropShadow.BlurRadius = 10

    # Apply drop shadow effect to the border
    $dialog.Effect = $dropShadow

    $dialog.Content = $border

    # Create a grid for layout inside the Border
    $grid = New-Object Windows.Controls.Grid
    $border.Child = $grid

    # Uncomment the following line to show gridlines
    #$grid.ShowGridLines = $true

    # Add the following line to set the background color of the grid
    $grid.Background = [Windows.Media.Brushes]::Transparent
    # Add the following line to make the Grid stretch
    $grid.HorizontalAlignment = [Windows.HorizontalAlignment]::Stretch
    $grid.VerticalAlignment = [Windows.VerticalAlignment]::Stretch

    # Add the following line to make the Border stretch
    $border.HorizontalAlignment = [Windows.HorizontalAlignment]::Stretch
    $border.VerticalAlignment = [Windows.VerticalAlignment]::Stretch

    # Set up Row Definitions
    $row0 = New-Object Windows.Controls.RowDefinition
    $row0.Height = [Windows.GridLength]::Auto

    $row1 = New-Object Windows.Controls.RowDefinition
    $row1.Height = [Windows.GridLength]::new(1, [Windows.GridUnitType]::Star)

    $row2 = New-Object Windows.Controls.RowDefinition
    $row2.Height = [Windows.GridLength]::Auto

    # Add Row Definitions to Grid
    $grid.RowDefinitions.Add($row0)
    $grid.RowDefinitions.Add($row1)
    $grid.RowDefinitions.Add($row2)

    # Add StackPanel for horizontal layout with margins
    $stackPanel = New-Object Windows.Controls.StackPanel
    $stackPanel.Margin = New-Object Windows.Thickness(10)  # Add margins around the stack panel
    $stackPanel.Orientation = [Windows.Controls.Orientation]::Horizontal
    $stackPanel.HorizontalAlignment = [Windows.HorizontalAlignment]::Left  # Align to the left
    $stackPanel.VerticalAlignment = [Windows.VerticalAlignment]::Top  # Align to the top

    $grid.Children.Add($stackPanel)
    [Windows.Controls.Grid]::SetRow($stackPanel, 0)  # Set the row to the second row (0-based index)

    # Add SVG path to the stack panel
    $stackPanel.Children.Add((Invoke-WinUtilAssets -Type "logo" -Size $LogoSize))

    # Add "Winutil" text
    $winutilTextBlock = New-Object Windows.Controls.TextBlock
    $winutilTextBlock.Text = "Winutil"
    $winutilTextBlock.FontSize = $HeaderFontSize
    $winutilTextBlock.Foreground = $LogoColor
    $winutilTextBlock.Margin = New-Object Windows.Thickness(10, 10, 10, 5)  # Add margins around the text block
    $stackPanel.Children.Add($winutilTextBlock)
    # Add TextBlock for information with text wrapping and margins
    $messageTextBlock = New-Object Windows.Controls.TextBlock
    $messageTextBlock.FontSize = $FontSize
    $messageTextBlock.TextWrapping = [Windows.TextWrapping]::Wrap  # Enable text wrapping
    $messageTextBlock.HorizontalAlignment = [Windows.HorizontalAlignment]::Left
    $messageTextBlock.VerticalAlignment = [Windows.VerticalAlignment]::Top
    $messageTextBlock.Margin = New-Object Windows.Thickness(10)  # Add margins around the text block

    # Define the Regex to find hyperlinks formatted as HTML <a> tags
    $regex = [regex]::new('<a href="([^"]+)">([^<]+)</a>')
    $lastPos = 0

    # Iterate through each match and add regular text and hyperlinks
    foreach ($match in $regex.Matches($Message)) {
        # Add the text before the hyperlink, if any
        $textBefore = $Message.Substring($lastPos, $match.Index - $lastPos)
        if ($textBefore.Length -gt 0) {
            $messageTextBlock.Inlines.Add((New-Object Windows.Documents.Run($textBefore)))
        }

        # Create and add the hyperlink
        $hyperlink = New-Object Windows.Documents.Hyperlink
        $hyperlink.NavigateUri = New-Object System.Uri($match.Groups[1].Value)
        $hyperlink.Inlines.Add($match.Groups[2].Value)
        $hyperlink.TextDecorations = [Windows.TextDecorations]::None  # Remove underline
        $hyperlink.Foreground = $LinkForegroundColor

        $hyperlink.Add_Click({
            param($sender, $args)
            Start-Process $sender.NavigateUri.AbsoluteUri
        })
        $hyperlink.Add_MouseEnter({
            param($sender, $args)
            $sender.Foreground = $LinkHoverForegroundColor
            $sender.FontSize = ($FontSize + ($FontSize / 4))
            $sender.FontWeight = "SemiBold"
        })
        $hyperlink.Add_MouseLeave({
            param($sender, $args)
            $sender.Foreground = $LinkForegroundColor
            $sender.FontSize = $FontSize
            $sender.FontWeight = "Normal"
        })

        $messageTextBlock.Inlines.Add($hyperlink)

        # Update the last position
        $lastPos = $match.Index + $match.Length
    }

    # Add any remaining text after the last hyperlink
    if ($lastPos -lt $Message.Length) {
        $textAfter = $Message.Substring($lastPos)
        $messageTextBlock.Inlines.Add((New-Object Windows.Documents.Run($textAfter)))
    }

    # If no matches, add the entire message as a run
    if ($regex.Matches($Message).Count -eq 0) {
        $messageTextBlock.Inlines.Add((New-Object Windows.Documents.Run($Message)))
    }

    # Create a ScrollViewer if EnableScroll is true
    if ($EnableScroll) {
        $scrollViewer = New-Object System.Windows.Controls.ScrollViewer
        $scrollViewer.VerticalScrollBarVisibility = 'Auto'
        $scrollViewer.HorizontalScrollBarVisibility = 'Disabled'
        $scrollViewer.Content = $messageTextBlock
        $grid.Children.Add($scrollViewer)
        [Windows.Controls.Grid]::SetRow($scrollViewer, 1)  # Set the row to the second row (0-based index)
    } else {
        $grid.Children.Add($messageTextBlock)
        [Windows.Controls.Grid]::SetRow($messageTextBlock, 1)  # Set the row to the second row (0-based index)
    }

    # Add OK button
    $okButton = New-Object Windows.Controls.Button
    $okButton.Content = "OK"
    $okButton.FontSize = $FontSize
    $okButton.Width = 80
    $okButton.Height = 30
    $okButton.HorizontalAlignment = [Windows.HorizontalAlignment]::Center
    $okButton.VerticalAlignment = [Windows.VerticalAlignment]::Bottom
    $okButton.Margin = New-Object Windows.Thickness(0, 0, 0, 10)
    $okButton.Background = $buttonBackgroundColor
    $okButton.Foreground = $buttonForegroundColor
    $okButton.BorderBrush = $BorderColor
    $okButton.Add_Click({
        $dialog.Close()
    })
    $grid.Children.Add($okButton)
    [Windows.Controls.Grid]::SetRow($okButton, 2)  # Set the row to the third row (0-based index)

    # Handle Escape key press to close the dialog
    $dialog.Add_KeyDown({
        if ($_.Key -eq 'Escape') {
            $dialog.Close()
        }
    })

    # Set the OK button as the default button (activated on Enter)
    $okButton.IsDefault = $true

    # Show the custom dialog
    $dialog.ShowDialog()
}
function Test-WinUtilPackageManager {
    <#

    .SYNOPSIS
        Checks if Winget and/or Choco are installed

    .PARAMETER winget
        Check if Winget is installed

    .PARAMETER choco
        Check if Chocolatey is installed

    #>

    Param(
        [System.Management.Automation.SwitchParameter]$winget,
        [System.Management.Automation.SwitchParameter]$choco
    )

    $status = "not-installed"

    if ($winget) {
        # Check if Winget is available while getting it's Version if it's available
        $wingetExists = $true
        try {
            $wingetVersionFull = winget --version
        } catch [System.Management.Automation.CommandNotFoundException], [System.Management.Automation.ApplicationFailedException] {
            Write-Warning "Winget was not found due to un-availablity reasons"
            $wingetExists = $false
        } catch {
            Write-Warning "Winget was not found due to un-known reasons, The Stack Trace is:`n$($psitem.Exception.StackTrace)"
            $wingetExists = $false
    }

        # If Winget is available, Parse it's Version and give proper information to Terminal Output.
    # If it isn't available, the return of this funtion will be "not-installed", indicating that
        # Winget isn't installed/available on The System.
    if ($wingetExists) {
            # Check if Preview Version
            if ($wingetVersionFull.Contains("-preview")) {
                $wingetVersion = $wingetVersionFull.Trim("-preview")
                $wingetPreview = $true
            } else {
                $wingetVersion = $wingetVersionFull
                $wingetPreview = $false
            }

            # Check if Winget's Version is too old.
            $wingetCurrentVersion = [System.Version]::Parse($wingetVersion.Trim('v'))
            # Grabs the latest release of Winget from the Github API for version check process.
            $response = Invoke-RestMethod -Uri "https://api.github.com/repos/microsoft/Winget-cli/releases/latest" -Method Get -ErrorAction Stop
            $wingetLatestVersion = [System.Version]::Parse(($response.tag_name).Trim('v')) #Stores version number of latest release.
            $wingetOutdated = $wingetCurrentVersion -lt $wingetLatestVersion
            Write-Host "===========================================" -ForegroundColor Green
            Write-Host "---        Winget is installed          ---" -ForegroundColor Green
            Write-Host "===========================================" -ForegroundColor Green
            Write-Host "Version: $wingetVersionFull" -ForegroundColor White

            if (!$wingetPreview) {
                Write-Host "    - Winget is a release version." -ForegroundColor Green
            } else {
                Write-Host "    - Winget is a preview version. Unexpected problems may occur." -ForegroundColor Yellow
            }

            if (!$wingetOutdated) {
                Write-Host "    - Winget is Up to Date" -ForegroundColor Green
                $status = "installed"
            } else {
                Write-Host "    - Winget is Out of Date" -ForegroundColor Red
                $status = "outdated"
            }
        } else {
            Write-Host "===========================================" -ForegroundColor Red
            Write-Host "---      Winget is not installed        ---" -ForegroundColor Red
            Write-Host "===========================================" -ForegroundColor Red
            $status = "not-installed"
        }
    }

    if ($choco) {
        if ((Get-Command -Name choco -ErrorAction Ignore) -and ($chocoVersion = (Get-Item "$env:ChocolateyInstall\choco.exe" -ErrorAction Ignore).VersionInfo.ProductVersion)) {
            Write-Host "===========================================" -ForegroundColor Green
            Write-Host "---      Chocolatey is installed        ---" -ForegroundColor Green
            Write-Host "===========================================" -ForegroundColor Green
            Write-Host "Version: v$chocoVersion" -ForegroundColor White
            $status = "installed"
        } else {
            Write-Host "===========================================" -ForegroundColor Red
            Write-Host "---    Chocolatey is not installed      ---" -ForegroundColor Red
            Write-Host "===========================================" -ForegroundColor Red
            $status = "not-installed"
        }
    }

    return $status
}
Function Uninstall-WinUtilEdgeBrowser {
    <#
    .SYNOPSIS
        Uninstall the Edge Browser (Chromium) from the system in an elegant way.
    .DESCRIPTION
        This will switch up the region to one of the EEA countries temporarily and uninstall the Edge Browser (Chromium).
    #>

    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("install", "uninstall")]
        [string]$action
    )

    function Uninstall-EdgeClient {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Key
        )

        $originalNation = [microsoft.win32.registry]::GetValue('HKEY_USERS\.DEFAULT\Control Panel\International\Geo', 'Nation', [Microsoft.Win32.RegistryValueKind]::String)

        # Set Nation to any of the EEA regions temporarily
        # Refer: https://learn.microsoft.com/en-us/windows/win32/intl/table-of-geographical-locations
        $tmpNation = 68 # Ireland
        [microsoft.win32.registry]::SetValue('HKEY_USERS\.DEFAULT\Control Panel\International\Geo', 'Nation', $tmpNation, [Microsoft.Win32.RegistryValueKind]::String) | Out-Null

        $baseKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate'
        $registryPath = $baseKey + '\ClientState\' + $Key

        if (!(Test-Path -Path $registryPath)) {
            Write-Host "[$Mode] Registry key not found: $registryPath"
            return
        }

        # Remove the status flag
        Remove-ItemProperty -Path $baseKey -Name "IsEdgeStableUninstalled" -ErrorAction SilentlyContinue | Out-Null

        Remove-ItemProperty -Path $registryPath -Name "experiment_control_labels" -ErrorAction SilentlyContinue | Out-Null

        $uninstallString = (Get-ItemProperty -Path $registryPath).UninstallString
        $uninstallArguments = (Get-ItemProperty -Path $registryPath).UninstallArguments

        if ([string]::IsNullOrEmpty($uninstallString) -or [string]::IsNullOrEmpty($uninstallArguments)) {
            Write-Host "[$Mode] Cannot find uninstall methods for $Mode"
            return
        }

        # Extra arguments to nuke it
        $uninstallArguments += " --force-uninstall --delete-profile"

        # $uninstallCommand = "`"$uninstallString`"" + $uninstallArguments
        if (!(Test-Path -Path $uninstallString)) {
            Write-Host "[$Mode] setup.exe not found at: $uninstallString"
            return
        }
        Start-Process -FilePath $uninstallString -ArgumentList $uninstallArguments -Wait -NoNewWindow -Verbose

        # Restore Nation back to the original
        [microsoft.win32.registry]::SetValue('HKEY_USERS\.DEFAULT\Control Panel\International\Geo', 'Nation', $originalNation, [Microsoft.Win32.RegistryValueKind]::String) | Out-Null

        # might not exist in some cases
        if ((Get-ItemProperty -Path $baseKey).IsEdgeStableUninstalled -eq 1) {
            Write-Host "[$Mode] Edge Stable has been successfully uninstalled"
        }
    }

    function Uninstall-Edge {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" -Name "NoRemove" -ErrorAction SilentlyContinue | Out-Null

        [microsoft.win32.registry]::SetValue("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev", "AllowUninstall", 1, [Microsoft.Win32.RegistryValueKind]::DWord) | Out-Null

        Uninstall-EdgeClient -Key '{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'

        Remove-Item -Path "Computer\\HKEY_CLASSES_ROOT\\MSEdgePDF" -ErrorAction SilentlyContinue | Out-Null
        Remove-Item -Path "Computer\\HKEY_CLASSES_ROOT\\MSEdgeHTM" -ErrorAction SilentlyContinue | Out-Null
        Remove-Item -Path "Computer\\HKEY_CLASSES_ROOT\\MSEdgeMHT" -ErrorAction SilentlyContinue | Out-Null

        # Remove Edge Polocy reg keys
        Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Recurse -ErrorAction SilentlyContinue | Out-Null

        # Remove Edge reg keys
        Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge" -Recurse -ErrorAction SilentlyContinue | Out-Null
    }

    function Uninstall-WebView {
        # FIXME: might not work on some systems

        Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView" -Name "NoRemove" -ErrorAction SilentlyContinue | Out-Null

        Uninstall-EdgeClient -Key '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    }

    function Uninstall-EdgeUpdate {
        # FIXME: might not work on some systems

        Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update" -Name "NoRemove" -ErrorAction SilentlyContinue | Out-Null

        $registryPath = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate'
        if (!(Test-Path -Path $registryPath)) {
            Write-Host "Registry key not found: $registryPath"
            return
        }
        $uninstallCmdLine = (Get-ItemProperty -Path $registryPath).UninstallCmdLine

        if ([string]::IsNullOrEmpty($uninstallCmdLine)) {
            Write-Host "Cannot find uninstall methods for $Mode"
            return
        }

        Start-Process cmd.exe "/c $uninstallCmdLine" -WindowStyle Hidden -Wait

        # Remove EdgeUpdate reg keys
        Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate" -Recurse -ErrorAction SilentlyContinue | Out-Null
    }

    function Install-Edge {
        $tempEdgePath = "$env:TEMP\MicrosoftEdgeSetup.exe"

        try {
            write-host "Installing Edge ..."
            Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2109047&Channel=Stable&language=en&consent=1" -OutFile $tempEdgePath
            Start-Process -FilePath $tempEdgePath -ArgumentList "/silent /install" -Wait
            Remove-item $tempEdgePath
            write-host "Edge Installed Successfully"
        } catch {
            write-host "Failed to install Edge"
        }
    }

    if ($action -eq "Install") {
        Install-Edge
    } elseif ($action -eq "Uninstall") {
        Uninstall-Edge
        Uninstall-EdgeUpdate
        # Uninstall-WebView - WebView is needed for Visual Studio and some MS Store Games like Forza
    }
}
Function Update-WinUtilProgramWinget {

    <#

    .SYNOPSIS
        This will update all programs using Winget

    #>

    [ScriptBlock]$wingetinstall = {

        $host.ui.RawUI.WindowTitle = """Winget Install"""

        Start-Transcript "$logdir\winget-update_$dateTime.log" -Append
        winget upgrade --all --accept-source-agreements --accept-package-agreements --scope=machine --silent

    }

    $global:WinGetInstall = Start-Process -Verb runas powershell -ArgumentList "-command invoke-command -scriptblock {$wingetinstall} -argumentlist '$($ProgramsToInstall -join ",")'" -PassThru

}

function Invoke-ScratchDialog {

    <#

    .SYNOPSIS
        Enable Editable Text box Alternate Scartch path

    .PARAMETER Button
    #>
    $sync.WPFMicrowinISOScratchDir.IsChecked


    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $Dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $Dialog.SelectedPath =          $sync.MicrowinScratchDirBox.Text
    $Dialog.ShowDialog()
    $filePath = $Dialog.SelectedPath
        Write-Host "No ISO is chosen+  $filePath"

    if ([string]::IsNullOrEmpty($filePath)) {
        Write-Host "No Folder had chosen"
        return
    }

       $sync.MicrowinScratchDirBox.Text =  Join-Path $filePath "\"

}
function Invoke-WPFButton {

    <#

    .SYNOPSIS
        Invokes the function associated with the clicked button

    .PARAMETER Button
        The name of the button that was clicked

    #>

    Param ([string]$Button)

    # Use this to get the name of the button
    #[System.Windows.MessageBox]::Show("$Button","Chris Titus Tech's Windows Utility","OK","Info")
    if (-not $sync.ProcessRunning) {
        Set-WinUtilProgressBar  -label "" -percent 0 -hide $true
    }

    Switch -Wildcard ($Button) {
        "WPFTab?BT" {Invoke-WPFTab $Button}
        "WPFInstall" {Invoke-WPFInstall}
        "WPFUninstall" {Invoke-WPFUnInstall}
        "WPFInstallUpgrade" {Invoke-WPFInstallUpgrade}
        "WPFStandard" {Invoke-WPFPresets "Standard" -checkboxfilterpattern "WPFTweak*"}
        "WPFMinimal" {Invoke-WPFPresets "Minimal" -checkboxfilterpattern "WPFTweak*"}
        "WPFClearTweaksSelection" {Invoke-WPFPresets -imported $true -checkboxfilterpattern "WPFTweak*"}
        "WPFClearInstallSelection" {Invoke-WPFPresets -imported $true -checkboxfilterpattern "WPFInstall*"}
        "WPFtweaksbutton" {Invoke-WPFtweaksbutton}
        "WPFOOSUbutton" {Invoke-WPFOOSU}
        "WPFAddUltPerf" {Invoke-WPFUltimatePerformance -State "Enable"}
        "WPFRemoveUltPerf" {Invoke-WPFUltimatePerformance -State "Disable"}
        "WPFundoall" {Invoke-WPFundoall}
        "WPFFeatureInstall" {Invoke-WPFFeatureInstall}
        "WPFPanelDISM" {Invoke-WPFPanelDISM}
        "WPFPanelAutologin" {Invoke-WPFPanelAutologin}
        "WPFPanelcontrol" {Invoke-WPFControlPanel -Panel $button}
        "WPFPanelnetwork" {Invoke-WPFControlPanel -Panel $button}
        "WPFPanelpower" {Invoke-WPFControlPanel -Panel $button}
        "WPFPanelregion" {Invoke-WPFControlPanel -Panel $button}
        "WPFPanelsound" {Invoke-WPFControlPanel -Panel $button}
        "WPFPanelprinter" {Invoke-WPFControlPanel -Panel $button}
        "WPFPanelsystem" {Invoke-WPFControlPanel -Panel $button}
        "WPFPaneluser" {Invoke-WPFControlPanel -Panel $button}
        "WPFUpdatesdefault" {Invoke-WPFFixesUpdate}
        "WPFFixesUpdate" {Invoke-WPFFixesUpdate}
        "WPFFixesWinget" {Invoke-WPFFixesWinget}
        "WPFRunAdobeCCCleanerTool" {Invoke-WPFRunAdobeCCCleanerTool}
        "WPFFixesNetwork" {Invoke-WPFFixesNetwork}
        "WPFUpdatesdisable" {Invoke-WPFUpdatesdisable}
        "WPFUpdatessecurity" {Invoke-WPFUpdatessecurity}
        "WPFWinUtilShortcut" {Invoke-WPFShortcut -ShortcutToAdd "WinUtil" -RunAsAdmin $true}
        "WPFGetInstalled" {Invoke-WPFGetInstalled -CheckBox "winget"}
        "WPFGetInstalledTweaks" {Invoke-WPFGetInstalled -CheckBox "tweaks"}
        "WPFGetIso" {Invoke-MicrowinGetIso}
        "WPFMicrowin" {Invoke-Microwin}
        "WPFCloseButton" {Invoke-WPFCloseButton}
        "MicrowinScratchDirBT" {Invoke-ScratchDialog}
        "WPFWinUtilInstallPSProfile" {Invoke-WinUtilInstallPSProfile}
        "WPFWinUtilUninstallPSProfile" {Invoke-WinUtilUninstallPSProfile}
        "WPFWinUtilSSHServer" {Invoke-WPFSSHServer}
    }
}
function Invoke-WPFCloseButton {

    <#

    .SYNOPSIS
        Close application

    .PARAMETER Button
    #>
    $sync["Form"].Close()
    Write-Host "Bye bye!"
}
function Invoke-WPFControlPanel {
    <#

    .SYNOPSIS
        Opens the requested legacy panel

    .PARAMETER Panel
        The panel to open

    #>
    param($Panel)

    switch ($Panel) {
        "WPFPanelcontrol" {cmd /c control}
        "WPFPanelnetwork" {cmd /c ncpa.cpl}
        "WPFPanelpower"   {cmd /c powercfg.cpl}
        "WPFPanelregion"  {cmd /c intl.cpl}
        "WPFPanelsound"   {cmd /c mmsys.cpl}
        "WPFPanelprinter" {Start-Process "shell:::{A8A91A66-3A7D-4424-8D24-04E180695C7A}"}
        "WPFPanelsystem"  {cmd /c sysdm.cpl}
        "WPFPaneluser"    {cmd /c "control userpasswords2"}
    }
}
function Invoke-WPFFeatureInstall {
    <#

    .SYNOPSIS
        Installs selected Windows Features

    #>

    if($sync.ProcessRunning) {
        $msg = "[Invoke-WPFFeatureInstall] Install process is currently running."
        [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $Features = (Get-WinUtilCheckBoxes)["WPFFeature"]

    Invoke-WPFRunspace -ArgumentList $Features -DebugPreference $DebugPreference -ScriptBlock {
        param($Features, $DebugPreference)
        $sync.ProcessRunning = $true
        if ($Features.count -eq 1) {
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Indeterminate" -value 0.01 -overlay "logo" })
        } else {
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Normal" -value 0.01 -overlay "logo" })
        }

        Invoke-WinUtilFeatureInstall $Features

        $sync.ProcessRunning = $false
        $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "None" -overlay "checkmark" })

        Write-Host "==================================="
        Write-Host "---   Features are Installed    ---"
        Write-Host "---  A Reboot may be required   ---"
        Write-Host "==================================="
    }
}
function Invoke-WPFFixesNetwork {
    <#

    .SYNOPSIS
        Resets various network configurations

    #>

    Write-Host "Resetting Network with netsh"

    # Reset WinSock catalog to a clean state
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "winsock", "reset"
    # Resets WinHTTP proxy setting to DIRECT
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "winhttp", "reset", "proxy"
    # Removes all user configured IP settings
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "int", "ip", "reset"

    Write-Host "Process complete. Please reboot your computer."

    $ButtonType = [System.Windows.MessageBoxButton]::OK
    $MessageboxTitle = "Network Reset "
    $Messageboxbody = ("Stock settings loaded.`n Please reboot your computer")
    $MessageIcon = [System.Windows.MessageBoxImage]::Information

    [System.Windows.MessageBox]::Show($Messageboxbody, $MessageboxTitle, $ButtonType, $MessageIcon)
    Write-Host "=========================================="
    Write-Host "-- Network Configuration has been Reset --"
    Write-Host "=========================================="
}
function Invoke-WPFFixesUpdate {

    <#

    .SYNOPSIS
        Performs various tasks in an attempt to repair Windows Update

    .DESCRIPTION
        1. (Aggressive Only) Scans the system for corruption using chkdsk, SFC, and DISM
            Steps:
                1. Runs chkdsk /scan /perf
                    /scan - Runs an online scan on the volume
                    /perf - Uses more system resources to complete a scan as fast as possible
                2. Runs SFC /scannow
                    /scannow - Scans integrity of all protected system files and repairs files with problems when possible
                3. Runs DISM /Online /Cleanup-Image /RestoreHealth
                    /Online - Targets the running operating system
                    /Cleanup-Image - Performs cleanup and recovery operations on the image
                    /RestoreHealth - Scans the image for component store corruption and attempts to repair the corruption using Windows Update
                4. Runs SFC /scannow
                    Ran twice in case DISM repaired SFC
        2. Stops Windows Update Services
        3. Remove the QMGR Data file, which stores BITS jobs
        4. (Aggressive Only) Renames the DataStore and CatRoot2 folders
            DataStore - Contains the Windows Update History and Log Files
            CatRoot2 - Contains the Signatures for Windows Update Packages
        5. Renames the Windows Update Download Folder
        6. Deletes the Windows Update Log
        7. (Aggressive Only) Resets the Security Descriptors on the Windows Update Services
        8. Reregisters the BITS and Windows Update DLLs
        9. Removes the WSUS client settings
        10. Resets WinSock
        11. Gets and deletes all BITS jobs
        12. Sets the startup type of the Windows Update Services then starts them
        13. Forces Windows Update to check for updates

    .PARAMETER Aggressive
        If specified, the script will take additional steps to repair Windows Update that are more dangerous, take a significant amount of time, or are generally unnecessary

    #>

    param($Aggressive = $false)

    Write-Progress -Id 0 -Activity "Repairing Windows Update" -PercentComplete 0
    # Wait for the first progress bar to show, otherwise the second one won't show
    Start-Sleep -Milliseconds 200

    if ($Aggressive) {
        # Scan system for corruption
        Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Scanning for corruption..." -PercentComplete 0
        Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Running chkdsk..." -PercentComplete 0
        # 2>&1 redirects stdout, alowing iteration over the output
        chkdsk.exe /scan /perf 2>&1 | ForEach-Object {
            # Write stdout to the Verbose stream
            Write-Verbose $_

            # Get the index of the total percentage
            $index = $_.IndexOf("Total:")
            if (
                # If the percent is found
                ($percent = try {(
                    $_.Substring(
                        $index + 6,
                        $_.IndexOf("%", $index) - $index - 6
                    )
                ).Trim()} catch {0}) `
                <# And the current percentage is greater than the previous one #>`
                -and $percent -gt $oldpercent
            ) {
                # Update the progress bar
                $oldpercent = $percent
                Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Running chkdsk... ($percent%)" -PercentComplete $percent
            }
        }

        Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Running SFC..." -PercentComplete 0
        $oldpercent = 0
        # SFC has a bug when redirected which causes it to output only when the stdout buffer is full, causing the progress bar to move in chunks
        sfc /scannow 2>&1 | ForEach-Object {
            # Write stdout to the Verbose stream
            Write-Verbose $_

            # Filter for lines that contain a percentage that is greater than the previous one
            if (
                (
                    # Use a different method to get the percentage that accounts for SFC's Unicode output
                    [int]$percent = try {(
                        (
                            $_.Substring(
                                $_.IndexOf("n") + 2,
                                $_.IndexOf("%") - $_.IndexOf("n") - 2
                            ).ToCharArray() | Where-Object {$_}
                        ) -join ''
                    ).TrimStart()} catch {0}
                ) -and $percent -gt $oldpercent
            ) {
                # Update the progress bar
                $oldpercent = $percent
                Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Running SFC... ($percent%)" -PercentComplete $percent
            }
        }

        Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Running DISM..." -PercentComplete 0
        $oldpercent = 0
        DISM /Online /Cleanup-Image /RestoreHealth | ForEach-Object {
            # Write stdout to the Verbose stream
            Write-Verbose $_

            # Filter for lines that contain a percentage that is greater than the previous one
            if (
                ($percent = try {
                    [int]($_ -replace "\[" -replace "=" -replace " " -replace "%" -replace "\]")
                } catch {0}) `
                -and $percent -gt $oldpercent
            ) {
                # Update the progress bar
                $oldpercent = $percent
                Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Running DISM... ($percent%)" -PercentComplete $percent
            }
        }

        Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Running SFC again..." -PercentComplete 0
        $oldpercent = 0
        sfc /scannow 2>&1 | ForEach-Object {
            # Write stdout to the Verbose stream
            Write-Verbose $_

            # Filter for lines that contain a percentage that is greater than the previous one
            if (
                (
                    [int]$percent = try {(
                        (
                            $_.Substring(
                                $_.IndexOf("n") + 2,
                                $_.IndexOf("%") - $_.IndexOf("n") - 2
                            ).ToCharArray() | Where-Object {$_}
                        ) -join ''
                    ).TrimStart()} catch {0}
                ) -and $percent -gt $oldpercent
            ) {
                # Update the progress bar
                $oldpercent = $percent
                Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Running SFC... ($percent%)" -PercentComplete $percent
            }
        }
        Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Completed" -PercentComplete 100
    }


    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Stopping Windows Update Services..." -PercentComplete 10
    # Stop the Windows Update Services
    Write-Progress -Id 2 -ParentId 0 -Activity "Stopping Services" -Status "Stopping BITS..." -PercentComplete 0
    Stop-Service -Name BITS -Force
    Write-Progress -Id 2 -ParentId 0 -Activity "Stopping Services" -Status "Stopping wuauserv..." -PercentComplete 20
    Stop-Service -Name wuauserv -Force
    Write-Progress -Id 2 -ParentId 0 -Activity "Stopping Services" -Status "Stopping appidsvc..." -PercentComplete 40
    Stop-Service -Name appidsvc -Force
    Write-Progress -Id 2 -ParentId 0 -Activity "Stopping Services" -Status "Stopping cryptsvc..." -PercentComplete 60
    Stop-Service -Name cryptsvc -Force
    Write-Progress -Id 2 -ParentId 0 -Activity "Stopping Services" -Status "Completed" -PercentComplete 100


    # Remove the QMGR Data file
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Renaming/Removing Files..." -PercentComplete 20
    Write-Progress -Id 3 -ParentId 0 -Activity "Renaming/Removing Files" -Status "Removing QMGR Data files..." -PercentComplete 0
    Remove-Item "$env:allusersprofile\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -ErrorAction SilentlyContinue


    if ($Aggressive) {
        # Rename the Windows Update Log and Signature Folders
        Write-Progress -Id 3 -ParentId 0 -Activity "Renaming/Removing Files" -Status "Renaming the Windows Update Log, Download, and Signature Folder..." -PercentComplete 20
        Rename-Item $env:systemroot\SoftwareDistribution\DataStore DataStore.bak -ErrorAction SilentlyContinue
        Rename-Item $env:systemroot\System32\Catroot2 catroot2.bak -ErrorAction SilentlyContinue
    }

    # Rename the Windows Update Download Folder
    Write-Progress -Id 3 -ParentId 0 -Activity "Renaming/Removing Files" -Status "Renaming the Windows Update Download Folder..." -PercentComplete 20
    Rename-Item $env:systemroot\SoftwareDistribution\Download Download.bak -ErrorAction SilentlyContinue

    # Delete the legacy Windows Update Log
    Write-Progress -Id 3 -ParentId 0 -Activity "Renaming/Removing Files" -Status "Removing the old Windows Update log..." -PercentComplete 80
    Remove-Item $env:systemroot\WindowsUpdate.log -ErrorAction SilentlyContinue
    Write-Progress -Id 3 -ParentId 0 -Activity "Renaming/Removing Files" -Status "Completed" -PercentComplete 100


    if ($Aggressive) {
        # Reset the Security Descriptors on the Windows Update Services
        Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Resetting the WU Service Security Descriptors..." -PercentComplete 25
        Write-Progress -Id 4 -ParentId 0 -Activity "Resetting the WU Service Security Descriptors" -Status "Resetting the BITS Security Descriptor..." -PercentComplete 0
        Start-Process -NoNewWindow -FilePath "sc.exe" -ArgumentList "sdset", "bits", "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)" -Wait
        Write-Progress -Id 4 -ParentId 0 -Activity "Resetting the WU Service Security Descriptors" -Status "Resetting the wuauserv Security Descriptor..." -PercentComplete 50
        Start-Process -NoNewWindow -FilePath "sc.exe" -ArgumentList "sdset", "wuauserv", "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)" -Wait
        Write-Progress -Id 4 -ParentId 0 -Activity "Resetting the WU Service Security Descriptors" -Status "Completed" -PercentComplete 100
    }


    # Reregister the BITS and Windows Update DLLs
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Reregistering DLLs..." -PercentComplete 40
    $oldLocation = Get-Location
    Set-Location $env:systemroot\system32
    $i = 0
    $DLLs = @(
        "atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll",
        "jscript.dll", "vbscript.dll", "scrrun.dll", "msxml.dll", "msxml3.dll",
        "msxml6.dll", "actxprxy.dll", "softpub.dll", "wintrust.dll", "dssenh.dll",
        "rsaenh.dll", "gpkcsp.dll", "sccbase.dll", "slbcsp.dll", "cryptdlg.dll",
        "oleaut32.dll", "ole32.dll", "shell32.dll", "initpki.dll", "wuapi.dll",
        "wuaueng.dll", "wuaueng1.dll", "wucltui.dll", "wups.dll", "wups2.dll",
        "wuweb.dll", "qmgr.dll", "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll"
    )
    foreach ($dll in $DLLs) {
        Write-Progress -Id 5 -ParentId 0 -Activity "Reregistering DLLs" -Status "Registering $dll..." -PercentComplete ($i / $DLLs.Count * 100)
        $i++
        Start-Process -NoNewWindow -FilePath "regsvr32.exe" -ArgumentList "/s", $dll
    }
    Set-Location $oldLocation
    Write-Progress -Id 5 -ParentId 0 -Activity "Reregistering DLLs" -Status "Completed" -PercentComplete 100


    # Remove the WSUS client settings
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate") {
        Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Removing WSUS client settings..." -PercentComplete 60
        Write-Progress -Id 6 -ParentId 0 -Activity "Removing WSUS client settings" -PercentComplete 0
        Start-Process -NoNewWindow -FilePath "REG" -ArgumentList "DELETE", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "/v", "AccountDomainSid", "/f" -RedirectStandardError "NUL"
        Start-Process -NoNewWindow -FilePath "REG" -ArgumentList "DELETE", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "/v", "PingID", "/f" -RedirectStandardError "NUL"
        Start-Process -NoNewWindow -FilePath "REG" -ArgumentList "DELETE", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "/v", "SusClientId", "/f" -RedirectStandardError "NUL"
        Write-Progress -Id 6 -ParentId 0 -Activity "Removing WSUS client settings" -Status "Completed" -PercentComplete 100
    }

    # Remove Group Policy Windows Update settings
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Removing Group Policy Windows Update settings..." -PercentComplete 60
    Write-Progress -Id 7 -ParentId 0 -Activity "Removing Group Policy Windows Update settings" -PercentComplete 0
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
    Write-Host "Defaulting driver offering through Windows Update..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
    Write-Host "Defaulting Windows Update automatic restart..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue
    Write-Host "Clearing ANY Windows Update Policy settings..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Microsoft\WindowsSelfHost" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Microsoft\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Microsoft\WindowsSelfHost" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\WOW6432Node\Microsoft\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Process -NoNewWindow -FilePath "secedit" -ArgumentList "/configure", "/cfg", "$env:windir\inf\defltbase.inf", "/db", "defltbase.sdb", "/verbose" -Wait
    Start-Process -NoNewWindow -FilePath "cmd.exe" -ArgumentList "/c RD /S /Q $env:WinDir\System32\GroupPolicyUsers" -Wait
    Start-Process -NoNewWindow -FilePath "cmd.exe" -ArgumentList "/c RD /S /Q $env:WinDir\System32\GroupPolicy" -Wait
    Start-Process -NoNewWindow -FilePath "gpupdate" -ArgumentList "/force" -Wait
    Write-Progress -Id 7 -ParentId 0 -Activity "Removing Group Policy Windows Update settings" -Status "Completed" -PercentComplete 100


    # Reset WinSock
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Resetting WinSock..." -PercentComplete 65
    Write-Progress -Id 7 -ParentId 0 -Activity "Resetting WinSock" -Status "Resetting WinSock..." -PercentComplete 0
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "winsock", "reset"
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "winhttp", "reset", "proxy"
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "int", "ip", "reset"
    Write-Progress -Id 7 -ParentId 0 -Activity "Resetting WinSock" -Status "Completed" -PercentComplete 100


    # Get and delete all BITS jobs
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Deleting BITS jobs..." -PercentComplete 75
    Write-Progress -Id 8 -ParentId 0 -Activity "Deleting BITS jobs" -Status "Deleting BITS jobs..." -PercentComplete 0
    Get-BitsTransfer | Remove-BitsTransfer
    Write-Progress -Id 8 -ParentId 0 -Activity "Deleting BITS jobs" -Status "Completed" -PercentComplete 100


    # Change the startup type of the Windows Update Services and start them
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Starting Windows Update Services..." -PercentComplete 90
    Write-Progress -Id 9 -ParentId 0 -Activity "Starting Windows Update Services" -Status "Starting BITS..." -PercentComplete 0
    Get-Service BITS | Set-Service -StartupType Manual -PassThru | Start-Service
    Write-Progress -Id 9 -ParentId 0 -Activity "Starting Windows Update Services" -Status "Starting wuauserv..." -PercentComplete 25
    Get-Service wuauserv | Set-Service -StartupType Manual -PassThru | Start-Service
    Write-Progress -Id 9 -ParentId 0 -Activity "Starting Windows Update Services" -Status "Starting AppIDSvc..." -PercentComplete 50
    # The AppIDSvc service is protected, so the startup type has to be changed in the registry
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc" -Name "Start" -Value "3" # Manual
    Start-Service AppIDSvc
    Write-Progress -Id 9 -ParentId 0 -Activity "Starting Windows Update Services" -Status "Starting CryptSvc..." -PercentComplete 75
    Get-Service CryptSvc | Set-Service -StartupType Manual -PassThru | Start-Service
    Write-Progress -Id 9 -ParentId 0 -Activity "Starting Windows Update Services" -Status "Completed" -PercentComplete 100


    # Force Windows Update to check for updates
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Forcing discovery..." -PercentComplete 95
    Write-Progress -Id 10 -ParentId 0 -Activity "Forcing discovery" -Status "Forcing discovery..." -PercentComplete 0
    try {
        (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
    } catch {
        Write-Warning "Failed to create Windows Update COM object: $_"
    }
    Start-Process -NoNewWindow -FilePath "wuauclt" -ArgumentList "/resetauthorization", "/detectnow"
    Write-Progress -Id 10 -ParentId 0 -Activity "Forcing discovery" -Status "Completed" -PercentComplete 100
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Completed" -PercentComplete 100

    $ButtonType = [System.Windows.MessageBoxButton]::OK
    $MessageboxTitle = "Reset Windows Update "
    $Messageboxbody = ("Stock settings loaded.`n Please reboot your computer")
    $MessageIcon = [System.Windows.MessageBoxImage]::Information

    [System.Windows.MessageBox]::Show($Messageboxbody, $MessageboxTitle, $ButtonType, $MessageIcon)
    Write-Host "==============================================="
    Write-Host "-- Reset All Windows Update Settings to Stock -"
    Write-Host "==============================================="

    # Remove the progress bars
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Completed
    Write-Progress -Id 1 -Activity "Scanning for corruption" -Completed
    Write-Progress -Id 2 -Activity "Stopping Services" -Completed
    Write-Progress -Id 3 -Activity "Renaming/Removing Files" -Completed
    Write-Progress -Id 4 -Activity "Resetting the WU Service Security Descriptors" -Completed
    Write-Progress -Id 5 -Activity "Reregistering DLLs" -Completed
    Write-Progress -Id 6 -Activity "Removing Group Policy Windows Update settings" -Completed
    Write-Progress -Id 7 -Activity "Resetting WinSock" -Completed
    Write-Progress -Id 8 -Activity "Deleting BITS jobs" -Completed
    Write-Progress -Id 9 -Activity "Starting Windows Update Services" -Completed
    Write-Progress -Id 10 -Activity "Forcing discovery" -Completed
}
function Invoke-WPFFixesWinget {

    <#

    .SYNOPSIS
        Fixes Winget by running choco install winget
    .DESCRIPTION
        BravoNorris for the fantastic idea of a button to reinstall winget
    #>
    # Install Choco if not already present
    Install-WinUtilChoco
    Start-Process -FilePath "choco" -ArgumentList "install winget -y --force" -NoNewWindow -Wait

}
Function Invoke-WPFFormVariables {
    <#

    .SYNOPSIS
        Prints the logo

    #>
    #If ($global:ReadmeDisplay -ne $true) { Write-Host "If you need to reference this display again, run Get-FormVariables" -ForegroundColor Yellow; $global:ReadmeDisplay = $true }

# Define an array of colors
$colors = "Red", "Yellow", "Green", "Cyan", "Blue", "Magenta", "DarkYellow", "Gray", "DarkCyan", "DarkMagenta", "DarkGreen", "DarkRed", "White"

# Define the ASCII art lines
$asciiArt = @(
    "                                                                                                         ",
    "                                                                                                         ",
    "TTTTTTTTTTTTTTTTTTTTTTTUUUUUUUU     UUUUUUUUTTTTTTTTTTTTTTTTTTTTTTT     OOOOOOOOO        SSSSSSSSSSSSSSS ",
    "T:::::::::::::::::::::TU::::::U     U::::::UT:::::::::::::::::::::T   OO:::::::::OO    SS:::::::::::::::S",
    "T:::::::::::::::::::::TU::::::U     U::::::UT:::::::::::::::::::::T OO:::::::::::::OO S:::::SSSSSS::::::S",
    "T:::::TT:::::::TT:::::TUU:::::U     U:::::UUT:::::TT:::::::TT:::::TO:::::::OOO:::::::OS:::::S     SSSSSSS",
    "TTTTTT  T:::::T  TTTTTT U:::::U     U:::::U TTTTTT  T:::::T  TTTTTTO::::::O   O::::::OS:::::S            ",
    "        T:::::T         U:::::D     D:::::U         T:::::T        O:::::O     O:::::OS:::::S            ",
    "        T:::::T         U:::::D     D:::::U         T:::::T        O:::::O     O:::::O S::::SSSS         ",
    "        T:::::T         U:::::D     D:::::U         T:::::T        O:::::O     O:::::O  SS::::::SSSSS    ",
    "        T:::::T         U:::::D     D:::::U         T:::::T        O:::::O     O:::::O    SSS::::::::SS  ",
    "        T:::::T         U:::::D     D:::::U         T:::::T        O:::::O     O:::::O       SSSSSS::::S ",
    "        T:::::T         U:::::D     D:::::U         T:::::T        O:::::O     O:::::O            S:::::S",
    "        T:::::T         U::::::U   U::::::U         T:::::T        O::::::O   O::::::O            S:::::S",
    "      TT:::::::TT       U:::::::UUU:::::::U       TT:::::::TT      O:::::::OOO:::::::OSSSSSSS     S:::::S",
    "      T:::::::::T        UU:::::::::::::UU        T:::::::::T       OO:::::::::::::OO S::::::SSSSSS:::::S",
    "      T:::::::::T          UU:::::::::UU          T:::::::::T         OO:::::::::OO   S:::::::::::::::SS ",
    "      TTTTTTTTTTT            UUUUUUUUU            TTTTTTTTTTT           OOOOOOOOO      SSSSSSSSSSSSSSS   ",
    "The Tech Pharaoh on youtube, who actually provides good content, not like those other suckers..."
)

# Loop through each line and apply a color
for ($i = 0; $i -lt $asciiArt.Length; $i++) {
    $color = $colors[$i % $colors.Length]  # Cycle through colors
    Write-Host -ForegroundColor $color $asciiArt[$i]
}

# ads



    #====DEBUG GUI Elements====

    #Write-Host "Found the following interactable elements from our form" -ForegroundColor Cyan
    #get-variable WPF*
}
function Invoke-WPFGetInstalled {
    <#
    TODO: Add the Option to use Chocolatey as Engine
    .SYNOPSIS
        Invokes the function that gets the checkboxes to check in a new runspace

    .PARAMETER checkbox
        Indicates whether to check for installed 'winget' programs or applied 'tweaks'

    #>
    param($checkbox)

    if($sync.ProcessRunning) {
        $msg = "[Invoke-WPFGetInstalled] Install process is currently running."
        [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    if(($sync.WPFpreferChocolatey.IsChecked -eq $false) -and ((Test-WinUtilPackageManager -winget) -eq "not-installed") -and $checkbox -eq "winget") {
        return
    }
    $preferChoco = $sync.WPFpreferChocolatey.IsChecked
    Invoke-WPFRunspace -ArgumentList $checkbox, $preferChoco -DebugPreference $DebugPreference -ScriptBlock {
        param($checkbox, $preferChoco, $DebugPreference)

        $sync.ProcessRunning = $true
        $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Indeterminate" })

        if($checkbox -eq "winget") {
            Write-Host "Getting Installed Programs..."
        }
        if($checkbox -eq "tweaks") {
            Write-Host "Getting Installed Tweaks..."
        }
        if ($preferChoco -and $checkbox -eq "winget") {
            $Checkboxes = Invoke-WinUtilCurrentSystem -CheckBox "choco"
        }
        else{
            $Checkboxes = Invoke-WinUtilCurrentSystem -CheckBox $checkbox
        }

        $sync.form.Dispatcher.invoke({
            foreach($checkbox in $Checkboxes) {
                $sync.$checkbox.ischecked = $True
            }
        })

        Write-Host "Done..."
        $sync.ProcessRunning = $false
        $sync.form.Dispatcher.Invoke([action] { Set-WinUtilTaskbaritem -state "None" })
    }
}
function Invoke-WPFImpex {
    <#

    .SYNOPSIS
        Handles importing and exporting of the checkboxes checked for the tweaks section

    .PARAMETER type
        Indicates whether to 'import' or 'export'

    .PARAMETER checkbox
        The checkbox to export to a file or apply the imported file to

    .EXAMPLE
        Invoke-WPFImpex -type "export"

    #>
    param(
        $type,
        $Config = $null
    )

    function ConfigDialog {
        if (!$Config) {
            switch ($type) {
                "export" { $FileBrowser = New-Object System.Windows.Forms.SaveFileDialog }
                "import" { $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog }
            }
            $FileBrowser.InitialDirectory = [Environment]::GetFolderPath('Desktop')
            $FileBrowser.Filter = "JSON Files (*.json)|*.json"
            $FileBrowser.ShowDialog() | Out-Null

            if ($FileBrowser.FileName -eq "") {
                return $null
            } else {
                return $FileBrowser.FileName
            }
        } else {
            return $Config
        }
    }

    switch ($type) {
        "export" {
            try {
                $Config = ConfigDialog
                if ($Config) {
                    $jsonFile = Get-WinUtilCheckBoxes -unCheck $false | ConvertTo-Json
                    $jsonFile | Out-File $Config -Force
                    "iex ""& { `$(irm christitus.com/win) } -Config '$Config'""" | Set-Clipboard
                }
            } catch {
                Write-Error "An error occurred while exporting: $_"
            }
        }
        "import" {
            try {
                $Config = ConfigDialog
                if ($Config) {
                    try {
                        if ($Config -match '^https?://') {
                            $jsonFile = (Invoke-WebRequest "$Config").Content | ConvertFrom-Json
                        } else {
                            $jsonFile = Get-Content $Config | ConvertFrom-Json
                        }
                    } catch {
                        Write-Error "Failed to load the JSON file from the specified path or URL: $_"
                        return
                    }
                    $flattenedJson = $jsonFile.PSObject.Properties.Where({ $_.Name -ne "Install" }).ForEach({ $_.Value })
                    Invoke-WPFPresets -preset $flattenedJson -imported $true
                }
            } catch {
                Write-Error "An error occurred while importing: $_"
            }
        }
    }
}
function Invoke-WPFInstall {
    <#

    .SYNOPSIS
        Installs the selected programs using winget, if one or more of the selected programs are already installed on the system, winget will try and perform an upgrade if there's a newer version to install.

    #>

    if($sync.ProcessRunning) {
        $msg = "[Invoke-WPFInstall] An Install process is currently running."
        [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $PackagesToInstall = (Get-WinUtilCheckBoxes)["Install"]
    Write-Host $PackagesToInstall
    if ($PackagesToInstall.Count -eq 0) {
        $WarningMsg = "Please select the program(s) to install or upgrade"
        [System.Windows.MessageBox]::Show($WarningMsg, $AppTitle, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }
    $ChocoPreference = $($sync.WPFpreferChocolatey.IsChecked)
    $installHandle = Invoke-WPFRunspace -ParameterList @(("PackagesToInstall", $PackagesToInstall),("ChocoPreference", $ChocoPreference)) -DebugPreference $DebugPreference -ScriptBlock {
        param($PackagesToInstall, $ChocoPreference, $DebugPreference)
        if ($PackagesToInstall.count -eq 1) {
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Indeterminate" -value 0.01 -overlay "logo" })
        } else {
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Normal" -value 0.01 -overlay "logo" })
        }
        $packagesWinget, $packagesChoco = {
            $packagesWinget = [System.Collections.ArrayList]::new()
            $packagesChoco = [System.Collections.ArrayList]::new()

        foreach ($package in $PackagesToInstall) {
            if ($ChocoPreference) {
                if ($package.choco -eq "na") {
                    $packagesWinget.add($package.winget)
                    Write-Host "Queueing $($package.winget) for Winget install"
                } else {
                    $null = $packagesChoco.add($package.choco)
                    Write-Host "Queueing $($package.choco) for Chocolatey install"
                }
            }
            else {
                if ($package.winget -eq "na") {
                    $packagesChoco.add($package.choco)
                    Write-Host "Queueing $($package.choco) for Chocolatey install"
                } else {
                    $null = $packagesWinget.add($($package.winget))
                    Write-Host "Queueing $($package.winget) for Winget install"
                }
            }
        }
        return $packagesWinget, $packagesChoco
        }.Invoke($PackagesToInstall)

        try {
            $sync.ProcessRunning = $true
            $errorPackages = @()
            if($packagesWinget.Count -gt 0) {
                Install-WinUtilWinget
                Install-WinUtilProgramWinget -Action Install -Programs $packagesWinget

            }
            if($packagesChoco.Count -gt 0) {
                Install-WinUtilChoco
                Install-WinUtilProgramChoco -Action Install -Programs $packagesChoco
            }
            Write-Host "==========================================="
            Write-Host "--      Installs have finished          ---"
            Write-Host "==========================================="
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "None" -overlay "checkmark" })
        } catch {
            Write-Host "==========================================="
            Write-Host "Error: $_"
            Write-Host "==========================================="
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Error" -overlay "warning" })
        }
        $sync.ProcessRunning = $False
    }
}
function Invoke-WPFInstallUpgrade {
    <#

    .SYNOPSIS
        Invokes the function that upgrades all installed programs

    #>
    if ($sync.WPFpreferChocolatey.IsChecked) {
        Install-WinUtilChoco
        $chocoUpgradeStatus = (Start-Process "choco" -ArgumentList "upgrade all -y" -Wait -PassThru -NoNewWindow).ExitCode
        if ($chocoUpgradeStatus -eq 0) {
            Write-Host "Upgrade Successful"
        }
        else{
            Write-Host "Error Occured. Return Code: $chocoUpgradeStatus"
        }
    }
    else{
        if((Test-WinUtilPackageManager -winget) -eq "not-installed") {
            return
        }

        if(Get-WinUtilInstallerProcess -Process $global:WinGetInstall) {
            $msg = "[Invoke-WPFInstallUpgrade] Install process is currently running. Please check for a powershell window labeled 'Winget Install'"
            [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        Update-WinUtilProgramWinget

        Write-Host "==========================================="
        Write-Host "--           Updates started            ---"
        Write-Host "-- You can close this window if desired ---"
        Write-Host "==========================================="
    }
}
function Invoke-WPFOOSU {
    <#
    .SYNOPSIS
        Downloads and runs OO Shutup 10
    #>
    try {
        $OOSU_filepath = "$ENV:temp\OOSU10.exe"
        $Initial_ProgressPreference = $ProgressPreference
        $ProgressPreference = "SilentlyContinue" # Disables the Progress Bar to drasticly speed up Invoke-WebRequest
        Invoke-WebRequest -Uri "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -OutFile $OOSU_filepath
        Write-Host "Starting OO Shutup 10 ..."
        Start-Process $OOSU_filepath
    } catch {
        Write-Host "Error Downloading and Running OO Shutup 10" -ForegroundColor Red
    }
    finally {
        $ProgressPreference = $Initial_ProgressPreference
    }
}
function Invoke-WPFPanelAutologin {
    <#

    .SYNOPSIS
        Enables autologin using Sysinternals Autologon.exe

    #>

    # Official Microsoft recommendation: https://learn.microsoft.com/en-us/sysinternals/downloads/autologon
    Invoke-WebRequest -Uri "https://live.sysinternals.com/Autologon.exe" -OutFile "$env:temp\autologin.exe"
    cmd /c "$env:temp\autologin.exe" /accepteula
}
function Invoke-WPFPanelDISM {
    <#

    .SYNOPSIS
        Checks for system corruption using Chkdsk, SFC, and DISM

    .DESCRIPTION
        1. Chkdsk    - Fixes disk and filesystem corruption
        2. SFC Run 1 - Fixes system file corruption, and fixes DISM if it was corrupted
        3. DISM      - Fixes system image corruption, and fixes SFC's system image if it was corrupted
        4. SFC Run 2 - Fixes system file corruption, this time with an almost guaranteed uncorrupted system image

    .NOTES
        Command Arguments:
            1. Chkdsk
                /Scan - Runs an online scan on the system drive, attempts to fix any corruption, and queues other corruption for fixing on reboot
            2. SFC
                /ScanNow - Performs a scan of the system files and fixes any corruption
            3. DISM      - Fixes system image corruption, and fixes SFC's system image if it was corrupted
                /Online - Fixes the currently running system image
                /Cleanup-Image - Performs cleanup operations on the image, could remove some unneeded temporary files
                /Restorehealth - Performs a scan of the image and fixes any corruption

    #>
    Start-Process PowerShell -ArgumentList "Write-Host '(1/4) Chkdsk' -ForegroundColor Green; Chkdsk /scan;
    Write-Host '`n(2/4) SFC - 1st scan' -ForegroundColor Green; sfc /scannow;
    Write-Host '`n(3/4) DISM' -ForegroundColor Green; DISM /Online /Cleanup-Image /Restorehealth;
    Write-Host '`n(4/4) SFC - 2nd scan' -ForegroundColor Green; sfc /scannow;
    Read-Host '`nPress Enter to Continue'" -verb runas
}
function Invoke-WPFPopup {
    param (
        [ValidateSet("Show", "Hide", "Toggle")]
        [string]$Action = "",

        [string[]]$Popups = @(),

        [ValidateScript({
            $invalid = $_.GetEnumerator() | Where-Object { $_.Value -notin @("Show", "Hide", "Toggle") }
            if ($invalid) {
                throw "Found invalid Popup-Action pair(s): " + ($invalid | ForEach-Object { "$($_.Key) = $($_.Value)" } -join "; ")
            }
            $true
        })]
        [hashtable]$PopupActionTable = @{}
    )

    if (-not $PopupActionTable.Count -and (-not $Action -or -not $Popups.Count)) {
        throw "Provide either 'PopupActionTable' or both 'Action' and 'Popups'."
    }

    if ($PopupActionTable.Count -and ($Action -or $Popups.Count)) {
        throw "Use 'PopupActionTable' on its own, or 'Action' with 'Popups'."
    }

    # Collect popups and actions
    $PopupsToProcess = if ($PopupActionTable.Count) {
        $PopupActionTable.GetEnumerator() | ForEach-Object { [PSCustomObject]@{ Name = "$($_.Key)Popup"; Action = $_.Value } }
    } else {
        $Popups | ForEach-Object { [PSCustomObject]@{ Name = "$_`Popup"; Action = $Action } }
    }

    $PopupsNotFound = @()

    # Apply actions
    foreach ($popupEntry in $PopupsToProcess) {
        $popupName = $popupEntry.Name

        if (-not $sync.$popupName) {
            $PopupsNotFound += $popupName
            continue
        }

        $sync.$popupName.IsOpen = switch ($popupEntry.Action) {
            "Show" { $true }
            "Hide" { $false }
            "Toggle" { -not $sync.$popupName.IsOpen }
        }
    }

    if ($PopupsNotFound.Count -gt 0) {
        throw "Could not find the following popups: $($PopupsNotFound -join ', ')"
    }
}
function Invoke-WPFPresets {
    <#

    .SYNOPSIS
        Sets the options in the tweaks panel to the given preset

    .PARAMETER preset
        The preset to set the options to

    .PARAMETER imported
        If the preset is imported from a file, defaults to false

    .PARAMETER checkboxfilterpattern
        The Pattern to use when filtering through CheckBoxes, defaults to "**"

    #>

    param (
        [Parameter(position=0)]
        [Array]$preset = "",

        [Parameter(position=1)]
        [bool]$imported = $false,

        [Parameter(position=2)]
        [string]$checkboxfilterpattern = "**"
    )

    if ($imported -eq $true) {
        $CheckBoxesToCheck = $preset
    } else {
        $CheckBoxesToCheck = $sync.configs.preset.$preset
    }

    $CheckBoxes = ($sync.GetEnumerator()).where{ $_.Value -is [System.Windows.Controls.CheckBox] -and $_.Name -notlike "WPFToggle*" -and $_.Name -like "$checkboxfilterpattern"}
    Write-Debug "Getting checkboxes to set, number of checkboxes: $($CheckBoxes.Count)"

    if ($CheckBoxesToCheck -ne "") {
        $debugMsg = "CheckBoxes to Check are: "
        $CheckBoxesToCheck | ForEach-Object { $debugMsg += "$_, " }
        $debugMsg = $debugMsg -replace (',\s*$', '')
        Write-Debug "$debugMsg"
    }

    foreach ($CheckBox in $CheckBoxes) {
        $checkboxName = $CheckBox.Key

        if (-not $CheckBoxesToCheck) {
            $sync.$checkboxName.IsChecked = $false
            continue
        }

        # Check if the checkbox name exists in the flattened JSON hashtable
        if ($CheckBoxesToCheck -contains $checkboxName) {
            # If it exists, set IsChecked to true
            $sync.$checkboxName.IsChecked = $true
            Write-Debug "$checkboxName is checked"
        } else {
            # If it doesn't exist, set IsChecked to false
            $sync.$checkboxName.IsChecked = $false
            Write-Debug "$checkboxName is not checked"
        }
    }
}
function Invoke-WPFRunAdobeCCCleanerTool {
    <#
    .SYNOPSIS
        It removes or fixes problem files and resolves permission issues in registry keys.
    .DESCRIPTION
        The Creative Cloud Cleaner tool is a utility for experienced users to clean up corrupted installations.
    #>

    [string]$url="https://swupmf.adobe.com/webfeed/CleanerTool/win/AdobeCreativeCloudCleanerTool.exe"

    Write-Host "The Adobe Creative Cloud Cleaner tool is hosted at"
    Write-Host "$url"

    try {
        # Don't show the progress because it will slow down the download speed
        $ProgressPreference='SilentlyContinue'

        Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\AdobeCreativeCloudCleanerTool.exe" -UseBasicParsing -ErrorAction SilentlyContinue -Verbose

        # Revert back the ProgressPreference variable to the default value since we got the file desired
        $ProgressPreference='Continue'

        Start-Process -FilePath "$env:TEMP\AdobeCreativeCloudCleanerTool.exe" -Wait -ErrorAction SilentlyContinue -Verbose
    } catch {
        Write-Error $_.Exception.Message
    } finally {
        if (Test-Path -Path "$env:TEMP\AdobeCreativeCloudCleanerTool.exe") {
            Write-Host "Cleaning up..."
            Remove-Item -Path "$env:TEMP\AdobeCreativeCloudCleanerTool.exe" -Verbose
        }
    }
}
function Invoke-WPFRunspace {

    <#

    .SYNOPSIS
        Creates and invokes a runspace using the given scriptblock and argumentlist

    .PARAMETER ScriptBlock
        The scriptblock to invoke in the runspace

    .PARAMETER ArgumentList
        A list of arguments to pass to the runspace

    .PARAMETER ParameterList
        A list of named parameters that should be provided.
    .EXAMPLE
        Invoke-WPFRunspace `
            -ScriptBlock $sync.ScriptsInstallPrograms `
            -ArgumentList "Installadvancedip,Installbitwarden" `

        Invoke-WPFRunspace`
            -ScriptBlock $sync.ScriptsInstallPrograms `
            -ParameterList @(("PackagesToInstall", @("Installadvancedip,Installbitwarden")),("ChocoPreference", $true))
    #>

    [CmdletBinding()]
    Param (
        $ScriptBlock,
        $ArgumentList,
        $ParameterList,
        $DebugPreference
    )

    # Create a PowerShell instance
    $script:powershell = [powershell]::Create()

    # Add Scriptblock and Arguments to runspace
    $script:powershell.AddScript($ScriptBlock)
    $script:powershell.AddArgument($ArgumentList)

    foreach ($parameter in $ParameterList) {
        $script:powershell.AddParameter($parameter[0], $parameter[1])
    }
    $script:powershell.AddArgument($DebugPreference)  # Pass DebugPreference to the script block
    $script:powershell.RunspacePool = $sync.runspace

    # Execute the RunspacePool
    $script:handle = $script:powershell.BeginInvoke()

    # Clean up the RunspacePool threads when they are complete, and invoke the garbage collector to clean up the memory
    if ($script:handle.IsCompleted) {
        $script:powershell.EndInvoke($script:handle)
        $script:powershell.Dispose()
        $sync.runspace.Dispose()
        $sync.runspace.Close()
        [System.GC]::Collect()
    }
    # Return the handle
    return $handle
}
function Invoke-WPFSSHServer {
    <#

    .SYNOPSIS
        Invokes the OpenSSH Server install in a runspace

  #>

    Invoke-WPFRunspace -DebugPreference $DebugPreference -ScriptBlock {

        Invoke-WinUtilSSHServer

        Write-Host "======================================="
        Write-Host "--     OpenSSH Server installed!    ---"
        Write-Host "======================================="
    }
}
function Invoke-WPFTab {

    <#

    .SYNOPSIS
        Sets the selected tab to the tab that was clicked

    .PARAMETER ClickedTab
        The name of the tab that was clicked

    #>

    Param (
        [Parameter(Mandatory,position=0)]
        [string]$ClickedTab
    )

    $tabNav = Get-WinUtilVariables | Where-Object {$psitem -like "WPFTabNav"}
    $tabNumber = [int]($ClickedTab -replace "WPFTab","" -replace "BT","") - 1

    $filter = Get-WinUtilVariables -Type ToggleButton | Where-Object {$psitem -like "WPFTab?BT"}
    ($sync.GetEnumerator()).where{$psitem.Key -in $filter} | ForEach-Object {
        if ($ClickedTab -ne $PSItem.name) {
            $sync[$PSItem.Name].IsChecked = $false
        } else {
            $sync["$ClickedTab"].IsChecked = $true
            $tabNumber = [int]($ClickedTab-replace "WPFTab","" -replace "BT","") - 1
            $sync.$tabNav.Items[$tabNumber].IsSelected = $true
        }
    }
}
function Invoke-WPFTweakPS7{
        <#
    .SYNOPSIS
        This will edit the config file of the Windows Terminal Replacing the Powershell 5 to Powershell 7 and install Powershell 7 if necessary
    .PARAMETER action
        PS7:           Configures Powershell 7 to be the default Terminal
        PS5:           Configures Powershell 5 to be the default Terminal
    #>
    param (
        [ValidateSet("PS7", "PS5")]
        [string]$action
    )

    switch ($action) {
        "PS7"{
            if (Test-Path -Path "$env:ProgramFiles\PowerShell\7") {
                Write-Host "Powershell 7 is already installed."
            } else {
                Write-Host "Installing Powershell 7..."
                Install-WinUtilProgramWinget -Action Install -Programs @("Microsoft.PowerShell")
            }
            $targetTerminalName = "PowerShell"
        }
        "PS5"{
            $targetTerminalName = "Windows PowerShell"
        }
    }
    # Check if the Windows Terminal is installed and return if not (Prerequisite for the following code)
    if (-not (Get-Command "wt" -ErrorAction SilentlyContinue)) {
        Write-Host "Windows Terminal not installed. Skipping Terminal preference"
        return
    }
    # Check if the Windows Terminal settings.json file exists and return if not (Prereqisite for the following code)
    $settingsPath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
    if (-not (Test-Path -Path $settingsPath)) {
        Write-Host "Windows Terminal Settings file not found at $settingsPath"
        return
    }

    Write-Host "Settings file found."
    $settingsContent = Get-Content -Path $settingsPath | ConvertFrom-Json
    $ps7Profile = $settingsContent.profiles.list | Where-Object { $_.name -eq $targetTerminalName }
    if ($ps7Profile) {
        $settingsContent.defaultProfile = $ps7Profile.guid
        $updatedSettings = $settingsContent | ConvertTo-Json -Depth 100
        Set-Content -Path $settingsPath -Value $updatedSettings
        Write-Host "Default profile updated to " -NoNewline
        Write-Host "$targetTerminalName " -ForegroundColor White -NoNewline
        Write-Host "using the name attribute."
    } else {
        Write-Host "No PowerShell 7 profile found in Windows Terminal settings using the name attribute."
    }
}
function Invoke-WPFtweaksbutton {
  <#

    .SYNOPSIS
        Invokes the functions associated with each group of checkboxes

  #>

  if($sync.ProcessRunning) {
    $msg = "[Invoke-WPFtweaksbutton] Install process is currently running."
    [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
    return
  }

  $Tweaks = (Get-WinUtilCheckBoxes)["WPFTweaks"]

  Set-WinUtilDNS -DNSProvider $sync["WPFchangedns"].text

  if ($tweaks.count -eq 0 -and  $sync["WPFchangedns"].text -eq "Default") {
    $msg = "Please check the tweaks you wish to perform."
    [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
    return
  }

  Write-Debug "Number of tweaks to process: $($Tweaks.Count)"

  # The leading "," in the ParameterList is nessecary because we only provide one argument and powershell cannot be convinced that we want a nested loop with only one argument otherwise
  $tweaksHandle = Invoke-WPFRunspace -ParameterList @(,("tweaks",$tweaks)) -DebugPreference $DebugPreference -ScriptBlock {
    param(
      $tweaks,
      $DebugPreference
      )
    Write-Debug "Inside Number of tweaks to process: $($Tweaks.Count)"

    $sync.ProcessRunning = $true

    if ($Tweaks.count -eq 1) {
        $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Indeterminate" -value 0.01 -overlay "logo" })
    } else {
        $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Normal" -value 0.01 -overlay "logo" })
    }
    # Execute other selected tweaks

    for ($i = 0; $i -lt $Tweaks.Count; $i++) {
      Set-WinUtilProgressBar -Label "Applying $($tweaks[$i])" -Percent ($i / $tweaks.Count * 100)
      Invoke-WinUtilTweaks $tweaks[$i]
      $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -value ($i/$Tweaks.Count) })
    }
    Set-WinUtilProgressBar -Label "Tweaks finished" -Percent 100
    $sync.ProcessRunning = $false
    $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "None" -overlay "checkmark" })
    Write-Host "================================="
    Write-Host "--     Tweaks are Finished    ---"
    Write-Host "================================="

    # $ButtonType = [System.Windows.MessageBoxButton]::OK
    # $MessageboxTitle = "Tweaks are Finished "
    # $Messageboxbody = ("Done")
    # $MessageIcon = [System.Windows.MessageBoxImage]::Information
    # [System.Windows.MessageBox]::Show($Messageboxbody, $MessageboxTitle, $ButtonType, $MessageIcon)
  }
}
function Invoke-WPFUIElements {
    <#
    .SYNOPSIS
        Adds UI elements to a specified Grid in the WinUtil GUI based on a JSON configuration.
    .PARAMETER configVariable
        The variable/link containing the JSON configuration.
    .PARAMETER targetGridName
        The name of the grid to which the UI elements should be added.
    .PARAMETER columncount
        The number of columns to be used in the Grid. If not provided, a default value is used based on the panel.
    .EXAMPLE
        Invoke-WPFUIElements -configVariable $sync.configs.applications -targetGridName "install" -columncount 5
    .NOTES
        Future me/contributer: If possible please wrap this into a runspace to make it load all panels at the same time.
    #>

    param(
        [Parameter(Mandatory, position=0)]
        [PSCustomObject]$configVariable,

        [Parameter(Mandatory, position=1)]
        [string]$targetGridName,

        [Parameter(Mandatory, position=2)]
        [int]$columncount
    )

    $window = $sync["Form"]

    $theme = $sync.Form.Resources
    $borderstyle = $window.FindResource("BorderStyle")
    $HoverTextBlockStyle = $window.FindResource("HoverTextBlockStyle")
    $ColorfulToggleSwitchStyle = $window.FindResource("ColorfulToggleSwitchStyle")

    if (!$borderstyle -or !$HoverTextBlockStyle -or !$ColorfulToggleSwitchStyle) {
        throw "Failed to retrieve Styles using 'FindResource' from main window element."
    }

    $targetGrid = $window.FindName($targetGridName)

    if (!$targetGrid) {
        throw "Failed to retrieve Target Grid by name, provided name: $targetGrid"
    }

    # Clear existing ColumnDefinitions and Children
    $targetGrid.ColumnDefinitions.Clear() | Out-Null
    $targetGrid.Children.Clear() | Out-Null

    # Add ColumnDefinitions to the target Grid
    for ($i = 0; $i -lt $columncount; $i++) {
        $colDef = New-Object Windows.Controls.ColumnDefinition
        $colDef.Width = New-Object Windows.GridLength(1, [Windows.GridUnitType]::Star)
        $targetGrid.ColumnDefinitions.Add($colDef) | Out-Null
    }

    # Convert PSCustomObject to Hashtable
    $configHashtable = @{}
    $configVariable.PSObject.Properties.Name | ForEach-Object {
        $configHashtable[$_] = $configVariable.$_
    }

    $organizedData = @{}
    # Iterate through JSON data and organize by panel and category
    foreach ($entry in $configHashtable.Keys) {
        $entryInfo = $configHashtable[$entry]

        # Create an object for the application
        $entryObject = [PSCustomObject]@{
            Name = $entry
            Order = $entryInfo.order
            Category = $entryInfo.Category
            Content = $entryInfo.Content
            Choco = $entryInfo.choco
            Winget = $entryInfo.winget
            Panel = if ($entryInfo.Panel) { $entryInfo.Panel } else { "0" }
            Link = $entryInfo.link
            Description = $entryInfo.description
            Type = $entryInfo.type
            ComboItems = $entryInfo.ComboItems
            Checked = $entryInfo.Checked
            ButtonWidth = $entryInfo.ButtonWidth
        }

        if (-not $organizedData.ContainsKey($entryObject.Panel)) {
            $organizedData[$entryObject.Panel] = @{}
        }

        if (-not $organizedData[$entryObject.Panel].ContainsKey($entryObject.Category)) {
            $organizedData[$entryObject.Panel][$entryObject.Category] = @()
        }

        # Store application data in an array under the category
        $organizedData[$entryObject.Panel][$entryObject.Category] += $entryObject

        # Only apply the logic for distributing entries across columns if the targetGridName is "appspanel"
        if ($targetGridName -eq "appspanel") {
            $panelcount = 0
            $entrycount = $configHashtable.Keys.Count + $organizedData["0"].Keys.Count
            $maxcount = [Math]::Round($entrycount / $columncount + 0.5)
        }

    }

    # Iterate through 'organizedData' by panel, category, and application
    $count = 0
    foreach ($panelKey in ($organizedData.Keys | Sort-Object)) {
        # Create a Border for each column
        $border = New-Object Windows.Controls.Border
        $border.VerticalAlignment = "Stretch"
        [System.Windows.Controls.Grid]::SetColumn($border, $panelcount)
        $border.style = $borderstyle
        $targetGrid.Children.Add($border) | Out-Null

        # Create a StackPanel inside the Border
        $stackPanel = New-Object Windows.Controls.StackPanel
        $stackPanel.Background = [Windows.Media.Brushes]::Transparent
        $stackPanel.SnapsToDevicePixels = $true
        $stackPanel.VerticalAlignment = "Stretch"
        $border.Child = $stackPanel
        $panelcount++

        # Add Windows Version label if this is the updates panel
        if ($targetGridName -eq "updatespanel") {
            $windowsVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
            $versionLabel = New-Object Windows.Controls.Label
            $versionLabel.Content = "Windows Version: $windowsVersion"
            $versionLabel.FontSize = $theme.FontSize
            $versionLabel.HorizontalAlignment = "Left"
            $stackPanel.Children.Add($versionLabel) | Out-Null
        }

        foreach ($category in ($organizedData[$panelKey].Keys | Sort-Object)) {
            $count++
            if ($targetGridName -eq "appspanel" -and $columncount -gt 0) {
                $panelcount2 = [Int](($count) / $maxcount - 0.5)
                if ($panelcount -eq $panelcount2) {
                    # Create a new Border for the new column
                    $border = New-Object Windows.Controls.Border
                    $border.VerticalAlignment = "Stretch"
                    [System.Windows.Controls.Grid]::SetColumn($border, $panelcount)
                    $border.style = $borderstyle
                    $targetGrid.Children.Add($border) | Out-Null

                    # Create a new StackPanel inside the Border
                    $stackPanel = New-Object Windows.Controls.StackPanel
                    $stackPanel.Background = [Windows.Media.Brushes]::Transparent
                    $stackPanel.SnapsToDevicePixels = $true
                    $stackPanel.VerticalAlignment = "Stretch"
                    $border.Child = $stackPanel
                    $panelcount++
                }
            }

            $label = New-Object Windows.Controls.Label
            $label.Content = $category -replace ".*__", ""
            $label.FontSize = $theme.HeadingFontSize
            $label.FontFamily = $theme.HeaderFontFamily
            $stackPanel.Children.Add($label) | Out-Null

            $sync[$category] = $label

            # Sort entries by Order and then by Name, but only display Name
            $entries = $organizedData[$panelKey][$category] | Sort-Object Order, Name
            foreach ($entryInfo in $entries) {
                $count++
                if ($targetGridName -eq "appspanel" -and $columncount -gt 0) {
                    $panelcount2 = [Int](($count) / $maxcount - 0.5)
                    if ($panelcount -eq $panelcount2) {
                        # Create a new Border for the new column
                        $border = New-Object Windows.Controls.Border
                        $border.VerticalAlignment = "Stretch"
                        [System.Windows.Controls.Grid]::SetColumn($border, $panelcount)
                        $border.style = $borderstyle
                        $targetGrid.Children.Add($border) | Out-Null

                        # Create a new StackPanel inside the Border
                        $stackPanel = New-Object Windows.Controls.StackPanel
                        $stackPanel.Background = [Windows.Media.Brushes]::Transparent
                        $stackPanel.SnapsToDevicePixels = $true
                        $stackPanel.VerticalAlignment = "Stretch"
                        $border.Child = $stackPanel
                        $panelcount++
                    }
                }

                switch ($entryInfo.Type) {
                    "Toggle" {
                        $dockPanel = New-Object Windows.Controls.DockPanel
                        $checkBox = New-Object Windows.Controls.CheckBox
                        $checkBox.Name = $entryInfo.Name
                        $checkBox.HorizontalAlignment = "Right"
                        $dockPanel.Children.Add($checkBox) | Out-Null
                        $checkBox.Style = $ColorfulToggleSwitchStyle

                        $label = New-Object Windows.Controls.Label
                        $label.Content = $entryInfo.Content
                        $label.ToolTip = $entryInfo.Description
                        $label.HorizontalAlignment = "Left"
                        $label.FontSize = $theme.FontSize
                        $label.SetResourceReference([Windows.Controls.Control]::ForegroundProperty, "MainForegroundColor")
                        $dockPanel.Children.Add($label) | Out-Null
                        $stackPanel.Children.Add($dockPanel) | Out-Null

                        $sync[$entryInfo.Name] = $checkBox

                        $sync[$entryInfo.Name].IsChecked = (Get-WinUtilToggleStatus $entryInfo.Name)

                        $sync[$entryInfo.Name].Add_Checked({
                            [System.Object]$Sender = $args[0]
                            Invoke-WinUtilTweaks $sender.name
                        })

                        $sync[$entryInfo.Name].Add_Unchecked({
                            [System.Object]$Sender = $args[0]
                            Invoke-WinUtiltweaks $sender.name -undo $true
                        })
                    }

                    "ToggleButton" {
                        $toggleButton = New-Object Windows.Controls.ToggleButton
                        $toggleButton.Name = $entryInfo.Name
                        $toggleButton.Name = "WPFTab" + ($stackPanel.Children.Count + 1) + "BT"
                        $toggleButton.HorizontalAlignment = "Left"
                        $toggleButton.Height = $theme.TabButtonHeight
                        $toggleButton.Width = $theme.TabButtonWidth
                        $toggleButton.SetResourceReference([Windows.Controls.Control]::BackgroundProperty, "ButtonInstallBackgroundColor")
                        $toggleButton.SetResourceReference([Windows.Controls.Control]::ForegroundProperty, "MainForegroundColor")
                        $toggleButton.FontWeight = [Windows.FontWeights]::Bold

                        $textBlock = New-Object Windows.Controls.TextBlock
                        $textBlock.FontSize = $theme.TabButtonFontSize
                        $textBlock.Background = [Windows.Media.Brushes]::Transparent
                        $textBlock.SetResourceReference([Windows.Controls.Control]::ForegroundProperty, "ButtonInstallForegroundColor")

                        $underline = New-Object Windows.Documents.Underline
                        $underline.Inlines.Add($entryInfo.name -replace "(.).*", "`$1")

                        $run = New-Object Windows.Documents.Run
                        $run.Text = $entryInfo.name -replace "^.", ""

                        $textBlock.Inlines.Add($underline)
                        $textBlock.Inlines.Add($run)

                        $toggleButton.Content = $textBlock

                        $stackPanel.Children.Add($toggleButton) | Out-Null

                        $sync[$entryInfo.Name] = $toggleButton
                    }

                    "Combobox" {
                        $horizontalStackPanel = New-Object Windows.Controls.StackPanel
                        $horizontalStackPanel.Orientation = "Horizontal"
                        $horizontalStackPanel.Margin = "0,5,0,0"

                        $label = New-Object Windows.Controls.Label
                        $label.Content = $entryInfo.Content
                        $label.HorizontalAlignment = "Left"
                        $label.VerticalAlignment = "Center"
                        $label.FontSize = $theme.ButtonFontSize
                        $horizontalStackPanel.Children.Add($label) | Out-Null

                        $comboBox = New-Object Windows.Controls.ComboBox
                        $comboBox.Name = $entryInfo.Name
                        $comboBox.Height = $theme.ButtonHeight
                        $comboBox.Width = $theme.ButtonWidth
                        $comboBox.HorizontalAlignment = "Left"
                        $comboBox.VerticalAlignment = "Center"
                        $comboBox.Margin = $theme.ButtonMargin

                        foreach ($comboitem in ($entryInfo.ComboItems -split " ")) {
                            $comboBoxItem = New-Object Windows.Controls.ComboBoxItem
                            $comboBoxItem.Content = $comboitem
                            $comboBoxItem.FontSize = $theme.ButtonFontSize
                            $comboBox.Items.Add($comboBoxItem) | Out-Null
                        }

                        $horizontalStackPanel.Children.Add($comboBox) | Out-Null
                        $stackPanel.Children.Add($horizontalStackPanel) | Out-Null

                        $comboBox.SelectedIndex = 0

                        $sync[$entryInfo.Name] = $comboBox
                    }

                    "Button" {
                        $button = New-Object Windows.Controls.Button
                        $button.Name = $entryInfo.Name
                        $button.Content = $entryInfo.Content
                        $button.HorizontalAlignment = "Left"
                        $button.Margin = $theme.ButtonMargin
                        $button.FontSize = $theme.ButtonFontSize
                        if ($entryInfo.ButtonWidth) {
                            $button.Width = $entryInfo.ButtonWidth
                        }
                        $stackPanel.Children.Add($button) | Out-Null

                        $sync[$entryInfo.Name] = $button
                    }

                    default {
                        $horizontalStackPanel = New-Object Windows.Controls.StackPanel
                        $horizontalStackPanel.Orientation = "Horizontal"

                        $checkBox = New-Object Windows.Controls.CheckBox
                        $checkBox.Name = $entryInfo.Name
                        $checkBox.Content = $entryInfo.Content
                        $checkBox.FontSize = $theme.FontSize
                        $checkBox.ToolTip = $entryInfo.Description
                        $checkBox.Margin = $theme.CheckBoxMargin
                        if ($entryInfo.Checked -eq $true) {
                            $checkBox.IsChecked = $entryInfo.Checked
                        }
                        $horizontalStackPanel.Children.Add($checkBox) | Out-Null

                        if ($entryInfo.Link) {
                            $textBlock = New-Object Windows.Controls.TextBlock
                            $textBlock.Name = $checkBox.Name + "Link"
                            $textBlock.Text = "(?)"
                            $textBlock.ToolTip = $entryInfo.Link
                            $textBlock.Style = $HoverTextBlockStyle

                            $horizontalStackPanel.Children.Add($textBlock) | Out-Null

                            $sync[$textBlock.Name] = $textBlock
                        }

                        $stackPanel.Children.Add($horizontalStackPanel) | Out-Null
                        $sync[$entryInfo.Name] = $checkBox
                    }
                }
            }
        }
    }
}
Function Invoke-WPFUltimatePerformance {
    <#

    .SYNOPSIS
        Enables or disables the Ultimate Performance power scheme based on its GUID.

    .PARAMETER State
        Specifies whether to "Enable" or "Disable" the Ultimate Performance power scheme.

    #>
    param($State)

    try {
        # GUID of the Ultimate Performance power plan
        $ultimateGUID = "e9a42b02-d5df-448d-aa00-03f14749eb61"

        if ($State -eq "Enable") {
            # Duplicate the Ultimate Performance power plan using its GUID
            $duplicateOutput = powercfg /duplicatescheme $ultimateGUID

            $guid = $null
            $nameFromFile = "ChrisTitus - Ultimate Power Plan"
            $description = "Ultimate Power Plan, added via WinUtils"

            # Extract the new GUID from the duplicateOutput
            foreach ($line in $duplicateOutput) {
                if ($line -match "\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b") {
                    $guid = $matches[0]  # $matches[0] will contain the first match, which is the GUID
                    Write-Output "GUID: $guid has been extracted and stored in the variable."
                    break
                }
            }

            if (-not $guid) {
                Write-Output "No GUID found in the duplicateOutput. Check the output format."
                exit 1
            }

            # Change the name of the power plan and set its description
            $changeNameOutput = powercfg /changename $guid "$nameFromFile" "$description"
            Write-Output "The power plan name and description have been changed. Output:"
            Write-Output $changeNameOutput

            # Set the duplicated Ultimate Performance plan as active
            $setActiveOutput = powercfg /setactive $guid
            Write-Output "The power plan has been set as active. Output:"
            Write-Output $setActiveOutput

            Write-Host "> Ultimate Performance plan installed and set as active."

        } elseif ($State -eq "Disable") {
            # Check if the Ultimate Performance plan is installed by GUID
            $installedPlan = (powercfg -list | Select-String -Pattern "ChrisTitus - Ultimate Power Plan").Line.Split()[3]

            if ($installedPlan) {
                # Extract the GUID of the installed Ultimate Performance plan
                $ultimatePlanGUID = $installedPlan.Line.Split()[3]

                # Set a different power plan as active before deleting the Ultimate Performance plan
                $balancedPlanGUID = 381b4222-f694-41f0-9685-ff5bb260df2e
                powercfg -setactive $balancedPlanGUID

                # Delete the Ultimate Performance plan by GUID
                powercfg -delete $ultimatePlanGUID

                Write-Host "Ultimate Performance plan has been uninstalled."
                Write-Host "> Balanced plan is now active."
            } else {
                Write-Host "Ultimate Performance plan is not installed."
            }
        }
    } catch {
        Write-Error "Error occurred: $_"
    }
}
function Invoke-WPFundoall {
    <#

    .SYNOPSIS
        Undoes every selected tweak

    #>

    if($sync.ProcessRunning) {
        $msg = "[Invoke-WPFundoall] Install process is currently running."
        [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $tweaks = (Get-WinUtilCheckBoxes)["WPFtweaks"]

    if ($tweaks.count -eq 0) {
        $msg = "Please check the tweaks you wish to undo."
        [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    Invoke-WPFRunspace -ArgumentList $tweaks -DebugPreference $DebugPreference -ScriptBlock {
        param($tweaks, $DebugPreference)

        $sync.ProcessRunning = $true
        if ($tweaks.count -eq 1) {
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Indeterminate" -value 0.01 -overlay "logo" })
        } else {
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Normal" -value 0.01 -overlay "logo" })
        }


        for ($i = 0; $i -lt $tweaks.Count; $i++) {
            Set-WinUtilProgressBar -Label "Undoing $($tweaks[$i])" -Percent ($i / $tweaks.Count * 100)
            Invoke-WinUtiltweaks $tweaks[$i] -undo $true
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -value ($i/$tweaks.Count) })
        }

        Set-WinUtilProgressBar -Label "Undo Tweaks Finished" -Percent 100
        $sync.ProcessRunning = $false
        $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "None" -overlay "checkmark" })
        Write-Host "=================================="
        Write-Host "---  Undo Tweaks are Finished  ---"
        Write-Host "=================================="

    }
}
function Invoke-WPFUnInstall {
    <#

    .SYNOPSIS
        Uninstalls the selected programs

    #>

    if($sync.ProcessRunning) {
        $msg = "[Invoke-WPFUnInstall] Install process is currently running"
        [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $PackagesToInstall = (Get-WinUtilCheckBoxes)["Install"]

    if ($PackagesToInstall.Count -eq 0) {
        $WarningMsg = "Please select the program(s) to uninstall"
        [System.Windows.MessageBox]::Show($WarningMsg, $AppTitle, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $ButtonType = [System.Windows.MessageBoxButton]::YesNo
    $MessageboxTitle = "Are you sure?"
    $Messageboxbody = ("This will uninstall the following applications: `n $($PackagesToInstall | Format-Table | Out-String)")
    $MessageIcon = [System.Windows.MessageBoxImage]::Information

    $confirm = [System.Windows.MessageBox]::Show($Messageboxbody, $MessageboxTitle, $ButtonType, $MessageIcon)

    if($confirm -eq "No") {return}
    $ChocoPreference = $($sync.WPFpreferChocolatey.IsChecked)

    Invoke-WPFRunspace -ArgumentList @(("PackagesToInstall", $PackagesToInstall),("ChocoPreference", $ChocoPreference)) -DebugPreference $DebugPreference -ScriptBlock {
        param($PackagesToInstall, $ChocoPreference, $DebugPreference)
        if ($PackagesToInstall.count -eq 1) {
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Indeterminate" -value 0.01 -overlay "logo" })
        } else {
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Normal" -value 0.01 -overlay "logo" })
        }
        $packagesWinget, $packagesChoco = {
            $packagesWinget = [System.Collections.ArrayList]::new()
            $packagesChoco = [System.Collections.ArrayList]::new()

        foreach ($package in $PackagesToInstall) {
            if ($ChocoPreference) {
                if ($package.choco -eq "na") {
                    $packagesWinget.add($package.winget)
                    Write-Host "Queueing $($package.winget) for Winget uninstall"
                } else {
                    $null = $packagesChoco.add($package.choco)
                    Write-Host "Queueing $($package.choco) for Chocolatey uninstall"
                }
            }
            else {
                if ($package.winget -eq "na") {
                    $packagesChoco.add($package.choco)
                    Write-Host "Queueing $($package.choco) for Chocolatey uninstall"
                } else {
                    $null = $packagesWinget.add($($package.winget))
                    Write-Host "Queueing $($package.winget) for Winget uninstall"
                }
            }
        }
        return $packagesWinget, $packagesChoco
        }.Invoke($PackagesToInstall)

        try {
            $sync.ProcessRunning = $true

            # Install all selected programs in new window
            if($packagesWinget.Count -gt 0) {
                Install-WinUtilProgramWinget -Action Uninstall -Programs $packagesWinget
            }
            if($packagesChoco.Count -gt 0) {
                Install-WinUtilProgramChoco -Action Uninstall -Programs $packagesChoco
            }

            Write-Host "==========================================="
            Write-Host "--       Uninstalls have finished       ---"
            Write-Host "==========================================="
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "None" -overlay "checkmark" })
        } catch {
            Write-Host "==========================================="
            Write-Host "Error: $_"
            Write-Host "==========================================="
            $sync.form.Dispatcher.Invoke([action]{ Set-WinUtilTaskbaritem -state "Error" -overlay "warning" })
        }
        $sync.ProcessRunning = $False

    }
}
function Invoke-WPFUpdatesdefault {
    <#

    .SYNOPSIS
        Resets Windows Update settings to default

    #>
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 3
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1

    $services = @(
        "BITS"
        "wuauserv"
    )

    foreach ($service in $services) {
        # -ErrorAction SilentlyContinue is so it doesn't write an error to stdout if a service doesn't exist

        Write-Host "Setting $service StartupType to Automatic"
        Get-Service -Name $service -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic
    }
    Write-Host "Enabling driver offering through Windows Update..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
    Write-Host "Enabling Windows Update automatic restart..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue
    Write-Host "Enabled driver offering through Windows Update"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
    Write-Host "==================================================="
    Write-Host "---  Windows Update Settings Reset to Default   ---"
    Write-Host "==================================================="

    Start-Process -FilePath "secedit" -ArgumentList "/configure /cfg $env:windir\inf\defltbase.inf /db defltbase.sdb /verbose" -Wait
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c RD /S /Q $env:WinDir\System32\GroupPolicyUsers" -Wait
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c RD /S /Q $env:WinDir\System32\GroupPolicy" -Wait
    Start-Process -FilePath "gpupdate" -ArgumentList "/force" -Wait
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Microsoft\WindowsSelfHost" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Microsoft\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Microsoft\WindowsSelfHost" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\WOW6432Node\Microsoft\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "==================================================="
    Write-Host "---  Windows Local Policies Reset to Default   ---"
    Write-Host "==================================================="
}
function Invoke-WPFUpdatesdisable {
    <#

    .SYNOPSIS
        Disables Windows Update

    .NOTES
        Disabling Windows Update is not recommended. This is only for advanced users who know what they are doing.

    #>
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 1
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0

    $services = @(
        "BITS"
        "wuauserv"
    )

    foreach ($service in $services) {
        # -ErrorAction SilentlyContinue is so it doesn't write an error to stdout if a service doesn't exist

        Write-Host "Setting $service StartupType to Disabled"
        Get-Service -Name $service -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
    }
    Write-Host "================================="
    Write-Host "---   Updates ARE DISABLED    ---"
    Write-Host "================================="
}
function Invoke-WPFUpdatessecurity {
    <#

    .SYNOPSIS
        Sets Windows Update to recommended settings

    .DESCRIPTION
        1. Disables driver offering through Windows Update
        2. Disables Windows Update automatic restart
        3. Sets Windows Update to Semi-Annual Channel (Targeted)
        4. Defers feature updates for 365 days
        5. Defers quality updates for 4 days

    #>
    Write-Host "Disabling driver offering through Windows Update..."
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
        Write-Host "Disabling Windows Update automatic restart..."
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
        Write-Host "Disabled driver offering through Windows Update"
        If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings")) {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -Type DWord -Value 20
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4

        $ButtonType = [System.Windows.MessageBoxButton]::OK
        $MessageboxTitle = "Set Security Updates"
        $Messageboxbody = ("Recommended Update settings loaded")
        $MessageIcon = [System.Windows.MessageBoxImage]::Information

        [System.Windows.MessageBox]::Show($Messageboxbody, $MessageboxTitle, $ButtonType, $MessageIcon)
        Write-Host "================================="
        Write-Host "-- Updates Set to Recommended ---"
        Write-Host "================================="
}
$sync.configs.applications = @'
{
  "WPFInstall1password": {
    "category": "Utilities",
    "choco": "1password",
    "content": "1Password",
    "description": "1Password is a password manager that allows you to store and manage your passwords securely.",
    "link": "https://1password.com/",
    "winget": "AgileBits.1Password"
  },
  "WPFInstall7zip": {
    "category": "Utilities",
    "choco": "7zip",
    "content": "7-Zip",
    "description": "7-Zip is a free and open-source file archiver utility. It supports several compression formats and provides a high compression ratio, making it a popular choice for file compression.",
    "link": "https://www.7-zip.org/",
    "winget": "7zip.7zip"
  },
  "WPFInstalladobe": {
    "category": "Document",
    "choco": "adobereader",
    "content": "Adobe Acrobat Reader",
    "description": "Adobe Acrobat Reader is a free PDF viewer with essential features for viewing, printing, and annotating PDF documents.",
    "link": "https://www.adobe.com/acrobat/pdf-reader.html",
    "winget": "Adobe.Acrobat.Reader.64-bit"
  },
  "WPFInstalladvancedip": {
    "category": "Pro Tools",
    "choco": "advanced-ip-scanner",
    "content": "Advanced IP Scanner",
    "description": "Advanced IP Scanner is a fast and easy-to-use network scanner. It is designed to analyze LAN networks and provides information about connected devices.",
    "link": "https://www.advanced-ip-scanner.com/",
    "winget": "Famatech.AdvancedIPScanner"
  },
  "WPFInstallaffine": {
    "category": "Document",
    "choco": "na",
    "content": "AFFiNE",
    "description": "AFFiNE is an open source alternative to Notion. Write, draw, plan all at once. Selfhost it to sync across devices.",
    "link": "https://affine.pro/",
    "winget": "ToEverything.AFFiNE"
  },
  "WPFInstallaimp": {
    "category": "Multimedia Tools",
    "choco": "aimp",
    "content": "AIMP (Music Player)",
    "description": "AIMP is a feature-rich music player with support for various audio formats, playlists, and customizable user interface.",
    "link": "https://www.aimp.ru/",
    "winget": "AIMP.AIMP"
  },
  "WPFInstallalacritty": {
    "category": "Utilities",
    "choco": "alacritty",
    "content": "Alacritty Terminal",
    "description": "Alacritty is a fast, cross-platform, and GPU-accelerated terminal emulator. It is designed for performance and aims to be the fastest terminal emulator available.",
    "link": "https://alacritty.org/",
    "winget": "Alacritty.Alacritty"
  },
  "WPFInstallanaconda3": {
    "category": "Development",
    "choco": "anaconda3",
    "content": "Anaconda",
    "description": "Anaconda is a distribution of the Python and R programming languages for scientific computing.",
    "link": "https://www.anaconda.com/products/distribution",
    "winget": "Anaconda.Anaconda3"
  },
  "WPFInstallangryipscanner": {
    "category": "Pro Tools",
    "choco": "angryip",
    "content": "Angry IP Scanner",
    "description": "Angry IP Scanner is an open-source and cross-platform network scanner. It is used to scan IP addresses and ports, providing information about network connectivity.",
    "link": "https://angryip.org/",
    "winget": "angryziber.AngryIPScanner"
  },
  "WPFInstallanki": {
    "category": "Document",
    "choco": "anki",
    "content": "Anki",
    "description": "Anki is a flashcard application that helps you memorize information with intelligent spaced repetition.",
    "link": "https://apps.ankiweb.net/",
    "winget": "Anki.Anki"
  },
  "WPFInstallanydesk": {
    "category": "Utilities",
    "choco": "anydesk",
    "content": "AnyDesk",
    "description": "AnyDesk is a remote desktop software that enables users to access and control computers remotely. It is known for its fast connection and low latency.",
    "link": "https://anydesk.com/",
    "winget": "AnyDeskSoftwareGmbH.AnyDesk"
  },
  "WPFInstallaudacity": {
    "category": "Multimedia Tools",
    "choco": "audacity",
    "content": "Audacity",
    "description": "Audacity is a free and open-source audio editing software known for its powerful recording and editing capabilities.",
    "link": "https://www.audacityteam.org/",
    "winget": "Audacity.Audacity"
  },
  "WPFInstallautoruns": {
    "category": "Microsoft Tools",
    "choco": "autoruns",
    "content": "Autoruns",
    "description": "This utility shows you what programs are configured to run during system bootup or login",
    "link": "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    "winget": "Microsoft.Sysinternals.Autoruns"
  },
  "WPFInstallrdcman": {
    "category": "Microsoft Tools",
    "choco": "rdcman",
    "content": "RDCMan",
    "description": "RDCMan manages multiple remote desktop connections. It is useful for managing server labs where you need regular access to each machine such as automated checkin systems and data centers.",
    "link": "https://learn.microsoft.com/en-us/sysinternals/downloads/rdcman",
    "winget": "Microsoft.Sysinternals.RDCMan"
  },
  "WPFInstallautohotkey": {
    "category": "Utilities",
    "choco": "autohotkey",
    "content": "AutoHotkey",
    "description": "AutoHotkey is a scripting language for Windows that allows users to create custom automation scripts and macros. It is often used for automating repetitive tasks and customizing keyboard shortcuts.",
    "link": "https://www.autohotkey.com/",
    "winget": "AutoHotkey.AutoHotkey"
  },
  "WPFInstallazuredatastudio": {
    "category": "Microsoft Tools",
    "choco": "azure-data-studio",
    "content": "Microsoft Azure Data Studio",
    "description": "Azure Data Studio is a data management tool that enables you to work with SQL Server, Azure SQL DB and SQL DW from Windows, macOS and Linux.",
    "link": "https://docs.microsoft.com/sql/azure-data-studio/what-is-azure-data-studio",
    "winget": "Microsoft.AzureDataStudio"
  },
  "WPFInstallbarrier": {
    "category": "Utilities",
    "choco": "barrier",
    "content": "Barrier",
    "description": "Barrier is an open-source software KVM (keyboard, video, and mouseswitch). It allows users to control multiple computers with a single keyboard and mouse, even if they have different operating systems.",
    "link": "https://github.com/debauchee/barrier",
    "winget": "DebaucheeOpenSourceGroup.Barrier"
  },
  "WPFInstallbat": {
    "category": "Utilities",
    "choco": "bat",
    "content": "Bat (Cat)",
    "description": "Bat is a cat command clone with syntax highlighting. It provides a user-friendly and feature-rich alternative to the traditional cat command for viewing and concatenating files.",
    "link": "https://github.com/sharkdp/bat",
    "winget": "sharkdp.bat"
  },
  "WPFInstallbitwarden": {
    "category": "Utilities",
    "choco": "bitwarden",
    "content": "Bitwarden",
    "description": "Bitwarden is an open-source password management solution. It allows users to store and manage their passwords in a secure and encrypted vault, accessible across multiple devices.",
    "link": "https://bitwarden.com/",
    "winget": "Bitwarden.Bitwarden"
  },
  "WPFInstallbleachbit": {
    "category": "Utilities",
    "choco": "bleachbit",
    "content": "BleachBit",
    "description": "Clean Your System and Free Disk Space",
    "link": "https://www.bleachbit.org/",
    "winget": "BleachBit.BleachBit"
  },
  "WPFInstallblender": {
    "category": "Multimedia Tools",
    "choco": "blender",
    "content": "Blender (3D Graphics)",
    "description": "Blender is a powerful open-source 3D creation suite, offering modeling, sculpting, animation, and rendering tools.",
    "link": "https://www.blender.org/",
    "winget": "BlenderFoundation.Blender"
  },
  "WPFInstallbrave": {
    "category": "Browsers",
    "choco": "brave",
    "content": "Brave",
    "description": "Brave is a privacy-focused web browser that blocks ads and trackers, offering a faster and safer browsing experience.",
    "link": "https://www.brave.com",
    "winget": "Brave.Brave"
  },
  "WPFInstallbulkcrapuninstaller": {
    "category": "Utilities",
    "choco": "bulk-crap-uninstaller",
    "content": "Bulk Crap Uninstaller",
    "description": "Bulk Crap Uninstaller is a free and open-source uninstaller utility for Windows. It helps users remove unwanted programs and clean up their system by uninstalling multiple applications at once.",
    "link": "https://www.bcuninstaller.com/",
    "winget": "Klocman.BulkCrapUninstaller"
  },
  "WPFInstallbulkrenameutility": {
    "category": "Utilities",
    "choco": "bulkrenameutility",
    "content": "Bulk Rename Utility",
    "description": "Bulk Rename Utility allows you to easily rename files and folders recursively based upon find-replace, character place, fields, sequences, regular expressions, EXIF data, and more.",
    "link": "https://www.bulkrenameutility.co.uk",
    "winget": "TGRMNSoftware.BulkRenameUtility"
  },
  "WPFInstallAdvancedRenamer": {
    "category": "Utilities",
    "choco": "advanced-renamer",
    "content": "Advanced Renamer",
    "description": "Advanced Renamer is a program for renaming multiple files and folders at once. By configuring renaming methods the names can be manipulated in various ways.",
    "link": "https://www.advancedrenamer.com/",
    "winget": "HulubuluSoftware.AdvancedRenamer"
  },
  "WPFInstallcalibre": {
    "category": "Document",
    "choco": "calibre",
    "content": "Calibre",
    "description": "Calibre is a powerful and easy-to-use e-book manager, viewer, and converter.",
    "link": "https://calibre-ebook.com/",
    "winget": "calibre.calibre"
  },
  "WPFInstallcarnac": {
    "category": "Utilities",
    "choco": "carnac",
    "content": "Carnac",
    "description": "Carnac is a keystroke visualizer for Windows. It displays keystrokes in an overlay, making it useful for presentations, tutorials, and live demonstrations.",
    "link": "https://carnackeys.com/",
    "winget": "code52.Carnac"
  },
  "WPFInstallcemu": {
    "category": "Games",
    "choco": "cemu",
    "content": "Cemu",
    "description": "Cemu is a highly experimental software to emulate Wii U applications on PC.",
    "link": "https://cemu.info/",
    "winget": "Cemu.Cemu"
  },
  "WPFInstallchatterino": {
    "category": "Communications",
    "choco": "chatterino",
    "content": "Chatterino",
    "description": "Chatterino is a chat client for Twitch chat that offers a clean and customizable interface for a better streaming experience.",
    "link": "https://www.chatterino.com/",
    "winget": "ChatterinoTeam.Chatterino"
  },
  "WPFInstallchrome": {
    "category": "Browsers",
    "choco": "googlechrome",
    "content": "Chrome",
    "description": "Google Chrome is a widely used web browser known for its speed, simplicity, and seamless integration with Google services.",
    "link": "https://www.google.com/chrome/",
    "winget": "Google.Chrome"
  },
  "WPFInstallchromium": {
    "category": "Browsers",
    "choco": "chromium",
    "content": "Chromium",
    "description": "Chromium is the open-source project that serves as the foundation for various web browsers, including Chrome.",
    "link": "https://github.com/Hibbiki/chromium-win64",
    "winget": "Hibbiki.Chromium"
  },
  "WPFInstallarc": {
    "category": "Browsers",
    "choco": "na",
    "content": "ARC ~",
    "description": "Arc is a Chromium based browser, known for it's clean and modern design.",
    "link": "https://arc.net/",
    "winget": "TheBrowserCompany.Arc"
  },
  "WPFInstallclementine": {
    "category": "Multimedia Tools",
    "choco": "clementine",
    "content": "Clementine",
    "description": "Clementine is a modern music player and library organizer, supporting various audio formats and online radio services.",
    "link": "https://www.clementine-player.org/",
    "winget": "Clementine.Clementine"
  },
  "WPFInstallclink": {
    "category": "Development",
    "choco": "clink",
    "content": "Clink",
    "description": "Clink is a powerful Bash-compatible command-line interface (CLIenhancement for Windows, adding features like syntax highlighting and improved history).",
    "link": "https://mridgers.github.io/clink/",
    "winget": "chrisant996.Clink"
  },
  "WPFInstallclonehero": {
    "category": "Games",
    "choco": "na",
    "content": "Clone Hero",
    "description": "Clone Hero is a free rhythm game, which can be played with any 5 or 6 button guitar controller.",
    "link": "https://clonehero.net/",
    "winget": "CloneHeroTeam.CloneHero"
  },
  "WPFInstallcmake": {
    "category": "Development",
    "choco": "cmake",
    "content": "CMake",
    "description": "CMake is an open-source, cross-platform family of tools designed to build, test and package software.",
    "link": "https://cmake.org/",
    "winget": "Kitware.CMake"
  },
  "WPFInstallcopyq": {
    "category": "Utilities",
    "choco": "copyq",
    "content": "CopyQ (Clipboard Manager)",
    "description": "CopyQ is a clipboard manager with advanced features, allowing you to store, edit, and retrieve clipboard history.",
    "link": "https://copyq.readthedocs.io/",
    "winget": "hluk.CopyQ"
  },
  "WPFInstallcpuz": {
    "category": "Utilities",
    "choco": "cpu-z",
    "content": "CPU-Z",
    "description": "CPU-Z is a system monitoring and diagnostic tool for Windows. It provides detailed information about the computer's hardware components, including the CPU, memory, and motherboard.",
    "link": "https://www.cpuid.com/softwares/cpu-z.html",
    "winget": "CPUID.CPU-Z"
  },
  "WPFInstallcrystaldiskinfo": {
    "category": "Utilities",
    "choco": "crystaldiskinfo",
    "content": "Crystal Disk Info",
    "description": "Crystal Disk Info is a disk health monitoring tool that provides information about the status and performance of hard drives. It helps users anticipate potential issues and monitor drive health.",
    "link": "https://crystalmark.info/en/software/crystaldiskinfo/",
    "winget": "CrystalDewWorld.CrystalDiskInfo"
  },
  "WPFInstallcapframex": {
    "category": "Utilities",
    "choco": "na",
    "content": "CapFrameX",
    "description": "Frametimes capture and analysis tool based on Intel's PresentMon. Overlay provided by Rivatuner Statistics Server.",
    "link": "https://www.capframex.com/",
    "winget": "CXWorld.CapFrameX"
  },
  "WPFInstallcrystaldiskmark": {
    "category": "Utilities",
    "choco": "crystaldiskmark",
    "content": "Crystal Disk Mark",
    "description": "Crystal Disk Mark is a disk benchmarking tool that measures the read and write speeds of storage devices. It helps users assess the performance of their hard drives and SSDs.",
    "link": "https://crystalmark.info/en/software/crystaldiskmark/",
    "winget": "CrystalDewWorld.CrystalDiskMark"
  },
  "WPFInstalldarktable": {
    "category": "Multimedia Tools",
    "choco": "darktable",
    "content": "darktable",
    "description": "Open-source photo editing tool, offering an intuitive interface, advanced editing capabilities, and a non-destructive workflow for seamless image enhancement.",
    "link": "https://www.darktable.org/install/",
    "winget": "darktable.darktable"
  },
  "WPFInstallDaxStudio": {
    "category": "Development",
    "choco": "daxstudio",
    "content": "DaxStudio",
    "description": "DAX (Data Analysis eXpressions) Studio is the ultimate tool for executing and analyzing DAX queries against Microsoft Tabular models.",
    "link": "https://daxstudio.org/",
    "winget": "DaxStudio.DaxStudio"
  },
  "WPFInstallddu": {
    "category": "Utilities",
    "choco": "ddu",
    "content": "Display Driver Uninstaller",
    "description": "Display Driver Uninstaller (DDU) is a tool for completely uninstalling graphics drivers from NVIDIA, AMD, and Intel. It is useful for troubleshooting graphics driver-related issues.",
    "link": "https://www.wagnardsoft.com/display-driver-uninstaller-DDU-",
    "winget": "ddu"
  },
  "WPFInstalldeluge": {
    "category": "Utilities",
    "choco": "deluge",
    "content": "Deluge",
    "description": "Deluge is a free and open-source BitTorrent client. It features a user-friendly interface, support for plugins, and the ability to manage torrents remotely.",
    "link": "https://deluge-torrent.org/",
    "winget": "DelugeTeam.Deluge"
  },
  "WPFInstalldevtoys": {
    "category": "Utilities",
    "choco": "devtoys",
    "content": "DevToys",
    "description": "DevToys is a collection of development-related utilities and tools for Windows. It includes tools for file management, code formatting, and productivity enhancements for developers.",
    "link": "https://devtoys.app/",
    "winget": "DevToys-app.DevToys"
  },
  "WPFInstalldigikam": {
    "category": "Multimedia Tools",
    "choco": "digikam",
    "content": "digiKam",
    "description": "digiKam is an advanced open-source photo management software with features for organizing, editing, and sharing photos.",
    "link": "https://www.digikam.org/",
    "winget": "KDE.digikam"
  },
  "WPFInstalldiscord": {
    "category": "Communications",
    "choco": "discord",
    "content": "Discord",
    "description": "Discord is a popular communication platform with voice, video, and text chat, designed for gamers but used by a wide range of communities.",
    "link": "https://discord.com/",
    "winget": "Discord.Discord"
  },
  "WPFInstallditto": {
    "category": "Utilities",
    "choco": "ditto",
    "content": "Ditto",
    "description": "Ditto is an extension to the standard windows clipboard.",
    "link": "https://github.com/sabrogden/Ditto",
    "winget": "Ditto.Ditto"
  },
  "WPFInstalldockerdesktop": {
    "category": "Development",
    "choco": "docker-desktop",
    "content": "Docker Desktop",
    "description": "Docker Desktop is a powerful tool for containerized application development and deployment.",
    "link": "https://www.docker.com/products/docker-desktop",
    "winget": "Docker.DockerDesktop"
  },
  "WPFInstalldotnet3": {
    "category": "Microsoft Tools",
    "choco": "dotnetcore3-desktop-runtime",
    "content": ".NET Desktop Runtime 3.1",
    "description": ".NET Desktop Runtime 3.1 is a runtime environment required for running applications developed with .NET Core 3.1.",
    "link": "https://dotnet.microsoft.com/download/dotnet/3.1",
    "winget": "Microsoft.DotNet.DesktopRuntime.3_1"
  },
  "WPFInstalldotnet5": {
    "category": "Microsoft Tools",
    "choco": "dotnet-5.0-runtime",
    "content": ".NET Desktop Runtime 5",
    "description": ".NET Desktop Runtime 5 is a runtime environment required for running applications developed with .NET 5.",
    "link": "https://dotnet.microsoft.com/download/dotnet/5.0",
    "winget": "Microsoft.DotNet.DesktopRuntime.5"
  },
  "WPFInstalldotnet6": {
    "category": "Microsoft Tools",
    "choco": "dotnet-6.0-runtime",
    "content": ".NET Desktop Runtime 6",
    "description": ".NET Desktop Runtime 6 is a runtime environment required for running applications developed with .NET 6.",
    "link": "https://dotnet.microsoft.com/download/dotnet/6.0",
    "winget": "Microsoft.DotNet.DesktopRuntime.6"
  },
  "WPFInstalldotnet7": {
    "category": "Microsoft Tools",
    "choco": "dotnet-7.0-runtime",
    "content": ".NET Desktop Runtime 7",
    "description": ".NET Desktop Runtime 7 is a runtime environment required for running applications developed with .NET 7.",
    "link": "https://dotnet.microsoft.com/download/dotnet/7.0",
    "winget": "Microsoft.DotNet.DesktopRuntime.7"
  },
  "WPFInstalldotnet8": {
    "category": "Microsoft Tools",
    "choco": "dotnet-8.0-runtime",
    "content": ".NET Desktop Runtime 8",
    "description": ".NET Desktop Runtime 8 is a runtime environment required for running applications developed with .NET 8.",
    "link": "https://dotnet.microsoft.com/download/dotnet/8.0",
    "winget": "Microsoft.DotNet.DesktopRuntime.8"
  },
  "WPFInstalldotnet9": {
    "category": "Microsoft Tools",
    "choco": "dotnet-9.0-runtime",
    "content": ".NET Desktop Runtime 9",
    "description": ".NET Desktop Runtime 9 is a runtime environment required for running applications developed with .NET 9.",
    "link": "https://dotnet.microsoft.com/download/dotnet/9.0",
    "winget": "Microsoft.DotNet.DesktopRuntime.9"
  },
  "WPFInstalldmt": {
    "winget": "GNE.DualMonitorTools",
    "choco": "dual-monitor-tools",
    "category": "Utilities",
    "content": "Dual Monitor Tools",
    "link": "https://dualmonitortool.sourceforge.net/",
    "description": "Dual Monitor Tools (DMT) is a FOSS app that allows you to customize the handling of multiple monitors. Useful for fullscreen games and apps that handle a second monitor poorly and can improve your workflow."
  },
  "WPFInstallduplicati": {
    "category": "Utilities",
    "choco": "duplicati",
    "content": "Duplicati",
    "description": "Duplicati is an open-source backup solution that supports encrypted, compressed, and incremental backups. It is designed to securely store data on cloud storage services.",
    "link": "https://www.duplicati.com/",
    "winget": "Duplicati.Duplicati"
  },
  "WPFInstalleaapp": {
    "category": "Games",
    "choco": "ea-app",
    "content": "EA App",
    "description": "EA App is a platform for accessing and playing Electronic Arts games.",
    "link": "https://www.ea.com/ea-app",
    "winget": "ElectronicArts.EADesktop"
  },
  "WPFInstalleartrumpet": {
    "category": "Multimedia Tools",
    "choco": "eartrumpet",
    "content": "EarTrumpet (Audio)",
    "description": "EarTrumpet is an audio control app for Windows, providing a simple and intuitive interface for managing sound settings.",
    "link": "https://eartrumpet.app/",
    "winget": "File-New-Project.EarTrumpet"
  },
  "WPFInstalledge": {
    "category": "Browsers",
    "choco": "microsoft-edge",
    "content": "Edge",
    "description": "Microsoft Edge is a modern web browser built on Chromium, offering performance, security, and integration with Microsoft services.",
    "link": "https://www.microsoft.com/edge",
    "winget": "Microsoft.Edge"
  },
  "WPFInstallefibooteditor": {
    "category": "Pro Tools",
    "choco": "na",
    "content": "EFI Boot Editor",
    "description": "EFI Boot Editor is a tool for managing the EFI/UEFI boot entries on your system. It allows you to customize the boot configuration of your computer.",
    "link": "https://www.easyuefi.com/",
    "winget": "EFIBootEditor.EFIBootEditor"
  },
  "WPFInstallemulationstation": {
    "category": "Games",
    "choco": "emulationstation",
    "content": "Emulation Station",
    "description": "Emulation Station is a graphical and themeable emulator front-end that allows you to access all your favorite games in one place.",
    "link": "https://emulationstation.org/",
    "winget": "Emulationstation.Emulationstation"
  },
  "WPFInstallepicgames": {
    "category": "Games",
    "choco": "epicgameslauncher",
    "content": "Epic Games Launcher",
    "description": "Epic Games Launcher is the client for accessing and playing games from the Epic Games Store.",
    "link": "https://www.epicgames.com/store/en-US/",
    "winget": "EpicGames.EpicGamesLauncher"
  },
  "WPFInstallesearch": {
    "category": "Utilities",
    "choco": "everything",
    "content": "Everything Search",
    "description": "Everything Search is a fast and efficient file search utility for Windows.",
    "link": "https://www.voidtools.com/",
    "winget": "voidtools.Everything"
  },
  "WPFInstallespanso": {
    "category": "Utilities",
    "choco": "espanso",
    "content": "Espanso",
    "description": "Cross-platform and open-source Text Expander written in Rust",
    "link": "https://espanso.org/",
    "winget": "Espanso.Espanso"
  },
  "WPFInstalletcher": {
    "category": "Utilities",
    "choco": "etcher",
    "content": "Etcher USB Creator",
    "description": "Etcher is a powerful tool for creating bootable USB drives with ease.",
    "link": "https://www.balena.io/etcher/",
    "winget": "Balena.Etcher"
  },
  "WPFInstallfalkon": {
    "category": "Browsers",
    "choco": "falkon",
    "content": "Falkon",
    "description": "Falkon is a lightweight and fast web browser with a focus on user privacy and efficiency.",
    "link": "https://www.falkon.org/",
    "winget": "KDE.Falkon"
  },
  "WPFInstallfastfetch": {
    "category": "Utilities",
    "choco": "na",
    "content": "Fastfetch",
    "description": "Fastfetch is a neofetch-like tool for fetching system information and displaying them in a pretty way",
    "link": "https://github.com/fastfetch-cli/fastfetch/",
    "winget": "Fastfetch-cli.Fastfetch"
  },
  "WPFInstallferdium": {
    "category": "Communications",
    "choco": "ferdium",
    "content": "Ferdium",
    "description": "Ferdium is a messaging application that combines multiple messaging services into a single app for easy management.",
    "link": "https://ferdium.org/",
    "winget": "Ferdium.Ferdium"
  },
  "WPFInstallffmpeg": {
    "category": "Multimedia Tools",
    "choco": "ffmpeg-full",
    "content": "FFmpeg (full)",
    "description": "FFmpeg is a powerful multimedia processing tool that enables users to convert, edit, and stream audio and video files with a vast range of codecs and formats.",
    "link": "https://ffmpeg.org/",
    "winget": "Gyan.FFmpeg"
  },
  "WPFInstallfileconverter": {
    "category": "Utilities",
    "choco": "file-converter",
    "content": "File-Converter",
    "description": "File Converter is a very simple tool which allows you to convert and compress one or several file(s) using the context menu in windows explorer.",
    "link": "https://file-converter.io/",
    "winget": "AdrienAllard.FileConverter"
  },
  "WPFInstallfiles": {
    "category": "Utilities",
    "choco": "files",
    "content": "Files",
    "description": "Alternative file explorer.",
    "link": "https://github.com/files-community/Files",
    "winget": "na"
  },
  "WPFInstallfirealpaca": {
    "category": "Multimedia Tools",
    "choco": "firealpaca",
    "content": "Fire Alpaca",
    "description": "Fire Alpaca is a free digital painting software that provides a wide range of drawing tools and a user-friendly interface.",
    "link": "https://firealpaca.com/",
    "winget": "FireAlpaca.FireAlpaca"
  },
  "WPFInstallfirefox": {
    "category": "Browsers",
    "choco": "firefox",
    "content": "Firefox",
    "description": "Mozilla Firefox is an open-source web browser known for its customization options, privacy features, and extensions.",
    "link": "https://www.mozilla.org/en-US/firefox/new/",
    "winget": "Mozilla.Firefox"
  },
  "WPFInstallfirefoxesr": {
    "category": "Browsers",
    "choco": "FirefoxESR",
    "content": "Firefox ESR",
    "description": "Mozilla Firefox is an open-source web browser known for its customization options, privacy features, and extensions. Firefox ESR (Extended Support Release) receives major updates every 42 weeks with minor updates such as crash fixes, security fixes and policy updates as needed, but at least every four weeks.",
    "link": "https://www.mozilla.org/en-US/firefox/enterprise/",
    "winget": "Mozilla.Firefox.ESR"
  },
  "WPFInstallflameshot": {
    "category": "Multimedia Tools",
    "choco": "flameshot",
    "content": "Flameshot (Screenshots)",
    "description": "Flameshot is a powerful yet simple to use screenshot software, offering annotation and editing features.",
    "link": "https://flameshot.org/",
    "winget": "Flameshot.Flameshot"
  },
  "WPFInstalllightshot": {
    "category": "Multimedia Tools",
    "choco": "lightshot",
    "content": "Lightshot (Screenshots)",
    "description": "Ligthshot is an Easy-to-use, light-weight screenshot software tool, where you can optionally edit your screenshots using different tools, share them via Internet and/or save to disk, and customize the available options.",
    "link": "https://app.prntscr.com/",
    "winget": "Skillbrains.Lightshot"
  },
  "WPFInstallfloorp": {
    "category": "Browsers",
    "choco": "na",
    "content": "Floorp",
    "description": "Floorp is an open-source web browser project that aims to provide a simple and fast browsing experience.",
    "link": "https://floorp.app/",
    "winget": "Ablaze.Floorp"
  },
  "WPFInstallflow": {
    "category": "Utilities",
    "choco": "flow-launcher",
    "content": "Flow launcher",
    "description": "Keystroke launcher for Windows to search, manage and launch files, folders bookmarks, websites and more.",
    "link": "https://www.flowlauncher.com/",
    "winget": "Flow-Launcher.Flow-Launcher"
  },
  "WPFInstallflux": {
    "category": "Utilities",
    "choco": "flux",
    "content": "F.lux",
    "description": "f.lux adjusts the color temperature of your screen to reduce eye strain during nighttime use.",
    "link": "https://justgetflux.com/",
    "winget": "flux.flux"
  },
  "WPFInstallfoobar": {
    "category": "Multimedia Tools",
    "choco": "foobar2000",
    "content": "foobar2000 (Music Player)",
    "description": "foobar2000 is a highly customizable and extensible music player for Windows, known for its modular design and advanced features.",
    "link": "https://www.foobar2000.org/",
    "winget": "PeterPawlowski.foobar2000"
  },
  "WPFInstallfoxpdfeditor": {
    "category": "Document",
    "choco": "na",
    "content": "Foxit PDF Editor",
    "description": "Foxit PDF Editor is a feature-rich PDF editor and viewer with a familiar ribbon-style interface.",
    "link": "https://www.foxit.com/pdf-editor/",
    "winget": "Foxit.PhantomPDF"
  },
  "WPFInstallfoxpdfreader": {
    "category": "Document",
    "choco": "foxitreader",
    "content": "Foxit PDF Reader",
    "description": "Foxit PDF Reader is a free PDF viewer with a familiar ribbon-style interface.",
    "link": "https://www.foxit.com/pdf-reader/",
    "winget": "Foxit.FoxitReader"
  },
  "WPFInstallfreecad": {
    "category": "Multimedia Tools",
    "choco": "freecad",
    "content": "FreeCAD",
    "description": "FreeCAD is a parametric 3D CAD modeler, designed for product design and engineering tasks, with a focus on flexibility and extensibility.",
    "link": "https://www.freecadweb.org/",
    "winget": "FreeCAD.FreeCAD"
  },
  "WPFInstallfxsound": {
    "category": "Multimedia Tools",
    "choco": "fxsound",
    "content": "FxSound",
    "description": "FxSound is a cutting-edge audio enhancement software that elevates your listening experience across all media.",
    "link": "https://www.fxsound.com/",
    "winget": "FxSoundLLC.FxSound"
  },
  "WPFInstallfzf": {
    "category": "Utilities",
    "choco": "fzf",
    "content": "Fzf",
    "description": "A command-line fuzzy finder",
    "link": "https://github.com/junegunn/fzf/",
    "winget": "junegunn.fzf"
  },
  "WPFInstallgeforcenow": {
    "category": "Games",
    "choco": "nvidia-geforce-now",
    "content": "GeForce NOW",
    "description": "GeForce NOW is a cloud gaming service that allows you to play high-quality PC games on your device.",
    "link": "https://www.nvidia.com/en-us/geforce-now/",
    "winget": "Nvidia.GeForceNow"
  },
  "WPFInstallgimp": {
    "category": "Multimedia Tools",
    "choco": "gimp",
    "content": "GIMP (Image Editor)",
    "description": "GIMP is a versatile open-source raster graphics editor used for tasks such as photo retouching, image editing, and image composition.",
    "link": "https://www.gimp.org/",
    "winget": "GIMP.GIMP"
  },
  "WPFInstallgit": {
    "category": "Development",
    "choco": "git",
    "content": "Git",
    "description": "Git is a distributed version control system widely used for tracking changes in source code during software development.",
    "link": "https://git-scm.com/",
    "winget": "Git.Git"
  },
  "WPFInstallgitbutler": {
    "category": "Development",
    "choco": "na",
    "content": "Git Butler",
    "description": "A Git client for simultaneous branches on top of your existing workflow.",
    "link": "https://gitbutler.com/",
    "winget": "GitButler.GitButler"
  },
  "WPFInstallgitextensions": {
    "category": "Development",
    "choco": "git;gitextensions",
    "content": "Git Extensions",
    "description": "Git Extensions is a graphical user interface for Git, providing additional features for easier source code management.",
    "link": "https://gitextensions.github.io/",
    "winget": "GitExtensionsTeam.GitExtensions"
  },
  "WPFInstallgithubcli": {
    "category": "Development",
    "choco": "git;gh",
    "content": "GitHub CLI",
    "description": "GitHub CLI is a command-line tool that simplifies working with GitHub directly from the terminal.",
    "link": "https://cli.github.com/",
    "winget": "GitHub.cli"
  },
  "WPFInstallgithubdesktop": {
    "category": "Development",
    "choco": "git;github-desktop",
    "content": "GitHub Desktop",
    "description": "GitHub Desktop is a visual Git client that simplifies collaboration on GitHub repositories with an easy-to-use interface.",
    "link": "https://desktop.github.com/",
    "winget": "GitHub.GitHubDesktop"
  },
  "WPFInstallgitkrakenclient": {
    "category": "Development",
    "choco": "gitkraken",
    "content": "GitKraken Client",
    "description": "GitKraken Client is a powerful visual Git client from Axosoft that works with ALL git repositories on any hosting environment.",
    "link": "https://www.gitkraken.com/git-client",
    "winget": "Axosoft.GitKraken"
  },
  "WPFInstallglaryutilities": {
    "category": "Utilities",
    "choco": "glaryutilities-free",
    "content": "Glary Utilities",
    "description": "Glary Utilities is a comprehensive system optimization and maintenance tool for Windows.",
    "link": "https://www.glarysoft.com/glary-utilities/",
    "winget": "Glarysoft.GlaryUtilities"
  },
  "WPFInstallgodotengine": {
    "category": "Development",
    "choco": "godot",
    "content": "Godot Engine",
    "description": "Godot Engine is a free, open-source 2D and 3D game engine with a focus on usability and flexibility.",
    "link": "https://godotengine.org/",
    "winget": "GodotEngine.GodotEngine"
  },
  "WPFInstallgog": {
    "category": "Games",
    "choco": "goggalaxy",
    "content": "GOG Galaxy",
    "description": "GOG Galaxy is a gaming client that offers DRM-free games, additional content, and more.",
    "link": "https://www.gog.com/galaxy",
    "winget": "GOG.Galaxy"
  },
  "WPFInstallgitify": {
    "category": "Development",
    "choco": "na",
    "content": "Gitify",
    "description": "GitHub notifications on your menu bar.",
    "link": "https://www.gitify.io/",
    "winget": "Gitify.Gitify"
  },
  "WPFInstallgolang": {
    "category": "Development",
    "choco": "golang",
    "content": "Go",
    "description": "Go (or Golang) is a statically typed, compiled programming language designed for simplicity, reliability, and efficiency.",
    "link": "https://go.dev/",
    "winget": "GoLang.Go"
  },
  "WPFInstallgoogledrive": {
    "category": "Utilities",
    "choco": "googledrive",
    "content": "Google Drive",
    "description": "File syncing across devices all tied to your google account",
    "link": "https://www.google.com/drive/",
    "winget": "Google.GoogleDrive"
  },
  "WPFInstallgpuz": {
    "category": "Utilities",
    "choco": "gpu-z",
    "content": "GPU-Z",
    "description": "GPU-Z provides detailed information about your graphics card and GPU.",
    "link": "https://www.techpowerup.com/gpuz/",
    "winget": "TechPowerUp.GPU-Z"
  },
  "WPFInstallgreenshot": {
    "category": "Multimedia Tools",
    "choco": "greenshot",
    "content": "Greenshot (Screenshots)",
    "description": "Greenshot is a light-weight screenshot software tool with built-in image editor and customizable capture options.",
    "link": "https://getgreenshot.org/",
    "winget": "Greenshot.Greenshot"
  },
  "WPFInstallgsudo": {
    "category": "Utilities",
    "choco": "gsudo",
    "content": "Gsudo",
    "description": "Gsudo is a sudo implementation for Windows, allowing elevated privilege execution.",
    "link": "https://gerardog.github.io/gsudo/",
    "winget": "gerardog.gsudo"
  },
  "WPFInstallguilded": {
    "category": "Communications",
    "choco": "na",
    "content": "Guilded",
    "description": "Guilded is a communication and productivity platform that includes chat, scheduling, and collaborative tools for gaming and communities.",
    "link": "https://www.guilded.gg/",
    "winget": "Guilded.Guilded"
  },
  "WPFInstallhandbrake": {
    "category": "Multimedia Tools",
    "choco": "handbrake",
    "content": "HandBrake",
    "description": "HandBrake is an open-source video transcoder, allowing you to convert video from nearly any format to a selection of widely supported codecs.",
    "link": "https://handbrake.fr/",
    "winget": "HandBrake.HandBrake"
  },
  "WPFInstallharmonoid": {
    "category": "Multimedia Tools",
    "choco": "na",
    "content": "Harmonoid",
    "description": "Plays and manages your music library. Looks beautiful and juicy. Playlists, visuals, synced lyrics, pitch shift, volume boost and more.",
    "link": "https://harmonoid.com/",
    "winget": "Harmonoid.Harmonoid"
  },
  "WPFInstallheidisql": {
    "category": "Pro Tools",
    "choco": "heidisql",
    "content": "HeidiSQL",
    "description": "HeidiSQL is a powerful and easy-to-use client for MySQL, MariaDB, Microsoft SQL Server, and PostgreSQL databases. It provides tools for database management and development.",
    "link": "https://www.heidisql.com/",
    "winget": "HeidiSQL.HeidiSQL"
  },
  "WPFInstallhelix": {
    "category": "Development",
    "choco": "helix",
    "content": "Helix",
    "description": "Helix is a neovim alternative built in rust.",
    "link": "https://helix-editor.com/",
    "winget": "Helix.Helix"
  },
  "WPFInstallheroiclauncher": {
    "category": "Games",
    "choco": "na",
    "content": "Heroic Games Launcher",
    "description": "Heroic Games Launcher is an open-source alternative game launcher for Epic Games Store.",
    "link": "https://heroicgameslauncher.com/",
    "winget": "HeroicGamesLauncher.HeroicGamesLauncher"
  },
  "WPFInstallhexchat": {
    "category": "Communications",
    "choco": "hexchat",
    "content": "Hexchat",
    "description": "HexChat is a free, open-source IRC (Internet Relay Chat) client with a graphical interface for easy communication.",
    "link": "https://hexchat.github.io/",
    "winget": "HexChat.HexChat"
  },
  "WPFInstallhwinfo": {
    "category": "Utilities",
    "choco": "hwinfo",
    "content": "HWiNFO",
    "description": "HWiNFO provides comprehensive hardware information and diagnostics for Windows.",
    "link": "https://www.hwinfo.com/",
    "winget": "REALiX.HWiNFO"
  },
  "WPFInstallhwmonitor": {
    "category": "Utilities",
    "choco": "hwmonitor",
    "content": "HWMonitor",
    "description": "HWMonitor is a hardware monitoring program that reads PC systems main health sensors.",
    "link": "https://www.cpuid.com/softwares/hwmonitor.html",
    "winget": "CPUID.HWMonitor"
  },
  "WPFInstallimageglass": {
    "category": "Multimedia Tools",
    "choco": "imageglass",
    "content": "ImageGlass (Image Viewer)",
    "description": "ImageGlass is a versatile image viewer with support for various image formats and a focus on simplicity and speed.",
    "link": "https://imageglass.org/",
    "winget": "DuongDieuPhap.ImageGlass"
  },
  "WPFInstallimgburn": {
    "category": "Multimedia Tools",
    "choco": "imgburn",
    "content": "ImgBurn",
    "description": "ImgBurn is a lightweight CD, DVD, HD-DVD, and Blu-ray burning application with advanced features for creating and burning disc images.",
    "link": "http://www.imgburn.com/",
    "winget": "LIGHTNINGUK.ImgBurn"
  },
  "WPFInstallinkscape": {
    "category": "Multimedia Tools",
    "choco": "inkscape",
    "content": "Inkscape",
    "description": "Inkscape is a powerful open-source vector graphics editor, suitable for tasks such as illustrations, icons, logos, and more.",
    "link": "https://inkscape.org/",
    "winget": "Inkscape.Inkscape"
  },
  "WPFInstallitch": {
    "category": "Games",
    "choco": "itch",
    "content": "Itch.io",
    "description": "Itch.io is a digital distribution platform for indie games and creative projects.",
    "link": "https://itch.io/",
    "winget": "ItchIo.Itch"
  },
  "WPFInstallitunes": {
    "category": "Multimedia Tools",
    "choco": "itunes",
    "content": "iTunes",
    "description": "iTunes is a media player, media library, and online radio broadcaster application developed by Apple Inc.",
    "link": "https://www.apple.com/itunes/",
    "winget": "Apple.iTunes"
  },
  "WPFInstalljami": {
    "category": "Communications",
    "choco": "jami",
    "content": "Jami",
    "description": "Jami is a secure and privacy-focused communication platform that offers audio and video calls, messaging, and file sharing.",
    "link": "https://jami.net/",
    "winget": "SFLinux.Jami"
  },
  "WPFInstalljava8": {
    "category": "Development",
    "choco": "corretto8jdk",
    "content": "Amazon Corretto 8 (LTS)",
    "description": "Amazon Corretto is a no-cost, multiplatform, production-ready distribution of the Open Java Development Kit (OpenJDK).",
    "link": "https://aws.amazon.com/corretto",
    "winget": "Amazon.Corretto.8.JDK"
  },
  "WPFInstalljava11": {
    "category": "Development",
    "choco": "corretto11jdk",
    "content": "Amazon Corretto 11 (LTS)",
    "description": "Amazon Corretto is a no-cost, multiplatform, production-ready distribution of the Open Java Development Kit (OpenJDK).",
    "link": "https://aws.amazon.com/corretto",
    "winget": "Amazon.Corretto.11.JDK"
  },
  "WPFInstalljava17": {
    "category": "Development",
    "choco": "corretto17jdk",
    "content": "Amazon Corretto 17 (LTS)",
    "description": "Amazon Corretto is a no-cost, multiplatform, production-ready distribution of the Open Java Development Kit (OpenJDK).",
    "link": "https://aws.amazon.com/corretto",
    "winget": "Amazon.Corretto.17.JDK"
  },
  "WPFInstalljava21": {
    "category": "Development",
    "choco": "corretto21jdk",
    "content": "Amazon Corretto 21 (LTS)",
    "description": "Amazon Corretto is a no-cost, multiplatform, production-ready distribution of the Open Java Development Kit (OpenJDK).",
    "link": "https://aws.amazon.com/corretto",
    "winget": "Amazon.Corretto.21.JDK"
  },
  "WPFInstalljdownloader": {
    "category": "Utilities",
    "choco": "jdownloader",
    "content": "JDownloader",
    "description": "JDownloader is a feature-rich download manager with support for various file hosting services.",
    "link": "http://jdownloader.org/",
    "winget": "AppWork.JDownloader"
  },
  "WPFInstalljellyfinmediaplayer": {
    "category": "Multimedia Tools",
    "choco": "jellyfin-media-player",
    "content": "Jellyfin Media Player",
    "description": "Jellyfin Media Player is a client application for the Jellyfin media server, providing access to your media library.",
    "link": "https://github.com/jellyfin/jellyfin-media-player",
    "winget": "Jellyfin.JellyfinMediaPlayer"
  },
  "WPFInstalljellyfinserver": {
    "category": "Multimedia Tools",
    "choco": "jellyfin",
    "content": "Jellyfin Server",
    "description": "Jellyfin Server is an open-source media server software, allowing you to organize and stream your media library.",
    "link": "https://jellyfin.org/",
    "winget": "Jellyfin.Server"
  },
  "WPFInstalljetbrains": {
    "category": "Development",
    "choco": "jetbrainstoolbox",
    "content": "Jetbrains Toolbox",
    "description": "Jetbrains Toolbox is a platform for easy installation and management of JetBrains developer tools.",
    "link": "https://www.jetbrains.com/toolbox/",
    "winget": "JetBrains.Toolbox"
  },
  "WPFInstalljoplin": {
    "category": "Document",
    "choco": "joplin",
    "content": "Joplin (FOSS Notes)",
    "description": "Joplin is an open-source note-taking and to-do application with synchronization capabilities.",
    "link": "https://joplinapp.org/",
    "winget": "Joplin.Joplin"
  },
  "WPFInstalljpegview": {
    "category": "Utilities",
    "choco": "jpegview",
    "content": "JPEG View",
    "description": "JPEGView is a lean, fast and highly configurable viewer/editor for JPEG, BMP, PNG, WEBP, TGA, GIF, JXL, HEIC, HEIF, AVIF and TIFF images with a minimal GUI",
    "link": "https://github.com/sylikc/jpegview",
    "winget": "sylikc.JPEGView"
  },
  "WPFInstallkdeconnect": {
    "category": "Utilities",
    "choco": "kdeconnect-kde",
    "content": "KDE Connect",
    "description": "KDE Connect allows seamless integration between your KDE desktop and mobile devices.",
    "link": "https://community.kde.org/KDEConnect",
    "winget": "KDE.KDEConnect"
  },
  "WPFInstallkdenlive": {
    "category": "Multimedia Tools",
    "choco": "kdenlive",
    "content": "Kdenlive (Video Editor)",
    "description": "Kdenlive is an open-source video editing software with powerful features for creating and editing professional-quality videos.",
    "link": "https://kdenlive.org/",
    "winget": "KDE.Kdenlive"
  },
  "WPFInstallkeepass": {
    "category": "Utilities",
    "choco": "keepassxc",
    "content": "KeePassXC",
    "description": "KeePassXC is a cross-platform, open-source password manager with strong encryption features.",
    "link": "https://keepassxc.org/",
    "winget": "KeePassXCTeam.KeePassXC"
  },
  "WPFInstallklite": {
    "category": "Multimedia Tools",
    "choco": "k-litecodecpack-standard",
    "content": "K-Lite Codec Standard",
    "description": "K-Lite Codec Pack Standard is a collection of audio and video codecs and related tools, providing essential components for media playback.",
    "link": "https://www.codecguide.com/",
    "winget": "CodecGuide.K-LiteCodecPack.Standard"
  },
  "WPFInstallkodi": {
    "category": "Multimedia Tools",
    "choco": "kodi",
    "content": "Kodi Media Center",
    "description": "Kodi is an open-source media center application that allows you to play and view most videos, music, podcasts, and other digital media files.",
    "link": "https://kodi.tv/",
    "winget": "XBMCFoundation.Kodi"
  },
  "WPFInstallkrita": {
    "category": "Multimedia Tools",
    "choco": "krita",
    "content": "Krita (Image Editor)",
    "description": "Krita is a powerful open-source painting application. It is designed for concept artists, illustrators, matte and texture artists, and the VFX industry.",
    "link": "https://krita.org/en/features/",
    "winget": "KDE.Krita"
  },
  "WPFInstalllazygit": {
    "category": "Development",
    "choco": "lazygit",
    "content": "Lazygit",
    "description": "Simple terminal UI for git commands",
    "link": "https://github.com/jesseduffield/lazygit/",
    "winget": "JesseDuffield.lazygit"
  },
  "WPFInstalllibreoffice": {
    "category": "Document",
    "choco": "libreoffice-fresh",
    "content": "LibreOffice",
    "description": "LibreOffice is a powerful and free office suite, compatible with other major office suites.",
    "link": "https://www.libreoffice.org/",
    "winget": "TheDocumentFoundation.LibreOffice"
  },
  "WPFInstalllibrewolf": {
    "category": "Browsers",
    "choco": "librewolf",
    "content": "LibreWolf",
    "description": "LibreWolf is a privacy-focused web browser based on Firefox, with additional privacy and security enhancements.",
    "link": "https://librewolf-community.gitlab.io/",
    "winget": "LibreWolf.LibreWolf"
  },
  "WPFInstalllinkshellextension": {
    "category": "Utilities",
    "choco": "linkshellextension",
    "content": "Link Shell extension",
    "description": "Link Shell Extension (LSE) provides for the creation of Hardlinks, Junctions, Volume Mountpoints, Symbolic Links, a folder cloning process that utilises Hardlinks or Symbolic Links and a copy process taking care of Junctions, Symbolic Links, and Hardlinks. LSE, as its name implies is implemented as a Shell extension and is accessed from Windows Explorer, or similar file/folder managers.",
    "link": "https://schinagl.priv.at/nt/hardlinkshellext/hardlinkshellext.html",
    "winget": "HermannSchinagl.LinkShellExtension"
  },
  "WPFInstalllinphone": {
    "category": "Communications",
    "choco": "linphone",
    "content": "Linphone",
    "description": "Linphone is an open-source voice over IP (VoIPservice that allows for audio and video calls, messaging, and more.",
    "link": "https://www.linphone.org/",
    "winget": "BelledonneCommunications.Linphone"
  },
  "WPFInstalllivelywallpaper": {
    "category": "Utilities",
    "choco": "lively",
    "content": "Lively Wallpaper",
    "description": "Free and open-source software that allows users to set animated desktop wallpapers and screensavers.",
    "link": "https://www.rocksdanister.com/lively/",
    "winget": "rocksdanister.LivelyWallpaper"
  },
  "WPFInstalllocalsend": {
    "category": "Utilities",
    "choco": "localsend.install",
    "content": "LocalSend",
    "description": "An open source cross-platform alternative to AirDrop.",
    "link": "https://localsend.org/",
    "winget": "LocalSend.LocalSend"
  },
  "WPFInstalllockhunter": {
    "category": "Utilities",
    "choco": "lockhunter",
    "content": "LockHunter",
    "description": "LockHunter is a free tool to delete files blocked by something you do not know.",
    "link": "https://lockhunter.com/",
    "winget": "CrystalRich.LockHunter"
  },
  "WPFInstalllogseq": {
    "category": "Document",
    "choco": "logseq",
    "content": "Logseq",
    "description": "Logseq is a versatile knowledge management and note-taking application designed for the digital thinker. With a focus on the interconnectedness of ideas, Logseq allows users to seamlessly organize their thoughts through a combination of hierarchical outlines and bi-directional linking. It supports both structured and unstructured content, enabling users to create a personalized knowledge graph that adapts to their evolving ideas and insights.",
    "link": "https://logseq.com/",
    "winget": "Logseq.Logseq"
  },
  "WPFInstallmalwarebytes": {
    "category": "Utilities",
    "choco": "malwarebytes",
    "content": "Malwarebytes",
    "description": "Malwarebytes is an anti-malware software that provides real-time protection against threats.",
    "link": "https://www.malwarebytes.com/",
    "winget": "Malwarebytes.Malwarebytes"
  },
  "WPFInstallmasscode": {
    "category": "Document",
    "choco": "na",
    "content": "massCode (Snippet Manager)",
    "description": "massCode is a fast and efficient open-source code snippet manager for developers.",
    "link": "https://masscode.io/",
    "winget": "antonreshetov.massCode"
  },
  "WPFInstallmatrix": {
    "category": "Communications",
    "choco": "element-desktop",
    "content": "Element",
    "description": "Element is a client for Matrix?an open network for secure, decentralized communication.",
    "link": "https://element.io/",
    "winget": "Element.Element"
  },
  "WPFInstallmeld": {
    "category": "Utilities",
    "choco": "meld",
    "content": "Meld",
    "description": "Meld is a visual diff and merge tool for files and directories.",
    "link": "https://meldmerge.org/",
    "winget": "Meld.Meld"
  },
  "WPFInstallModernFlyouts": {
    "category": "Multimedia Tools",
    "choco": "na",
    "content": "Modern Flyouts",
    "description": "An open source, modern, Fluent Design-based set of flyouts for Windows.",
    "link": "https://github.com/ModernFlyouts-Community/ModernFlyouts/",
    "winget": "ModernFlyouts.ModernFlyouts"
  },
  "WPFInstallmonitorian": {
    "category": "Utilities",
    "choco": "monitorian",
    "content": "Monitorian",
    "description": "Monitorian is a utility for adjusting monitor brightness and contrast on Windows.",
    "link": "https://github.com/emoacht/Monitorian",
    "winget": "emoacht.Monitorian"
  },
  "WPFInstallmoonlight": {
    "category": "Games",
    "choco": "moonlight-qt",
    "content": "Moonlight/GameStream Client",
    "description": "Moonlight/GameStream Client allows you to stream PC games to other devices over your local network.",
    "link": "https://moonlight-stream.org/",
    "winget": "MoonlightGameStreamingProject.Moonlight"
  },
  "WPFInstallMotrix": {
    "category": "Utilities",
    "choco": "motrix",
    "content": "Motrix Download Manager",
    "description": "A full-featured download manager.",
    "link": "https://motrix.app/",
    "winget": "agalwood.Motrix"
  },
  "WPFInstallmpchc": {
    "category": "Multimedia Tools",
    "choco": "mpc-hc-clsid2",
    "content": "Media Player Classic - Home Cinema",
    "description": "Media Player Classic - Home Cinema (MPC-HC) is a free and open-source video and audio player for Windows. MPC-HC is based on the original Guliverkli project and contains many additional features and bug fixes.",
    "link": "https://github.com/clsid2/mpc-hc/",
    "winget": "clsid2.mpc-hc"
  },
  "WPFInstallmremoteng": {
    "category": "Pro Tools",
    "choco": "mremoteng",
    "content": "mRemoteNG",
    "description": "mRemoteNG is a free and open-source remote connections manager. It allows you to view and manage multiple remote sessions in a single interface.",
    "link": "https://mremoteng.org/",
    "winget": "mRemoteNG.mRemoteNG"
  },
  "WPFInstallmsedgeredirect": {
    "category": "Utilities",
    "choco": "msedgeredirect",
    "content": "MSEdgeRedirect",
    "description": "A Tool to Redirect News, Search, Widgets, Weather, and More to Your Default Browser.",
    "link": "https://github.com/rcmaehl/MSEdgeRedirect",
    "winget": "rcmaehl.MSEdgeRedirect"
  },
  "WPFInstallmsiafterburner": {
    "category": "Utilities",
    "choco": "msiafterburner",
    "content": "MSI Afterburner",
    "description": "MSI Afterburner is a graphics card overclocking utility with advanced features.",
    "link": "https://www.msi.com/Landing/afterburner",
    "winget": "Guru3D.Afterburner"
  },
  "WPFInstallmullvadvpn": {
    "category": "Pro Tools",
    "choco": "mullvad-app",
    "content": "Mullvad VPN",
    "description": "This is the VPN client software for the Mullvad VPN service.",
    "link": "https://github.com/mullvad/mullvadvpn-app",
    "winget": "MullvadVPN.MullvadVPN"
  },
  "WPFInstallBorderlessGaming": {
    "category": "Utilities",
    "choco": "borderlessgaming",
    "content": "Borderless Gaming",
    "description": "Play your favorite games in a borderless window; no more time consuming alt-tabs.",
    "link": "https://github.com/Codeusa/Borderless-Gaming",
    "winget": "Codeusa.BorderlessGaming"
  },
  "WPFInstallEqualizerAPO": {
    "category": "Multimedia Tools",
    "choco": "equalizerapo",
    "content": "Equalizer APO",
    "description": "Equalizer APO is a parametric / graphic equalizer for Windows.",
    "link": "https://sourceforge.net/projects/equalizerapo",
    "winget": "na"
  },
  "WPFInstallCompactGUI": {
    "category": "Utilities",
    "choco": "compactgui",
    "content": "Compact GUI",
    "description": "Transparently compress active games and programs using Windows 10/11 APIs",
    "link": "https://github.com/IridiumIO/CompactGUI",
    "winget": "IridiumIO.CompactGUI"
  },
  "WPFInstallExifCleaner": {
    "category": "Utilities",
    "choco": "na",
    "content": "ExifCleaner",
    "description": "Desktop app to clean metadata from images, videos, PDFs, and other files.",
    "link": "https://github.com/szTheory/exifcleaner",
    "winget": "szTheory.exifcleaner"
  },
  "WPFInstallmullvadbrowser": {
    "category": "Browsers",
    "choco": "na",
    "content": "Mullvad Browser",
    "description": "Mullvad Browser is a privacy-focused web browser, developed in partnership with the Tor Project.",
    "link": "https://mullvad.net/browser",
    "winget": "MullvadVPN.MullvadBrowser"
  },
  "WPFInstallmusescore": {
    "category": "Multimedia Tools",
    "choco": "musescore",
    "content": "MuseScore",
    "description": "Create, play back and print beautiful sheet music with free and easy to use music notation software MuseScore.",
    "link": "https://musescore.org/en",
    "winget": "Musescore.Musescore"
  },
  "WPFInstallmusicbee": {
    "category": "Multimedia Tools",
    "choco": "musicbee",
    "content": "MusicBee (Music Player)",
    "description": "MusicBee is a customizable music player with support for various audio formats. It includes features like an integrated search function, tag editing, and more.",
    "link": "https://getmusicbee.com/",
    "winget": "MusicBee.MusicBee"
  },
  "WPFInstallmp3tag": {
    "category": "Multimedia Tools",
    "choco": "mp3tag",
    "content": "Mp3tag (Metadata Audio Editor)",
    "description": "Mp3tag is a powerful and yet easy-to-use tool to edit metadata of common audio formats.",
    "link": "https://www.mp3tag.de/en/",
    "winget": "Mp3tag.Mp3tag"
  },
  "WPFInstalltagscanner": {
    "category": "Multimedia Tools",
    "choco": "tagscanner",
    "content": "TagScanner (Tag Scanner)",
    "description": "TagScanner is a powerful tool for organizing and managing your music collection",
    "link": "https://www.xdlab.ru/en/",
    "winget": "SergeySerkov.TagScanner"
  },
  "WPFInstallnanazip": {
    "category": "Utilities",
    "choco": "nanazip",
    "content": "NanaZip",
    "description": "NanaZip is a fast and efficient file compression and decompression tool.",
    "link": "https://github.com/M2Team/NanaZip",
    "winget": "M2Team.NanaZip"
  },
  "WPFInstallnetbird": {
    "category": "Pro Tools",
    "choco": "netbird",
    "content": "NetBird",
    "description": "NetBird is a Open Source alternative comparable to TailScale that can be connected to a selfhosted Server.",
    "link": "https://netbird.io/",
    "winget": "netbird"
  },
  "WPFInstallnaps2": {
    "category": "Document",
    "choco": "naps2",
    "content": "NAPS2 (Document Scanner)",
    "description": "NAPS2 is a document scanning application that simplifies the process of creating electronic documents.",
    "link": "https://www.naps2.com/",
    "winget": "Cyanfish.NAPS2"
  },
  "WPFInstallneofetchwin": {
    "category": "Utilities",
    "choco": "na",
    "content": "Neofetch",
    "description": "Neofetch is a command-line utility for displaying system information in a visually appealing way.",
    "link": "https://github.com/nepnep39/neofetch-win",
    "winget": "nepnep.neofetch-win"
  },
  "WPFInstallneovim": {
    "category": "Development",
    "choco": "neovim",
    "content": "Neovim",
    "description": "Neovim is a highly extensible text editor and an improvement over the original Vim editor.",
    "link": "https://neovim.io/",
    "winget": "Neovim.Neovim"
  },
  "WPFInstallnextclouddesktop": {
    "category": "Utilities",
    "choco": "nextcloud-client",
    "content": "Nextcloud Desktop",
    "description": "Nextcloud Desktop is the official desktop client for the Nextcloud file synchronization and sharing platform.",
    "link": "https://nextcloud.com/install/#install-clients",
    "winget": "Nextcloud.NextcloudDesktop"
  },
  "WPFInstallnglide": {
    "category": "Multimedia Tools",
    "choco": "na",
    "content": "nGlide (3dfx compatibility)",
    "description": "nGlide is a 3Dfx Voodoo Glide wrapper. It allows you to play games that use Glide API on modern graphics cards without the need for a 3Dfx Voodoo graphics card.",
    "link": "http://www.zeus-software.com/downloads/nglide",
    "winget": "ZeusSoftware.nGlide"
  },
  "WPFInstallnmap": {
    "category": "Pro Tools",
    "choco": "nmap",
    "content": "Nmap",
    "description": "Nmap (Network Mapper) is an open-source tool for network exploration and security auditing. It discovers devices on a network and provides information about their ports and services.",
    "link": "https://nmap.org/",
    "winget": "Insecure.Nmap"
  },
  "WPFInstallnodejs": {
    "category": "Development",
    "choco": "nodejs",
    "content": "NodeJS",
    "description": "NodeJS is a JavaScript runtime built on Chrome's V8 JavaScript engine for building server-side and networking applications.",
    "link": "https://nodejs.org/",
    "winget": "OpenJS.NodeJS"
  },
  "WPFInstallnodejslts": {
    "category": "Development",
    "choco": "nodejs-lts",
    "content": "NodeJS LTS",
    "description": "NodeJS LTS provides Long-Term Support releases for stable and reliable server-side JavaScript development.",
    "link": "https://nodejs.org/",
    "winget": "OpenJS.NodeJS.LTS"
  },
  "WPFInstallnomacs": {
    "category": "Multimedia Tools",
    "choco": "nomacs",
    "content": "Nomacs (Image viewer)",
    "description": "Nomacs is a free, open-source image viewer that supports multiple platforms. It features basic image editing capabilities and supports a variety of image formats.",
    "link": "https://nomacs.org/",
    "winget": "nomacs.nomacs"
  },
  "WPFInstallnotepadplus": {
    "category": "Document",
    "choco": "notepadplusplus",
    "content": "Notepad++",
    "description": "Notepad++ is a free, open-source code editor and Notepad replacement with support for multiple languages.",
    "link": "https://notepad-plus-plus.org/",
    "winget": "Notepad++.Notepad++"
  },
  "WPFInstallnuget": {
    "category": "Microsoft Tools",
    "choco": "nuget.commandline",
    "content": "NuGet",
    "description": "NuGet is a package manager for the .NET framework, enabling developers to manage and share libraries in their .NET applications.",
    "link": "https://www.nuget.org/",
    "winget": "Microsoft.NuGet"
  },
  "WPFInstallnushell": {
    "category": "Utilities",
    "choco": "nushell",
    "content": "Nushell",
    "description": "Nushell is a new shell that takes advantage of modern hardware and systems to provide a powerful, expressive, and fast experience.",
    "link": "https://www.nushell.sh/",
    "winget": "Nushell.Nushell"
  },
  "WPFInstallnvclean": {
    "category": "Utilities",
    "choco": "na",
    "content": "NVCleanstall",
    "description": "NVCleanstall is a tool designed to customize NVIDIA driver installations, allowing advanced users to control more aspects of the installation process.",
    "link": "https://www.techpowerup.com/nvcleanstall/",
    "winget": "TechPowerUp.NVCleanstall"
  },
  "WPFInstallnvm": {
    "category": "Development",
    "choco": "nvm",
    "content": "Node Version Manager",
    "description": "Node Version Manager (NVM) for Windows allows you to easily switch between multiple Node.js versions.",
    "link": "https://github.com/coreybutler/nvm-windows",
    "winget": "CoreyButler.NVMforWindows"
  },
  "WPFInstallobs": {
    "category": "Multimedia Tools",
    "choco": "obs-studio",
    "content": "OBS Studio",
    "description": "OBS Studio is a free and open-source software for video recording and live streaming. It supports real-time video/audio capturing and mixing, making it popular among content creators.",
    "link": "https://obsproject.com/",
    "winget": "OBSProject.OBSStudio"
  },
  "WPFInstallobsidian": {
    "category": "Document",
    "choco": "obsidian",
    "content": "Obsidian",
    "description": "Obsidian is a powerful note-taking and knowledge management application.",
    "link": "https://obsidian.md/",
    "winget": "Obsidian.Obsidian"
  },
  "WPFInstallokular": {
    "category": "Document",
    "choco": "okular",
    "content": "Okular",
    "description": "Okular is a versatile document viewer with advanced features.",
    "link": "https://okular.kde.org/",
    "winget": "KDE.Okular"
  },
  "WPFInstallonedrive": {
    "category": "Microsoft Tools",
    "choco": "onedrive",
    "content": "OneDrive",
    "description": "OneDrive is a cloud storage service provided by Microsoft, allowing users to store and share files securely across devices.",
    "link": "https://onedrive.live.com/",
    "winget": "Microsoft.OneDrive"
  },
  "WPFInstallonlyoffice": {
    "category": "Document",
    "choco": "onlyoffice",
    "content": "ONLYOffice Desktop",
    "description": "ONLYOffice Desktop is a comprehensive office suite for document editing and collaboration.",
    "link": "https://www.onlyoffice.com/desktop.aspx",
    "winget": "ONLYOFFICE.DesktopEditors"
  },
  "WPFInstallOPAutoClicker": {
    "category": "Utilities",
    "choco": "autoclicker",
    "content": "OPAutoClicker",
    "description": "A full-fledged autoclicker with two modes of autoclicking, at your dynamic cursor location or at a prespecified location.",
    "link": "https://www.opautoclicker.com",
    "winget": "OPAutoClicker.OPAutoClicker"
  },
  "WPFInstallopenhashtab": {
    "category": "Utilities",
    "choco": "openhashtab",
    "content": "OpenHashTab",
    "description": "OpenHashTab is a shell extension for conveniently calculating and checking file hashes from file properties.",
    "link": "https://github.com/namazso/OpenHashTab/",
    "winget": "namazso.OpenHashTab"
  },
  "WPFInstallopenoffice": {
    "category": "Document",
    "choco": "openoffice",
    "content": "Apache OpenOffice",
    "description": "Apache OpenOffice is an open-source office software suite for word processing, spreadsheets, presentations, and more.",
    "link": "https://www.openoffice.org/",
    "winget": "Apache.OpenOffice"
  },
  "WPFInstallopenrgb": {
    "category": "Utilities",
    "choco": "openrgb",
    "content": "OpenRGB",
    "description": "OpenRGB is an open-source RGB lighting control software designed to manage and control RGB lighting for various components and peripherals.",
    "link": "https://openrgb.org/",
    "winget": "CalcProgrammer1.OpenRGB"
  },
  "WPFInstallopenscad": {
    "category": "Multimedia Tools",
    "choco": "openscad",
    "content": "OpenSCAD",
    "description": "OpenSCAD is a free and open-source script-based 3D CAD modeler. It is especially useful for creating parametric designs for 3D printing.",
    "link": "https://www.openscad.org/",
    "winget": "OpenSCAD.OpenSCAD"
  },
  "WPFInstallopenshell": {
    "category": "Utilities",
    "choco": "open-shell",
    "content": "Open Shell (Start Menu)",
    "description": "Open Shell is a Windows Start Menu replacement with enhanced functionality and customization options.",
    "link": "https://github.com/Open-Shell/Open-Shell-Menu",
    "winget": "Open-Shell.Open-Shell-Menu"
  },
  "WPFInstallOpenVPN": {
    "category": "Pro Tools",
    "choco": "openvpn-connect",
    "content": "OpenVPN Connect",
    "description": "OpenVPN Connect is an open-source VPN client that allows you to connect securely to a VPN server. It provides a secure and encrypted connection for protecting your online privacy.",
    "link": "https://openvpn.net/",
    "winget": "OpenVPNTechnologies.OpenVPNConnect"
  },
  "WPFInstallOVirtualBox": {
    "category": "Utilities",
    "choco": "virtualbox",
    "content": "Oracle VirtualBox",
    "description": "Oracle VirtualBox is a powerful and free open-source virtualization tool for x86 and AMD64/Intel64 architectures.",
    "link": "https://www.virtualbox.org/",
    "winget": "Oracle.VirtualBox"
  },
  "WPFInstallownclouddesktop": {
    "category": "Utilities",
    "choco": "owncloud-client",
    "content": "ownCloud Desktop",
    "description": "ownCloud Desktop is the official desktop client for the ownCloud file synchronization and sharing platform.",
    "link": "https://owncloud.com/desktop-app/",
    "winget": "ownCloud.ownCloudDesktop"
  },
  "WPFInstallPaintdotnet": {
    "category": "Multimedia Tools",
    "choco": "paint.net",
    "content": "Paint.NET",
    "description": "Paint.NET is a free image and photo editing software for Windows. It features an intuitive user interface and supports a wide range of powerful editing tools.",
    "link": "https://www.getpaint.net/",
    "winget": "dotPDN.PaintDotNet"
  },
  "WPFInstallparsec": {
    "category": "Utilities",
    "choco": "parsec",
    "content": "Parsec",
    "description": "Parsec is a low-latency, high-quality remote desktop sharing application for collaborating and gaming across devices.",
    "link": "https://parsec.app/",
    "winget": "Parsec.Parsec"
  },
  "WPFInstallpdf24creator": {
    "category": "Document",
    "choco": "pdf24",
    "content": "PDF24 creator",
    "description": "Free and easy-to-use online/desktop PDF tools that make you more productive",
    "link": "https://tools.pdf24.org/en/",
    "winget": "geeksoftwareGmbH.PDF24Creator"
  },
  "WPFInstallpdfsam": {
    "category": "Document",
    "choco": "pdfsam",
    "content": "PDFsam Basic",
    "description": "PDFsam Basic is a free and open-source tool for splitting, merging, and rotating PDF files.",
    "link": "https://pdfsam.org/",
    "winget": "PDFsam.PDFsam"
  },
  "WPFInstallpeazip": {
    "category": "Utilities",
    "choco": "peazip",
    "content": "PeaZip",
    "description": "PeaZip is a free, open-source file archiver utility that supports multiple archive formats and provides encryption features.",
    "link": "https://peazip.github.io/",
    "winget": "Giorgiotani.Peazip"
  },
  "WPFInstallpiimager": {
    "category": "Utilities",
    "choco": "rpi-imager",
    "content": "Raspberry Pi Imager",
    "description": "Raspberry Pi Imager is a utility for writing operating system images to SD cards for Raspberry Pi devices.",
    "link": "https://www.raspberrypi.com/software/",
    "winget": "RaspberryPiFoundation.RaspberryPiImager"
  },
  "WPFInstallplaynite": {
    "category": "Games",
    "choco": "playnite",
    "content": "Playnite",
    "description": "Playnite is an open-source video game library manager with one simple goal: To provide a unified interface for all of your games.",
    "link": "https://playnite.link/",
    "winget": "Playnite.Playnite"
  },
  "WPFInstallplex": {
    "category": "Multimedia Tools",
    "choco": "plexmediaserver",
    "content": "Plex Media Server",
    "description": "Plex Media Server is a media server software that allows you to organize and stream your media library. It supports various media formats and offers a wide range of features.",
    "link": "https://www.plex.tv/your-media/",
    "winget": "Plex.PlexMediaServer"
  },
  "WPFInstallplexdesktop": {
    "category": "Multimedia Tools",
    "choco": "plex",
    "content": "Plex Desktop",
    "description": "Plex Desktop for Windows is the front end for Plex Media Server.",
    "link": "https://www.plex.tv",
    "winget": "Plex.Plex"
  },
  "WPFInstallPortmaster": {
    "category": "Pro Tools",
    "choco": "portmaster",
    "content": "Portmaster",
    "description": "Portmaster is a free and open-source application that puts you back in charge over all your computers network connections.",
    "link": "https://safing.io/",
    "winget": "Safing.Portmaster"
  },
  "WPFInstallposh": {
    "category": "Development",
    "choco": "oh-my-posh",
    "content": "Oh My Posh (Prompt)",
    "description": "Oh My Posh is a cross-platform prompt theme engine for any shell.",
    "link": "https://ohmyposh.dev/",
    "winget": "JanDeDobbeleer.OhMyPosh"
  },
  "WPFInstallpostman": {
    "category": "Development",
    "choco": "postman",
    "content": "Postman",
    "description": "Postman is a collaboration platform for API development that simplifies the process of developing APIs.",
    "link": "https://www.postman.com/",
    "winget": "Postman.Postman"
  },
  "WPFInstallpowerautomate": {
    "category": "Microsoft Tools",
    "choco": "powerautomatedesktop",
    "content": "Power Automate",
    "description": "Using Power Automate Desktop you can automate tasks on the desktop as well as the Web.",
    "link": "https://www.microsoft.com/en-us/power-platform/products/power-automate",
    "winget": "Microsoft.PowerAutomateDesktop"
  },
  "WPFInstallpowerbi": {
    "category": "Microsoft Tools",
    "choco": "powerbi",
    "content": "Power BI",
    "description": "Create stunning reports and visualizations with Power BI Desktop. It puts visual analytics at your fingertips with intuitive report authoring. Drag-and-drop to place content exactly where you want it on the flexible and fluid canvas. Quickly discover patterns as you explore a single unified view of linked, interactive visualizations.",
    "link": "https://www.microsoft.com/en-us/power-platform/products/power-bi/",
    "winget": "Microsoft.PowerBI"
  },
  "WPFInstallpowershell": {
    "category": "Microsoft Tools",
    "choco": "powershell-core",
    "content": "PowerShell",
    "description": "PowerShell is a task automation framework and scripting language designed for system administrators, offering powerful command-line capabilities.",
    "link": "https://github.com/PowerShell/PowerShell",
    "winget": "Microsoft.PowerShell"
  },
  "WPFInstallpowertoys": {
    "category": "Microsoft Tools",
    "choco": "powertoys",
    "content": "PowerToys",
    "description": "PowerToys is a set of utilities for power users to enhance productivity, featuring tools like FancyZones, PowerRename, and more.",
    "link": "https://github.com/microsoft/PowerToys",
    "winget": "Microsoft.PowerToys"
  },
  "WPFInstallprismlauncher": {
    "category": "Games",
    "choco": "prismlauncher",
    "content": "Prism Launcher",
    "description": "Prism Launcher is a game launcher and manager designed to provide a clean and intuitive interface for organizing and launching your games.",
    "link": "https://prismlauncher.org/",
    "winget": "PrismLauncher.PrismLauncher"
  },
  "WPFInstallprocesslasso": {
    "category": "Utilities",
    "choco": "plasso",
    "content": "Process Lasso",
    "description": "Process Lasso is a system optimization and automation tool that improves system responsiveness and stability by adjusting process priorities and CPU affinities.",
    "link": "https://bitsum.com/",
    "winget": "BitSum.ProcessLasso"
  },
  "WPFInstallspotify": {
    "category": "Multimedia Tools",
    "choco": "spotify",
    "content": "Spotify",
    "description": "Spotify is a digital music service that gives you access to millions of songs, podcasts, and videos from artists all over the world.",
    "link": "https://www.spotify.com/",
    "winget": "Spotify.Spotify"
  },
  "WPFInstallprocessmonitor": {
    "category": "Microsoft Tools",
    "choco": "procexp",
    "content": "SysInternals Process Monitor",
    "description": "SysInternals Process Monitor is an advanced monitoring tool that shows real-time file system, registry, and process/thread activity.",
    "link": "https://docs.microsoft.com/en-us/sysinternals/downloads/procmon",
    "winget": "Microsoft.Sysinternals.ProcessMonitor"
  },
  "WPFInstallorcaslicer": {
    "category": "Utilities",
    "choco": "orcaslicer",
    "content": "OrcaSlicer",
    "description": "G-code generator for 3D printers (Bambu, Prusa, Voron, VzBot, RatRig, Creality, etc.)",
    "link": "https://github.com/SoftFever/OrcaSlicer",
    "winget": "SoftFever.OrcaSlicer"
  },
  "WPFInstallprucaslicer": {
    "category": "Utilities",
    "choco": "prusaslicer",
    "content": "PrusaSlicer",
    "description": "PrusaSlicer is a powerful and easy-to-use slicing software for 3D printing with Prusa 3D printers.",
    "link": "https://www.prusa3d.com/prusaslicer/",
    "winget": "Prusa3d.PrusaSlicer"
  },
  "WPFInstallpsremoteplay": {
    "category": "Games",
    "choco": "ps-remote-play",
    "content": "PS Remote Play",
    "description": "PS Remote Play is a free application that allows you to stream games from your PlayStation console to a PC or mobile device.",
    "link": "https://remoteplay.dl.playstation.net/remoteplay/lang/gb/",
    "winget": "PlayStation.PSRemotePlay"
  },
  "WPFInstallputty": {
    "category": "Pro Tools",
    "choco": "putty",
    "content": "PuTTY",
    "description": "PuTTY is a free and open-source terminal emulator, serial console, and network file transfer application. It supports various network protocols such as SSH, Telnet, and SCP.",
    "link": "https://www.chiark.greenend.org.uk/~sgtatham/putty/",
    "winget": "PuTTY.PuTTY"
  },
  "WPFInstallpython3": {
    "category": "Development",
    "choco": "python",
    "content": "Python3",
    "description": "Python is a versatile programming language used for web development, data analysis, artificial intelligence, and more.",
    "link": "https://www.python.org/",
    "winget": "Python.Python.3.12"
  },
  "WPFInstallqbittorrent": {
    "category": "Utilities",
    "choco": "qbittorrent",
    "content": "qBittorrent",
    "description": "qBittorrent is a free and open-source BitTorrent client that aims to provide a feature-rich and lightweight alternative to other torrent clients.",
    "link": "https://www.qbittorrent.org/",
    "winget": "qBittorrent.qBittorrent"
  },
  "WPFInstalltransmission": {
    "category": "Utilities",
    "choco": "transmission",
    "content": "Transmission",
    "description": "Transmission is a cross-platform BitTorrent client that is open source, easy, powerful, and lean.",
    "link": "https://transmissionbt.com/",
    "winget": "Transmission.Transmission"
  },
  "WPFInstalltixati": {
    "category": "Utilities",
    "choco": "tixati.portable",
    "content": "Tixati",
    "description": "Tixati is a cross-platform BitTorrent client written in C++ that has been designed to be light on system resources.",
    "link": "https://www.tixati.com/",
    "winget": "Tixati.Tixati.Portable"
  },
  "WPFInstallqtox": {
    "category": "Communications",
    "choco": "qtox",
    "content": "QTox",
    "description": "QTox is a free and open-source messaging app that prioritizes user privacy and security in its design.",
    "link": "https://qtox.github.io/",
    "winget": "Tox.qTox"
  },
  "WPFInstallquicklook": {
    "category": "Utilities",
    "choco": "quicklook",
    "content": "Quicklook",
    "description": "Bring macOS ?Quick Look? feature to Windows",
    "link": "https://github.com/QL-Win/QuickLook",
    "winget": "QL-Win.QuickLook"
  },
  "WPFInstallrainmeter": {
    "category": "Utilities",
    "choco": "na",
    "content": "Rainmeter",
    "description": "Rainmeter is a desktop customization tool that allows you to create and share customizable skins for your desktop.",
    "link": "https://www.rainmeter.net/",
    "winget": "Rainmeter.Rainmeter"
  },
  "WPFInstallrevo": {
    "category": "Utilities",
    "choco": "revo-uninstaller",
    "content": "Revo Uninstaller",
    "description": "Revo Uninstaller is an advanced uninstaller tool that helps you remove unwanted software and clean up your system.",
    "link": "https://www.revouninstaller.com/",
    "winget": "RevoUninstaller.RevoUninstaller"
  },
  "WPFInstallWiseProgramUninstaller": {
    "category": "Utilities",
    "choco": "na",
    "content": "Wise Program Uninstaller (WiseCleaner)",
    "description": "Wise Program Uninstaller is the perfect solution for uninstalling Windows programs, allowing you to uninstall applications quickly and completely using its simple and user-friendly interface.",
    "link": "https://www.wisecleaner.com/wise-program-uninstaller.html",
    "winget": "WiseCleaner.WiseProgramUninstaller"
  },
  "WPFInstallrevolt": {
    "category": "Communications",
    "choco": "na",
    "content": "Revolt",
    "description": "Find your community, connect with the world. Revolt is one of the best ways to stay connected with your friends and community without sacrificing any usability.",
    "link": "https://revolt.chat/",
    "winget": "Revolt.RevoltDesktop"
  },
  "WPFInstallripgrep": {
    "category": "Utilities",
    "choco": "ripgrep",
    "content": "Ripgrep",
    "description": "Fast and powerful commandline search tool",
    "link": "https://github.com/BurntSushi/ripgrep/",
    "winget": "BurntSushi.ripgrep.MSVC"
  },
  "WPFInstallrufus": {
    "category": "Utilities",
    "choco": "rufus",
    "content": "Rufus Imager",
    "description": "Rufus is a utility that helps format and create bootable USB drives, such as USB keys or pen drives.",
    "link": "https://rufus.ie/",
    "winget": "Rufus.Rufus"
  },
  "WPFInstallrustdesk": {
    "category": "Pro Tools",
    "choco": "rustdesk.portable",
    "content": "RustDesk",
    "description": "RustDesk is a free and open-source remote desktop application. It provides a secure way to connect to remote machines and access desktop environments.",
    "link": "https://rustdesk.com/",
    "winget": "RustDesk.RustDesk"
  },
  "WPFInstallrustlang": {
    "category": "Development",
    "choco": "rust",
    "content": "Rust",
    "description": "Rust is a programming language designed for safety and performance, particularly focused on systems programming.",
    "link": "https://www.rust-lang.org/",
    "winget": "Rustlang.Rust.MSVC"
  },
  "WPFInstallsagethumbs": {
    "category": "Utilities",
    "choco": "sagethumbs",
    "content": "SageThumbs",
    "description": "Provides support for thumbnails in Explorer with more formats.",
    "link": "https://sagethumbs.en.lo4d.com/windows",
    "winget": "CherubicSoftware.SageThumbs"
  },
  "WPFInstallsamsungmagician": {
    "category": "Utilities",
    "choco": "samsung-magician",
    "content": "Samsung Magician",
    "description": "Samsung Magician is a utility for managing and optimizing Samsung SSDs.",
    "link": "https://semiconductor.samsung.com/consumer-storage/magician/",
    "winget": "Samsung.SamsungMagician"
  },
  "WPFInstallsandboxie": {
    "category": "Utilities",
    "choco": "sandboxie",
    "content": "Sandboxie Plus",
    "description": "Sandboxie Plus is a sandbox-based isolation program that provides enhanced security by running applications in an isolated environment.",
    "link": "https://github.com/sandboxie-plus/Sandboxie",
    "winget": "Sandboxie.Plus"
  },
  "WPFInstallsdio": {
    "category": "Utilities",
    "choco": "sdio",
    "content": "Snappy Driver Installer Origin",
    "description": "Snappy Driver Installer Origin is a free and open-source driver updater with a vast driver database for Windows.",
    "link": "https://www.glenn.delahoy.com/snappy-driver-installer-origin/",
    "winget": "GlennDelahoy.SnappyDriverInstallerOrigin"
  },
  "WPFInstallsession": {
    "category": "Communications",
    "choco": "session",
    "content": "Session",
    "description": "Session is a private and secure messaging app built on a decentralized network for user privacy and data protection.",
    "link": "https://getsession.org/",
    "winget": "Oxen.Session"
  },
  "WPFInstallsharex": {
    "category": "Multimedia Tools",
    "choco": "sharex",
    "content": "ShareX (Screenshots)",
    "description": "ShareX is a free and open-source screen capture and file sharing tool. It supports various capture methods and offers advanced features for editing and sharing screenshots.",
    "link": "https://getsharex.com/",
    "winget": "ShareX.ShareX"
  },
  "WPFInstallnilesoftShell": {
    "category": "Utilities",
    "choco": "nilesoft-shell",
    "content": "Nilesoft Shell",
    "description": "Shell is an expanded context menu tool that adds extra functionality and customization options to the Windows context menu.",
    "link": "https://nilesoft.org/",
    "winget": "Nilesoft.Shell"
  },
  "WPFInstallsidequest": {
    "category": "Games",
    "choco": "sidequest",
    "content": "SideQuestVR",
    "description": "SideQuestVR is a community-driven platform that enables users to discover, install, and manage virtual reality content on Oculus Quest devices.",
    "link": "https://sidequestvr.com/",
    "winget": "SideQuestVR.SideQuest"
  },
  "WPFInstallsignal": {
    "category": "Communications",
    "choco": "signal",
    "content": "Signal",
    "description": "Signal is a privacy-focused messaging app that offers end-to-end encryption for secure and private communication.",
    "link": "https://signal.org/",
    "winget": "OpenWhisperSystems.Signal"
  },
  "WPFInstallsignalrgb": {
    "category": "Utilities",
    "choco": "na",
    "content": "SignalRGB",
    "description": "SignalRGB lets you control and sync your favorite RGB devices with one free application.",
    "link": "https://www.signalrgb.com/",
    "winget": "WhirlwindFX.SignalRgb"
  },
  "WPFInstallsimplenote": {
    "category": "Document",
    "choco": "simplenote",
    "content": "simplenote",
    "description": "Simplenote is an easy way to keep notes, lists, ideas and more.",
    "link": "https://simplenote.com/",
    "winget": "Automattic.Simplenote"
  },
  "WPFInstallsimplewall": {
    "category": "Pro Tools",
    "choco": "simplewall",
    "content": "Simplewall",
    "description": "Simplewall is a free and open-source firewall application for Windows. It allows users to control and manage the inbound and outbound network traffic of applications.",
    "link": "https://github.com/henrypp/simplewall",
    "winget": "Henry++.simplewall"
  },
  "WPFInstallskype": {
    "category": "Communications",
    "choco": "skype",
    "content": "Skype",
    "description": "Skype is a widely used communication platform offering video calls, voice calls, and instant messaging services.",
    "link": "https://www.skype.com/",
    "winget": "Microsoft.Skype"
  },
  "WPFInstallslack": {
    "category": "Communications",
    "choco": "slack",
    "content": "Slack",
    "description": "Slack is a collaboration hub that connects teams and facilitates communication through channels, messaging, and file sharing.",
    "link": "https://slack.com/",
    "winget": "SlackTechnologies.Slack"
  },
  "WPFInstallspacedrive": {
    "category": "Utilities",
    "choco": "na",
    "content": "Spacedrive File Manager",
    "description": "Spacedrive is a file manager that offers cloud storage integration and file synchronization across devices.",
    "link": "https://www.spacedrive.com/",
    "winget": "spacedrive.Spacedrive"
  },
  "WPFInstallspacesniffer": {
    "category": "Utilities",
    "choco": "spacesniffer",
    "content": "SpaceSniffer",
    "description": "A tool application that lets you understand how folders and files are structured on your disks",
    "link": "http://www.uderzo.it/main_products/space_sniffer/",
    "winget": "UderzoSoftware.SpaceSniffer"
  },
  "WPFInstallspotube": {
    "category": "Multimedia Tools",
    "choco": "spotube",
    "content": "Spotube",
    "description": "Open source Spotify client that doesn't require Premium nor uses Electron! Available for both desktop & mobile! ",
    "link": "https://github.com/KRTirtho/spotube",
    "winget": "KRTirtho.Spotube"
  },
  "WPFInstallstarship": {
    "category": "Development",
    "choco": "starship",
    "content": "Starship (Shell Prompt)",
    "description": "Starship is a minimal, fast, and customizable prompt for any shell.",
    "link": "https://starship.rs/",
    "winget": "starship"
  },
  "WPFInstallsteam": {
    "category": "Games",
    "choco": "steam-client",
    "content": "Steam",
    "description": "Steam is a digital distribution platform for purchasing and playing video games, offering multiplayer gaming, video streaming, and more.",
    "link": "https://store.steampowered.com/about/",
    "winget": "Valve.Steam"
  },
  "WPFInstallstrawberry": {
    "category": "Multimedia Tools",
    "choco": "strawberrymusicplayer",
    "content": "Strawberry (Music Player)",
    "description": "Strawberry is an open-source music player that focuses on music collection management and audio quality. It supports various audio formats and features a clean user interface.",
    "link": "https://www.strawberrymusicplayer.org/",
    "winget": "StrawberryMusicPlayer.Strawberry"
  },
  "WPFInstallstremio": {
    "winget": "Stremio.Stremio",
    "choco": "stremio",
    "category": "Multimedia Tools",
    "content": "Stremio",
    "link": "https://www.stremio.com/",
    "description": "Stremio is a media center application that allows users to organize and stream their favorite movies, TV shows, and video content."
  },
  "WPFInstallsublimemerge": {
    "category": "Development",
    "choco": "sublimemerge",
    "content": "Sublime Merge",
    "description": "Sublime Merge is a Git client with advanced features and a beautiful interface.",
    "link": "https://www.sublimemerge.com/",
    "winget": "SublimeHQ.SublimeMerge"
  },
  "WPFInstallsublimetext": {
    "category": "Development",
    "choco": "sublimetext4",
    "content": "Sublime Text",
    "description": "Sublime Text is a sophisticated text editor for code, markup, and prose.",
    "link": "https://www.sublimetext.com/",
    "winget": "SublimeHQ.SublimeText.4"
  },
  "WPFInstallsumatra": {
    "category": "Document",
    "choco": "sumatrapdf",
    "content": "Sumatra PDF",
    "description": "Sumatra PDF is a lightweight and fast PDF viewer with minimalistic design.",
    "link": "https://www.sumatrapdfreader.org/free-pdf-reader.html",
    "winget": "SumatraPDF.SumatraPDF"
  },
  "WPFInstallpdfgear": {
    "category": "Document",
    "choco": "na",
    "content": "PDFgear",
    "description": "PDFgear is a piece of full-featured PDF management software for Windows, Mac, and mobile, and it's completely free to use.",
    "link": "https://www.pdfgear.com/",
    "winget": "PDFgear.PDFgear"
  },
  "WPFInstallsunshine": {
    "category": "Games",
    "choco": "sunshine",
    "content": "Sunshine/GameStream Server",
    "description": "Sunshine is a GameStream server that allows you to remotely play PC games on Android devices, offering low-latency streaming.",
    "link": "https://github.com/LizardByte/Sunshine",
    "winget": "LizardByte.Sunshine"
  },
  "WPFInstallsuperf4": {
    "category": "Utilities",
    "choco": "superf4",
    "content": "SuperF4",
    "description": "SuperF4 is a utility that allows you to terminate programs instantly by pressing a customizable hotkey.",
    "link": "https://stefansundin.github.io/superf4/",
    "winget": "StefanSundin.Superf4"
  },
  "WPFInstallswift": {
    "category": "Development",
    "choco": "na",
    "content": "Swift toolchain",
    "description": "Swift is a general-purpose programming language that's approachable for newcomers and powerful for experts.",
    "link": "https://www.swift.org/",
    "winget": "Swift.Toolchain"
  },
  "WPFInstallsynctrayzor": {
    "category": "Utilities",
    "choco": "synctrayzor",
    "content": "SyncTrayzor",
    "description": "Windows tray utility / filesystem watcher / launcher for Syncthing",
    "link": "https://github.com/canton7/SyncTrayzor/",
    "winget": "SyncTrayzor.SyncTrayzor"
  },
  "WPFInstallsqlmanagementstudio": {
    "category": "Microsoft Tools",
    "choco": "sql-server-management-studio",
    "content": "Microsoft SQL Server Management Studio",
    "description": "SQL Server Management Studio (SSMS) is an integrated environment for managing any SQL infrastructure, from SQL Server to Azure SQL Database. SSMS provides tools to configure, monitor, and administer instances of SQL Server and databases.",
    "link": "https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-ver16",
    "winget": "Microsoft.SQLServerManagementStudio"
  },
  "WPFInstalltabby": {
    "category": "Utilities",
    "choco": "tabby",
    "content": "Tabby.sh",
    "description": "Tabby is a highly configurable terminal emulator, SSH and serial client for Windows, macOS and Linux",
    "link": "https://tabby.sh/",
    "winget": "Eugeny.Tabby"
  },
  "WPFInstalltailscale": {
    "category": "Utilities",
    "choco": "tailscale",
    "content": "Tailscale",
    "description": "Tailscale is a secure and easy-to-use VPN solution for connecting your devices and networks.",
    "link": "https://tailscale.com/",
    "winget": "tailscale.tailscale"
  },
  "WPFInstallTcNoAccSwitcher": {
    "category": "Games",
    "choco": "tcno-acc-switcher",
    "content": "TCNO Account Switcher",
    "description": "A Super-fast account switcher for Steam, Battle.net, Epic Games, Origin, Riot, Ubisoft and many others!",
    "link": "https://github.com/TCNOco/TcNo-Acc-Switcher",
    "winget": "TechNobo.TcNoAccountSwitcher"
  },
  "WPFInstalltcpview": {
    "category": "Microsoft Tools",
    "choco": "tcpview",
    "content": "SysInternals TCPView",
    "description": "SysInternals TCPView is a network monitoring tool that displays a detailed list of all TCP and UDP endpoints on your system.",
    "link": "https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview",
    "winget": "Microsoft.Sysinternals.TCPView"
  },
  "WPFInstallteams": {
    "category": "Communications",
    "choco": "microsoft-teams",
    "content": "Teams",
    "description": "Microsoft Teams is a collaboration platform that integrates with Office 365 and offers chat, video conferencing, file sharing, and more.",
    "link": "https://www.microsoft.com/en-us/microsoft-teams/group-chat-software",
    "winget": "Microsoft.Teams"
  },
  "WPFInstallteamviewer": {
    "category": "Utilities",
    "choco": "teamviewer9",
    "content": "TeamViewer",
    "description": "TeamViewer is a popular remote access and support software that allows you to connect to and control remote devices.",
    "link": "https://www.teamviewer.com/",
    "winget": "TeamViewer.TeamViewer"
  },
  "WPFInstalltelegram": {
    "category": "Communications",
    "choco": "telegram",
    "content": "Telegram",
    "description": "Telegram is a cloud-based instant messaging app known for its security features, speed, and simplicity.",
    "link": "https://telegram.org/",
    "winget": "Telegram.TelegramDesktop"
  },
  "WPFInstallunigram": {
    "category": "Communications",
    "choco": "na",
    "content": "Unigram",
    "description": "Unigram - Telegram for Windows",
    "link": "https://unigramdev.github.io/",
    "winget": "Telegram.Unigram"
  },
  "WPFInstallterminal": {
    "category": "Microsoft Tools",
    "choco": "microsoft-windows-terminal",
    "content": "Windows Terminal",
    "description": "Windows Terminal is a modern, fast, and efficient terminal application for command-line users, supporting multiple tabs, panes, and more.",
    "link": "https://aka.ms/terminal",
    "winget": "Microsoft.WindowsTerminal"
  },
  "WPFInstallThonny": {
    "category": "Development",
    "choco": "thonny",
    "content": "Thonny Python IDE",
    "description": "Python IDE for beginners.",
    "link": "https://github.com/thonny/thonny",
    "winget": "AivarAnnamaa.Thonny"
  },
  "WPFInstallMuEditor": {
    "category": "Development",
    "choco": "na",
    "content": "Code With Mu (Mu Editor)",
    "description": "Mu is a Python code editor for beginner programmers",
    "link": "https://codewith.mu/",
    "winget": "Mu.Mu"
  },
  "WPFInstallthorium": {
    "category": "Browsers",
    "choco": "na",
    "content": "Thorium Browser AVX2",
    "description": "Browser built for speed over vanilla chromium. It is built with AVX2 optimizations and is the fastest browser on the market.",
    "link": "http://thorium.rocks/",
    "winget": "Alex313031.Thorium.AVX2"
  },
  "WPFInstallthunderbird": {
    "category": "Communications",
    "choco": "thunderbird",
    "content": "Thunderbird",
    "description": "Mozilla Thunderbird is a free and open-source email client, news client, and chat client with advanced features.",
    "link": "https://www.thunderbird.net/",
    "winget": "Mozilla.Thunderbird"
  },
  "WPFInstallbetterbird": {
    "category": "Communications",
    "choco": "betterbird",
    "content": "Betterbird",
    "description": "Betterbird is a fork of Mozilla Thunderbird with additional features and bugfixes.",
    "link": "https://www.betterbird.eu/",
    "winget": "Betterbird.Betterbird"
  },
  "WPFInstalltidal": {
    "category": "Multimedia Tools",
    "choco": "na",
    "content": "Tidal",
    "description": "Tidal is a music streaming service known for its high-fidelity audio quality and exclusive content. It offers a vast library of songs and curated playlists.",
    "link": "https://tidal.com/",
    "winget": "9NNCB5BS59PH"
  },
  "WPFInstalltor": {
    "category": "Browsers",
    "choco": "tor-browser",
    "content": "Tor Browser",
    "description": "Tor Browser is designed for anonymous web browsing, utilizing the Tor network to protect user privacy and security.",
    "link": "https://www.torproject.org/",
    "winget": "TorProject.TorBrowser"
  },
  "WPFInstalltotalcommander": {
    "category": "Utilities",
    "choco": "TotalCommander",
    "content": "Total Commander",
    "description": "Total Commander is a file manager for Windows that provides a powerful and intuitive interface for file management.",
    "link": "https://www.ghisler.com/",
    "winget": "Ghisler.TotalCommander"
  },
  "WPFInstalltreesize": {
    "category": "Utilities",
    "choco": "treesizefree",
    "content": "TreeSize Free",
    "description": "TreeSize Free is a disk space manager that helps you analyze and visualize the space usage on your drives.",
    "link": "https://www.jam-software.com/treesize_free/",
    "winget": "JAMSoftware.TreeSize.Free"
  },
  "WPFInstallttaskbar": {
    "category": "Utilities",
    "choco": "translucenttb",
    "content": "Translucent Taskbar",
    "description": "Translucent Taskbar is a tool that allows you to customize the transparency of the Windows taskbar.",
    "link": "https://github.com/TranslucentTB/TranslucentTB",
    "winget": "9PF4KZ2VN4W9"
  },
  "WPFInstalltwinkletray": {
    "category": "Utilities",
    "choco": "twinkle-tray",
    "content": "Twinkle Tray",
    "description": "Twinkle Tray lets you easily manage the brightness levels of multiple monitors.",
    "link": "https://twinkletray.com/",
    "winget": "xanderfrangos.twinkletray"
  },
  "WPFInstallubisoft": {
    "category": "Games",
    "choco": "ubisoft-connect",
    "content": "Ubisoft Connect",
    "description": "Ubisoft Connect is Ubisoft's digital distribution and online gaming service, providing access to Ubisoft's games and services.",
    "link": "https://ubisoftconnect.com/",
    "winget": "Ubisoft.Connect"
  },
  "WPFInstallungoogled": {
    "category": "Browsers",
    "choco": "ungoogled-chromium",
    "content": "Ungoogled",
    "description": "Ungoogled Chromium is a version of Chromium without Google's integration for enhanced privacy and control.",
    "link": "https://github.com/Eloston/ungoogled-chromium",
    "winget": "eloston.ungoogled-chromium"
  },
  "WPFInstallunity": {
    "category": "Development",
    "choco": "unityhub",
    "content": "Unity Game Engine",
    "description": "Unity is a powerful game development platform for creating 2D, 3D, augmented reality, and virtual reality games.",
    "link": "https://unity.com/",
    "winget": "Unity.UnityHub"
  },
  "WPFInstallvagrant": {
    "category": "Development",
    "choco": "vagrant",
    "content": "Vagrant",
    "description": "Vagrant is an open-source tool for building and managing virtualized development environments.",
    "link": "https://www.vagrantup.com/",
    "winget": "Hashicorp.Vagrant"
  },
  "WPFInstallvc2015_32": {
    "category": "Microsoft Tools",
    "choco": "na",
    "content": "Visual C++ 2015-2022 32-bit",
    "description": "Visual C++ 2015-2022 32-bit redistributable package installs runtime components of Visual C++ libraries required to run 32-bit applications.",
    "link": "https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads",
    "winget": "Microsoft.VCRedist.2015+.x86"
  },
  "WPFInstallvc2015_64": {
    "category": "Microsoft Tools",
    "choco": "na",
    "content": "Visual C++ 2015-2022 64-bit",
    "description": "Visual C++ 2015-2022 64-bit redistributable package installs runtime components of Visual C++ libraries required to run 64-bit applications.",
    "link": "https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads",
    "winget": "Microsoft.VCRedist.2015+.x64"
  },
  "WPFInstallventoy": {
    "category": "Pro Tools",
    "choco": "ventoy",
    "content": "Ventoy",
    "description": "Ventoy is an open-source tool for creating bootable USB drives. It supports multiple ISO files on a single USB drive, making it a versatile solution for installing operating systems.",
    "link": "https://www.ventoy.net/",
    "winget": "Ventoy.Ventoy"
  },
  "WPFInstallvesktop": {
    "category": "Communications",
    "choco": "na",
    "content": "Vesktop",
    "description": "A cross platform electron-based desktop app aiming to give you a snappier Discord experience with Vencord pre-installed.",
    "link": "https://github.com/Vencord/Vesktop",
    "winget": "Vencord.Vesktop"
  },
  "WPFInstallviber": {
    "category": "Communications",
    "choco": "viber",
    "content": "Viber",
    "description": "Viber is a free messaging and calling app with features like group chats, video calls, and more.",
    "link": "https://www.viber.com/",
    "winget": "Viber.Viber"
  },
  "WPFInstallvideomass": {
    "category": "Multimedia Tools",
    "choco": "na",
    "content": "Videomass",
    "description": "Videomass by GianlucaPernigotto is a cross-platform GUI for FFmpeg, streamlining multimedia file processing with batch conversions and user-friendly features.",
    "link": "https://jeanslack.github.io/Videomass/",
    "winget": "GianlucaPernigotto.Videomass"
  },
  "WPFInstallvisualstudio": {
    "category": "Development",
    "choco": "visualstudio2022community",
    "content": "Visual Studio 2022",
    "description": "Visual Studio 2022 is an integrated development environment (IDE) for building, debugging, and deploying applications.",
    "link": "https://visualstudio.microsoft.com/",
    "winget": "Microsoft.VisualStudio.2022.Community"
  },
  "WPFInstallvivaldi": {
    "category": "Browsers",
    "choco": "vivaldi",
    "content": "Vivaldi",
    "description": "Vivaldi is a highly customizable web browser with a focus on user personalization and productivity features.",
    "link": "https://vivaldi.com/",
    "winget": "Vivaldi.Vivaldi"
  },
  "WPFInstallvlc": {
    "category": "Multimedia Tools",
    "choco": "vlc",
    "content": "VLC (Video Player)",
    "description": "VLC Media Player is a free and open-source multimedia player that supports a wide range of audio and video formats. It is known for its versatility and cross-platform compatibility.",
    "link": "https://www.videolan.org/vlc/",
    "winget": "VideoLAN.VLC"
  },
  "WPFInstallvoicemeeter": {
    "category": "Multimedia Tools",
    "choco": "voicemeeter",
    "content": "Voicemeeter (Audio)",
    "description": "Voicemeeter is a virtual audio mixer that allows you to manage and enhance audio streams on your computer. It is commonly used for audio recording and streaming purposes.",
    "link": "https://voicemeeter.com/",
    "winget": "VB-Audio.Voicemeeter"
  },
  "WPFInstallVoicemeeterPotato": {
    "category": "Multimedia Tools",
    "choco": "voicemeeter-potato",
    "content": "Voicemeeter Potato",
    "description": "Voicemeeter Potato is the ultimate version of the Voicemeeter Audio Mixer Application endowed with Virtual Audio Device to mix and manage any audio sources from or to any audio devices or applications.",
    "link": "https://voicemeeter.com/",
    "winget": "VB-Audio.Voicemeeter.Potato"
  },
  "WPFInstallvrdesktopstreamer": {
    "category": "Games",
    "choco": "na",
    "content": "Virtual Desktop Streamer",
    "description": "Virtual Desktop Streamer is a tool that allows you to stream your desktop screen to VR devices.",
    "link": "https://www.vrdesktop.net/",
    "winget": "VirtualDesktop.Streamer"
  },
  "WPFInstallvscode": {
    "category": "Development",
    "choco": "vscode",
    "content": "VS Code",
    "description": "Visual Studio Code is a free, open-source code editor with support for multiple programming languages.",
    "link": "https://code.visualstudio.com/",
    "winget": "Microsoft.VisualStudioCode"
  },
  "WPFInstallvscodium": {
    "category": "Development",
    "choco": "vscodium",
    "content": "VS Codium",
    "description": "VSCodium is a community-driven, freely-licensed binary distribution of Microsoft's VS Code.",
    "link": "https://vscodium.com/",
    "winget": "VSCodium.VSCodium"
  },
  "WPFInstallwaterfox": {
    "category": "Browsers",
    "choco": "waterfox",
    "content": "Waterfox",
    "description": "Waterfox is a fast, privacy-focused web browser based on Firefox, designed to preserve user choice and privacy.",
    "link": "https://www.waterfox.net/",
    "winget": "Waterfox.Waterfox"
  },
  "WPFInstallwazuh": {
    "category": "Utilities",
    "choco": "wazuh-agent",
    "content": "Wazuh.",
    "description": "Wazuh is an open-source security monitoring platform that offers intrusion detection, compliance checks, and log analysis.",
    "link": "https://wazuh.com/",
    "winget": "Wazuh.WazuhAgent"
  },
  "WPFInstallwezterm": {
    "category": "Development",
    "choco": "wezterm",
    "content": "Wezterm",
    "description": "WezTerm is a powerful cross-platform terminal emulator and multiplexer",
    "link": "https://wezfurlong.org/wezterm/index.html",
    "winget": "wez.wezterm"
  },
  "WPFInstallwindowspchealth": {
    "category": "Utilities",
    "choco": "na",
    "content": "Windows PC Health Check",
    "description": "Windows PC Health Check is a tool that helps you check if your PC meets the system requirements for Windows 11.",
    "link": "https://support.microsoft.com/en-us/windows/how-to-use-the-pc-health-check-app-9c8abd9b-03ba-4e67-81ef-36f37caa7844",
    "winget": "Microsoft.WindowsPCHealthCheck"
  },
  "WPFInstallWindowGrid": {
    "category": "Utilities",
    "choco": "windowgrid",
    "content": "WindowGrid",
    "description": "WindowGrid is a modern window management program for Windows that allows the user to quickly and easily layout their windows on a dynamic grid using just the mouse.",
    "link": "http://windowgrid.net/",
    "winget": "na"
  },
  "WPFInstallwingetui": {
    "category": "Utilities",
    "choco": "wingetui",
    "content": "UniGetUI",
    "description": "UniGetUI is a GUI for Winget, Chocolatey, and other Windows CLI package managers.",
    "link": "https://www.marticliment.com/wingetui/",
    "winget": "SomePythonThings.WingetUIStore"
  },
  "WPFInstallwinmerge": {
    "category": "Document",
    "choco": "winmerge",
    "content": "WinMerge",
    "description": "WinMerge is a visual text file and directory comparison tool for Windows.",
    "link": "https://winmerge.org/",
    "winget": "WinMerge.WinMerge"
  },
  "WPFInstallwinpaletter": {
    "category": "Utilities",
    "choco": "WinPaletter",
    "content": "WinPaletter",
    "description": "WinPaletter is a tool for adjusting the color palette of Windows 10, providing customization options for window colors.",
    "link": "https://github.com/Abdelrhman-AK/WinPaletter",
    "winget": "Abdelrhman-AK.WinPaletter"
  },
  "WPFInstallwinrar": {
    "category": "Utilities",
    "choco": "winrar",
    "content": "WinRAR",
    "description": "WinRAR is a powerful archive manager that allows you to create, manage, and extract compressed files.",
    "link": "https://www.win-rar.com/",
    "winget": "RARLab.WinRAR"
  },
  "WPFInstallwinscp": {
    "category": "Pro Tools",
    "choco": "winscp",
    "content": "WinSCP",
    "description": "WinSCP is a popular open-source SFTP, FTP, and SCP client for Windows. It allows secure file transfers between a local and a remote computer.",
    "link": "https://winscp.net/",
    "winget": "WinSCP.WinSCP"
  },
  "WPFInstallwireguard": {
    "category": "Pro Tools",
    "choco": "wireguard",
    "content": "WireGuard",
    "description": "WireGuard is a fast and modern VPN (Virtual Private Network) protocol. It aims to be simpler and more efficient than other VPN protocols, providing secure and reliable connections.",
    "link": "https://www.wireguard.com/",
    "winget": "WireGuard.WireGuard"
  },
  "WPFInstallwireshark": {
    "category": "Pro Tools",
    "choco": "wireshark",
    "content": "Wireshark",
    "description": "Wireshark is a widely-used open-source network protocol analyzer. It allows users to capture and analyze network traffic in real-time, providing detailed insights into network activities.",
    "link": "https://www.wireshark.org/",
    "winget": "WiresharkFoundation.Wireshark"
  },
  "WPFInstallwisetoys": {
    "category": "Utilities",
    "choco": "na",
    "content": "WiseToys",
    "description": "WiseToys is a set of utilities and tools designed to enhance and optimize your Windows experience.",
    "link": "https://toys.wisecleaner.com/",
    "winget": "WiseCleaner.WiseToys"
  },
  "WPFInstallTeraCopy": {
    "category": "Utilities",
    "choco": "TeraCopy",
    "content": "TeraCopy",
    "description": "Copy your files faster and more securely",
    "link": "https://codesector.com/teracopy",
    "winget": "CodeSector.TeraCopy"
  },
  "WPFInstallwizfile": {
    "category": "Utilities",
    "choco": "na",
    "content": "WizFile",
    "description": "Find files by name on your hard drives almost instantly.",
    "link": "https://antibody-software.com/wizfile/",
    "winget": "AntibodySoftware.WizFile"
  },
  "WPFInstallwiztree": {
    "category": "Utilities",
    "choco": "wiztree",
    "content": "WizTree",
    "description": "WizTree is a fast disk space analyzer that helps you quickly find the files and folders consuming the most space on your hard drive.",
    "link": "https://wiztreefree.com/",
    "winget": "AntibodySoftware.WizTree"
  },
  "WPFInstallxdm": {
    "category": "Utilities",
    "choco": "xdm",
    "content": "Xtreme Download Manager",
    "description": "Xtreme Download Manager is an advanced download manager with support for various protocols and browsers.*Browser integration deprecated by google store. No official release.*",
    "link": "https://xtremedownloadmanager.com/",
    "winget": "subhra74.XtremeDownloadManager"
  },
  "WPFInstallxeheditor": {
    "category": "Utilities",
    "choco": "HxD",
    "content": "HxD Hex Editor",
    "description": "HxD is a free hex editor that allows you to edit, view, search, and analyze binary files.",
    "link": "https://mh-nexus.de/en/hxd/",
    "winget": "MHNexus.HxD"
  },
  "WPFInstallxemu": {
    "category": "Games",
    "choco": "na",
    "content": "XEMU",
    "description": "XEMU is an open-source Xbox emulator that allows you to play Xbox games on your PC, aiming for accuracy and compatibility.",
    "link": "https://xemu.app/",
    "winget": "xemu-project.xemu"
  },
  "WPFInstallxnview": {
    "category": "Utilities",
    "choco": "xnview",
    "content": "XnView classic",
    "description": "XnView is an efficient image viewer, browser and converter for Windows.",
    "link": "https://www.xnview.com/en/xnview/",
    "winget": "XnSoft.XnView.Classic"
  },
  "WPFInstallxournal": {
    "category": "Document",
    "choco": "xournalplusplus",
    "content": "Xournal++",
    "description": "Xournal++ is an open-source handwriting notetaking software with PDF annotation capabilities.",
    "link": "https://xournalpp.github.io/",
    "winget": "Xournal++.Xournal++"
  },
  "WPFInstallxpipe": {
    "category": "Pro Tools",
    "choco": "xpipe",
    "content": "XPipe",
    "description": "XPipe is an open-source tool for orchestrating containerized applications. It simplifies the deployment and management of containerized services in a distributed environment.",
    "link": "https://xpipe.io/",
    "winget": "xpipe-io.xpipe"
  },
  "WPFInstallyarn": {
    "category": "Development",
    "choco": "yarn",
    "content": "Yarn",
    "description": "Yarn is a fast, reliable, and secure dependency management tool for JavaScript projects.",
    "link": "https://yarnpkg.com/",
    "winget": "Yarn.Yarn"
  },
  "WPFInstallytdlp": {
    "category": "Multimedia Tools",
    "choco": "yt-dlp",
    "content": "Yt-dlp",
    "description": "Command-line tool that allows you to download videos from YouTube and other supported sites. It is an improved version of the popular youtube-dl.",
    "link": "https://github.com/yt-dlp/yt-dlp",
    "winget": "yt-dlp.yt-dlp"
  },
  "WPFInstallzerotierone": {
    "category": "Utilities",
    "choco": "zerotier-one",
    "content": "ZeroTier One",
    "description": "ZeroTier One is a software-defined networking tool that allows you to create secure and scalable networks.",
    "link": "https://zerotier.com/",
    "winget": "ZeroTier.ZeroTierOne"
  },
  "WPFInstallzim": {
    "category": "Document",
    "choco": "zim",
    "content": "Zim Desktop Wiki",
    "description": "Zim Desktop Wiki is a graphical text editor used to maintain a collection of wiki pages.",
    "link": "https://zim-wiki.org/",
    "winget": "Zimwiki.Zim"
  },
  "WPFInstallznote": {
    "category": "Document",
    "choco": "na",
    "content": "Znote",
    "description": "Znote is a note-taking application.",
    "link": "https://znote.io/",
    "winget": "alagrede.znote"
  },
  "WPFInstallzoom": {
    "category": "Communications",
    "choco": "zoom",
    "content": "Zoom",
    "description": "Zoom is a popular video conferencing and web conferencing service for online meetings, webinars, and collaborative projects.",
    "link": "https://zoom.us/",
    "winget": "Zoom.Zoom"
  },
  "WPFInstallzoomit": {
    "category": "Utilities",
    "choco": "na",
    "content": "ZoomIt",
    "description": "A screen zoom, annotation, and recording tool for technical presentations and demos",
    "link": "https://learn.microsoft.com/en-us/sysinternals/downloads/zoomit",
    "winget": "Microsoft.Sysinternals.ZoomIt"
  },
  "WPFInstallzotero": {
    "category": "Document",
    "choco": "zotero",
    "content": "Zotero",
    "description": "Zotero is a free, easy-to-use tool to help you collect, organize, cite, and share your research materials.",
    "link": "https://www.zotero.org/",
    "winget": "DigitalScholar.Zotero"
  },
  "WPFInstallzoxide": {
    "category": "Utilities",
    "choco": "zoxide",
    "content": "Zoxide",
    "description": "Zoxide is a fast and efficient directory changer (cd) that helps you navigate your file system with ease.",
    "link": "https://github.com/ajeetdsouza/zoxide",
    "winget": "ajeetdsouza.zoxide"
  },
  "WPFInstallzulip": {
    "category": "Communications",
    "choco": "zulip",
    "content": "Zulip",
    "description": "Zulip is an open-source team collaboration tool with chat streams for productive and organized communication.",
    "link": "https://zulipchat.com/",
    "winget": "Zulip.Zulip"
  },
  "WPFInstallsyncthingtray": {
    "category": "Utilities",
    "choco": "syncthingtray",
    "content": "Syncthingtray",
    "description": "Might be the alternative for Synctrayzor. Windows tray utility / filesystem watcher / launcher for Syncthing",
    "link": "https://github.com/Martchus/syncthingtray",
    "winget": "Martchus.syncthingtray"
  },
  "WPFInstallminiconda": {
    "category": "Development",
    "choco": "miniconda3",
    "content": "Miniconda",
    "description": "Miniconda is a free minimal installer for conda. It is a small bootstrap version of Anaconda that includes only conda, Python, the packages they both depend on, and a small number of other useful packages (like pip, zlib, and a few others).",
    "link": "https://docs.conda.io/projects/miniconda",
    "winget": "Anaconda.Miniconda3"
  },
  "WPFInstallpixi": {
    "category": "Development",
    "choco": "pixi",
    "content": "Pixi",
    "description": "Pixi is a fast software package manager built on top of the existing conda ecosystem. Spins up development environments quickly on Windows, macOS and Linux. Pixi supports Python, R, C/C++, Rust, Ruby, and many other languages.",
    "link": "https://pixi.sh",
    "winget": "prefix-dev.pixi"
  },
  "WPFInstalltemurin": {
    "category": "Development",
    "choco": "temurin",
    "content": "Eclipse Temurin",
    "description": "Eclipse Temurin is the open source Java SE build based upon OpenJDK.",
    "link": "https://adoptium.net/temurin/",
    "winget": "EclipseAdoptium.Temurin.21.JDK"
  },
  "WPFInstallintelpresentmon": {
    "category": "Utilities",
    "choco": "na",
    "content": "Intel-PresentMon",
    "description": "A new gaming performance overlay and telemetry application to monitor and measure your gaming experience.",
    "link": "https://game.intel.com/us/stories/intel-presentmon/",
    "winget": "Intel.PresentMon.Beta"
  },
  "WPFInstallpyenvwin": {
    "category": "Development",
    "choco": "pyenv-win",
    "content": "Python Version Manager (pyenv-win)",
    "description": "pyenv for Windows is a simple python version management tool. It lets you easily switch between multiple versions of Python.",
    "link": "https://pyenv-win.github.io/pyenv-win/",
    "winget": "na"
  },
  "WPFInstalltightvnc": {
    "category": "Utilities",
    "choco": "TightVNC",
    "content": "TightVNC",
    "description": "TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network. With its intuitive interface, you can interact with the remote screen as if you were sitting in front of it. You can open files, launch applications, and perform other actions on the remote desktop almost as if you were physically there",
    "link": "https://www.tightvnc.com/",
    "winget": "GlavSoft.TightVNC"
  },
  "WPFInstallultravnc": {
    "category": "Utilities",
    "choco": "ultravnc",
    "content": "UltraVNC",
    "description": "UltraVNC is a powerful, easy to use and free - remote pc access softwares - that can display the screen of another computer (via internet or network) on your own screen. The program allows you to use your mouse and keyboard to control the other PC remotely. It means that you can work on a remote computer, as if you were sitting in front of it, right from your current location.",
    "link": "https://uvnc.com/",
    "winget": "uvncbvba.UltraVnc"
  },
  "WPFInstallwindowsfirewallcontrol": {
    "category": "Utilities",
    "choco": "windowsfirewallcontrol",
    "content": "Windows Firewall Control",
    "description": "Windows Firewall Control is a powerful tool which extends the functionality of Windows Firewall and provides new extra features which makes Windows Firewall better.",
    "link": "https://www.binisoft.org/wfc",
    "winget": "BiniSoft.WindowsFirewallControl"
  },
  "WPFInstallvistaswitcher": {
    "category": "Utilities",
    "choco": "na",
    "content": "VistaSwitcher",
    "description": "VistaSwitcher makes it easier for you to locate windows and switch focus, even on multi-monitor systems. The switcher window consists of an easy-to-read list of all tasks running with clearly shown titles and a full-sized preview of the selected task.",
    "link": "https://www.ntwind.com/freeware/vistaswitcher.html",
    "winget": "ntwind.VistaSwitcher"
  },
  "WPFInstallautodarkmode": {
    "category": "Utilities",
    "choco": "auto-dark-mode",
    "content": "Windows Auto Dark Mode",
    "description": "Automatically switches between the dark and light theme of Windows 10 and Windows 11",
    "link": "https://github.com/AutoDarkMode/Windows-Auto-Night-Mode",
    "winget": "Armin2208.WindowsAutoNightMode"
  },
  "WPFInstallAmbieWhiteNoise": {
    "category": "Utilities",
    "choco": "na",
    "content": "Ambie White Noise",
    "description": "Ambie is the ultimate app to help you focus, study, or relax. We use white noise and nature sounds combined with an innovative focus timer to keep you concentrated on doing your best work.",
    "link": "https://ambieapp.com/",
    "winget": "9P07XNM5CHP0"
  },
  "WPFInstallmagicwormhole": {
    "category": "Utilities",
    "choco": "magic-wormhole",
    "content": "Magic Wormhole",
    "description": "get things from one computer to another, safely",
    "link": "https://github.com/magic-wormhole/magic-wormhole",
    "winget": "magic-wormhole.magic-wormhole"
  },
  "WPFInstallcroc": {
    "category": "Utilities",
    "choco": "croc",
    "content": "croc",
    "description": "Easily and securely send things from one computer to another.",
    "link": "https://github.com/schollz/croc",
    "winget": "schollz.croc"
  },
  "WPFInstallqgis": {
    "category": "Multimedia Tools",
    "choco": "qgis",
    "content": "QGIS",
    "description": "QGIS (Quantum GIS) is an open-source Geographic Information System (GIS) software that enables users to create, edit, visualize, analyze, and publish geospatial information on Windows, Mac, and Linux platforms.",
    "link": "https://qgis.org/en/site/",
    "winget": "OSGeo.QGIS"
  },
  "WPFInstallsmplayer": {
    "category": "Multimedia Tools",
    "choco": "smplayer",
    "content": "SMPlayer",
    "description": "SMPlayer is a free media player for Windows and Linux with built-in codecs that can play virtually all video and audio formats.",
    "link": "https://www.smplayer.info",
    "winget": "SMPlayer.SMPlayer"
  },
  "WPFInstallglazewm": {
    "category": "Utilities",
    "choco": "na",
    "content": "GlazeWM",
    "description": "GlazeWM is a tiling window manager for Windows inspired by i3 and Polybar",
    "link": "https://github.com/glzr-io/glazewm",
    "winget": "glzr-io.glazewm"
  },
  "WPFInstallfancontrol": {
    "category": "Utilities",
    "choco": "na",
    "content": "FanControl",
    "description": "Fan Control is a free and open-source software that allows the user to control his CPU, GPU and case fans using temperatures.",
    "link": "https://getfancontrol.com/",
    "winget": "Rem0o.FanControl"
  },
  "WPFInstallfnm": {
    "category": "Development",
    "choco": "fnm",
    "content": "Fast Node Manager",
    "description": "Fast Node Manager (fnm) allows you to switch your Node version by using the Terminal",
    "link": "https://github.com/Schniz/fnm",
    "winget": "Schniz.fnm"
  },
  "WPFInstallWindhawk": {
    "category": "Utilities",
    "choco": "windhawk",
    "content": "Windhawk",
    "description": "The customization marketplace for Windows programs",
    "link": "https://windhawk.net",
    "winget": "RamenSoftware.Windhawk"
  },
  "WPFInstallForceAutoHDR": {
    "category": "Utilities",
    "choco": "na",
    "content": "ForceAutoHDR",
    "description": "ForceAutoHDR simplifies the process of adding games to the AutoHDR list in the Windows Registry",
    "link": "https://github.com/7gxycn08/ForceAutoHDR",
    "winget": "ForceAutoHDR.7gxycn08"
  },
  "WPFInstallJoyToKey": {
    "category": "Utilities",
    "choco": "joytokey",
    "content": "JoyToKey",
    "description": "enables PC game controllers to emulate the keyboard and mouse input",
    "link": "https://joytokey.net/en/",
    "winget": "JTKsoftware.JoyToKey"
  },
  "WPFInstallnditools": {
    "category": "Multimedia Tools",
    "choco": "na",
    "content": "NDI Tools",
    "description": "NDI, or Network Device Interface, is a video connectivity standard that enables multimedia systems to identify and communicate with one another over IP and to encode, transmit, and receive high-quality, low latency, frame-accurate video and audio, and exchange metadata in real-time.",
    "link": "https://ndi.video/",
    "winget": "NDI.NDITools"
  },
  "WPFInstallkicad": {
    "category": "Multimedia Tools",
    "choco": "na",
    "content": "Kicad",
    "description": "Kicad is an open-source EDA tool. It's a good starting point for those who want to do electrical design and is even used by professionals in the industry.",
    "link": "https://www.kicad.org/",
    "winget": "KiCad.KiCad"
  },
  "WPFInstalldropox": {
    "category": "Utilities",
    "choco": "na",
    "content": "Dropbox",
    "description": "The Dropbox desktop app! Save hard drive space, share and edit files and send for signature ? all without the distraction of countless browser tabs.",
    "link": "https://www.dropbox.com/en_GB/desktop",
    "winget": "Dropbox.Dropbox"
  },
  "WPFInstallOFGB": {
    "category": "Utilities",
    "choco": "ofgb",
    "content": "OFGB (Oh Frick Go Back)",
    "description": "GUI Tool to remove ads from various places around Windows 11",
    "link": "https://github.com/xM4ddy/OFGB",
    "winget": "xM4ddy.OFGB"
  },
  "WPFInstallPaleMoon": {
    "category": "Browsers",
    "choco": "paleMoon",
    "content": "PaleMoon",
    "description": "Pale Moon is an Open Source, Goanna-based web browser available for Microsoft Windows and Linux (with other operating systems in development), focusing on efficiency and ease of use.",
    "link": "https://www.palemoon.org/download.shtml",
    "winget": "MoonchildProductions.PaleMoon"
  },
  "WPFInstallShotcut": {
    "category": "Multimedia Tools",
    "choco": "na",
    "content": "Shotcut",
    "description": "Shotcut is a free, open source, cross-platform video editor.",
    "link": "https://shotcut.org/",
    "winget": "Meltytech.Shotcut"
  },
  "WPFInstallLenovoLegionToolkit": {
    "category": "Utilities",
    "choco": "na",
    "content": "Lenovo Legion Toolkit",
    "description": "Lenovo Legion Toolkit (LLT) is a open-source utility created for Lenovo Legion (and similar) series laptops, that allows changing a couple of features that are only available in Lenovo Vantage or Legion Zone. It runs no background services, uses less memory, uses virtually no CPU, and contains no telemetry. Just like Lenovo Vantage, this application is Windows only.",
    "link": "https://github.com/BartoszCichecki/LenovoLegionToolkit",
    "winget": "BartoszCichecki.LenovoLegionToolkit"
  },
  "WPFInstallPulsarEdit": {
    "category": "Development",
    "choco": "pulsar",
    "content": "Pulsar",
    "description": "A Community-led Hyper-Hackable Text Editor",
    "link": "https://pulsar-edit.dev/",
    "winget": "Pulsar-Edit.Pulsar"
  },
  "WPFInstallAegisub": {
    "category": "Development",
    "choco": "aegisub",
    "content": "Aegisub",
    "description": "Aegisub is a free, cross-platform open source tool for creating and modifying subtitles. Aegisub makes it quick and easy to time subtitles to audio, and features many powerful tools for styling them, including a built-in real-time video preview.",
    "link": "https://github.com/Aegisub/Aegisub",
    "winget": "Aegisub.Aegisub"
  },
  "WPFInstallSubtitleEdit": {
    "category": "Multimedia Tools",
    "choco": "na",
    "content": "Subtitle Edit",
    "description": "Subtitle Edit is a free and open source editor for video subtitles.",
    "link": "https://github.com/SubtitleEdit/subtitleedit",
    "winget": "Nikse.SubtitleEdit"
  },
  "WPFInstallFork": {
    "category": "Development",
    "choco": "git-fork",
    "content": "Fork",
    "description": "Fork - a fast and friendly git client.",
    "link": "https://git-fork.com/",
    "winget": "Fork.Fork"
  }
}
'@ | ConvertFrom-Json
$sync.configs.dns = @'
{
  "Google": {
    "Primary": "8.8.8.8",
    "Secondary": "8.8.4.4",
    "Primary6": "2001:4860:4860::8888",
    "Secondary6": "2001:4860:4860::8844"
  },
  "Cloudflare": {
    "Primary": "1.1.1.1",
    "Secondary": "1.0.0.1",
    "Primary6": "2606:4700:4700::1111",
    "Secondary6": "2606:4700:4700::1001"
  },
  "Cloudflare_Malware": {
    "Primary": "1.1.1.2",
    "Secondary": "1.0.0.2",
    "Primary6": "2606:4700:4700::1112",
    "Secondary6": "2606:4700:4700::1002"
  },
  "Cloudflare_Malware_Adult": {
    "Primary": "1.1.1.3",
    "Secondary": "1.0.0.3",
    "Primary6": "2606:4700:4700::1113",
    "Secondary6": "2606:4700:4700::1003"
  },
  "Open_DNS": {
    "Primary": "208.67.222.222",
    "Secondary": "208.67.220.220",
    "Primary6": "2620:119:35::35",
    "Secondary6": "2620:119:53::53"
  },
  "Quad9": {
    "Primary": "9.9.9.9",
    "Secondary": "149.112.112.112",
    "Primary6": "2620:fe::fe",
    "Secondary6": "2620:fe::9"
  },
  "AdGuard_Ads_Trackers": {
    "Primary": "94.140.14.14",
    "Secondary": "94.140.15.15",
    "Primary6": "2a10:50c0::ad1:ff",
    "Secondary6": "2a10:50c0::ad2:ff"
  },
  "AdGuard_Ads_Trackers_Malware_Adult": {
    "Primary": "94.140.14.15",
    "Secondary": "94.140.15.16",
    "Primary6": "2a10:50c0::bad1:ff",
    "Secondary6": "2a10:50c0::bad2:ff"
  },
  "dns0.eu_Open": {
    "Primary": "193.110.81.254",
    "Secondary": "185.253.5.254",
    "Primary6": "2a0f:fc80::ffff",
    "Secondary6": "2a0f:fc81::ffff"
  },
  "dns0.eu_ZERO": {
    "Primary": "193.110.81.9",
    "Secondary": "185.253.5.9",
    "Primary6": "2a0f:fc80::9",
    "Secondary6": "2a0f:fc81::9"
  },
  "dns0.eu_KIDS": {
    "Primary": "193.110.81.1",
    "Secondary": "185.253.5.1",
    "Primary6": "2a0f:fc80::1",
    "Secondary6": "2a0f:fc81::1"
  }
}
'@ | ConvertFrom-Json
$sync.configs.feature = @'
{
  "WPFFeaturesdotnet": {
    "Content": "All .Net Framework (2,3,4)",
    "Description": ".NET and .NET Framework is a developer platform made up of tools, programming languages, and libraries for building many different types of applications.",
    "category": "Features",
    "panel": "1",
    "Order": "a010_",
    "feature": [
      "NetFx4-AdvSrvs",
      "NetFx3"
    ],
    "InvokeScript": [],
    "link": "https://tut-os.github.io/winutil/dev/features/Features/dotnet"
  },
  "WPFFeatureshyperv": {
    "Content": "HyperV Virtualization",
    "Description": "Hyper-V is a hardware virtualization product developed by Microsoft that allows users to create and manage virtual machines.",
    "category": "Features",
    "panel": "1",
    "Order": "a011_",
    "feature": [
      "HypervisorPlatform",
      "Microsoft-Hyper-V-All",
      "Microsoft-Hyper-V",
      "Microsoft-Hyper-V-Tools-All",
      "Microsoft-Hyper-V-Management-PowerShell",
      "Microsoft-Hyper-V-Hypervisor",
      "Microsoft-Hyper-V-Services",
      "Microsoft-Hyper-V-Management-Clients"
    ],
    "InvokeScript": [
      "Start-Process -FilePath cmd.exe -ArgumentList '/c bcdedit /set hypervisorschedulertype classic' -Wait"
    ],
    "link": "https://tut-os.github.io/winutil/dev/features/Features/hyperv"
  },
  "WPFFeatureslegacymedia": {
    "Content": "Legacy Media (WMP, DirectPlay)",
    "Description": "Enables legacy programs from previous versions of windows",
    "category": "Features",
    "panel": "1",
    "Order": "a012_",
    "feature": [
      "WindowsMediaPlayer",
      "MediaPlayback",
      "DirectPlay",
      "LegacyComponents"
    ],
    "InvokeScript": [],
    "link": "https://tut-os.github.io/winutil/dev/features/Features/legacymedia"
  },
  "WPFFeaturewsl": {
    "Content": "Windows Subsystem for Linux",
    "Description": "Windows Subsystem for Linux is an optional feature of Windows that allows Linux programs to run natively on Windows without the need for a separate virtual machine or dual booting.",
    "category": "Features",
    "panel": "1",
    "Order": "a020_",
    "feature": [
      "VirtualMachinePlatform",
      "Microsoft-Windows-Subsystem-Linux"
    ],
    "InvokeScript": [],
    "link": "https://tut-os.github.io/winutil/dev/features/Features/wsl"
  },
  "WPFFeaturenfs": {
    "Content": "NFS - Network File System",
    "Description": "Network File System (NFS) is a mechanism for storing files on a network.",
    "category": "Features",
    "panel": "1",
    "Order": "a014_",
    "feature": [
      "ServicesForNFS-ClientOnly",
      "ClientForNFS-Infrastructure",
      "NFS-Administration"
    ],
    "InvokeScript": [
      "nfsadmin client stop",
      "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\ClientForNFS\\CurrentVersion\\Default' -Name 'AnonymousUID' -Type DWord -Value 0",
      "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\ClientForNFS\\CurrentVersion\\Default' -Name 'AnonymousGID' -Type DWord -Value 0",
      "nfsadmin client start",
      "nfsadmin client localhost config fileaccess=755 SecFlavors=+sys -krb5 -krb5i"
    ],
    "link": "https://tut-os.github.io/winutil/dev/features/Features/nfs"
  },
  "WPFFeatureEnableSearchSuggestions": {
    "Content": "Enable Search Box Web Suggestions in Registry(explorer restart)",
    "Description": "Enables web suggestions when searching using Windows Search.",
    "category": "Features",
    "panel": "1",
    "Order": "a015_",
    "feature": [],
    "InvokeScript": [
      "\r\n      If (!(Test-Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer')) {\r\n            New-Item -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer' -Force | Out-Null\r\n      }\r\n      New-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer' -Name 'DisableSearchBoxSuggestions' -Type DWord -Value 0 -Force\r\n      Stop-Process -name explorer -force\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/features/Features/EnableSearchSuggestions"
  },
  "WPFFeatureDisableSearchSuggestions": {
    "Content": "Disable Search Box Web Suggestions in Registry(explorer restart)",
    "Description": "Disables web suggestions when searching using Windows Search.",
    "category": "Features",
    "panel": "1",
    "Order": "a016_",
    "feature": [],
    "InvokeScript": [
      "\r\n      If (!(Test-Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer')) {\r\n            New-Item -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer' -Force | Out-Null\r\n      }\r\n      New-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer' -Name 'DisableSearchBoxSuggestions' -Type DWord -Value 1 -Force\r\n      Stop-Process -name explorer -force\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/features/Features/DisableSearchSuggestions"
  },
  "WPFFeatureRegBackup": {
    "Content": "Enable Daily Registry Backup Task 12.30am",
    "Description": "Enables daily registry backup, previously disabled by Microsoft in Windows 10 1803.",
    "category": "Features",
    "panel": "1",
    "Order": "a017_",
    "feature": [],
    "InvokeScript": [
      "\r\n      New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager' -Name 'EnablePeriodicBackup' -Type DWord -Value 1 -Force\r\n      New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager' -Name 'BackupCount' -Type DWord -Value 2 -Force\r\n      $action = New-ScheduledTaskAction -Execute 'schtasks' -Argument '/run /i /tn \"\\Microsoft\\Windows\\Registry\\RegIdleBackup\"'\r\n      $trigger = New-ScheduledTaskTrigger -Daily -At 00:30\r\n      Register-ScheduledTask -Action $action -Trigger $trigger -TaskName 'AutoRegBackup' -Description 'Create System Registry Backups' -User 'System'\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/features/Features/RegBackup"
  },
  "WPFFeatureEnableLegacyRecovery": {
    "Content": "Enable Legacy F8 Boot Recovery",
    "Description": "Enables Advanced Boot Options screen that lets you start Windows in advanced troubleshooting modes.",
    "category": "Features",
    "panel": "1",
    "Order": "a018_",
    "feature": [],
    "InvokeScript": [
      "\r\n      If (!(Test-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood')) {\r\n            New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood' -Force | Out-Null\r\n      }\r\n      New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood' -Name 'Enabled' -Type DWord -Value 1 -Force\r\n      Start-Process -FilePath cmd.exe -ArgumentList '/c bcdedit /Set {Current} BootMenuPolicy Legacy' -Wait\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/features/Features/EnableLegacyRecovery"
  },
  "WPFFeatureDisableLegacyRecovery": {
    "Content": "Disable Legacy F8 Boot Recovery",
    "Description": "Disables Advanced Boot Options screen that lets you start Windows in advanced troubleshooting modes.",
    "category": "Features",
    "panel": "1",
    "Order": "a019_",
    "feature": [],
    "InvokeScript": [
      "\r\n      If (!(Test-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood')) {\r\n            New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood' -Force | Out-Null\r\n      }\r\n      New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood' -Name 'Enabled' -Type DWord -Value 0 -Force\r\n      Start-Process -FilePath cmd.exe -ArgumentList '/c bcdedit /Set {Current} BootMenuPolicy Standard' -Wait\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/features/Features/DisableLegacyRecovery"
  },
  "WPFFeaturesSandbox": {
    "Content": "Windows Sandbox",
    "category": "Features",
    "panel": "1",
    "Order": "a021_",
    "Description": "Windows Sandbox is a lightweight virtual machine that provides a temporary desktop environment to safely run applications and programs in isolation.",
    "link": "https://tut-os.github.io/winutil/dev/features/Features/Sandbox"
  },
  "WPFFeatureInstall": {
    "Content": "Install Features",
    "category": "Features",
    "panel": "1",
    "Order": "a060_",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Features/Install"
  },
  "WPFPanelAutologin": {
    "Content": "Set Up Autologin",
    "category": "Fixes",
    "Order": "a040_",
    "panel": "1",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Fixes/Autologin"
  },
  "WPFFixesUpdate": {
    "Content": "Reset Windows Update",
    "category": "Fixes",
    "panel": "1",
    "Order": "a041_",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Fixes/Update"
  },
  "WPFFixesNetwork": {
    "Content": "Reset Network",
    "category": "Fixes",
    "Order": "a042_",
    "panel": "1",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Fixes/Network"
  },
  "WPFPanelDISM": {
    "Content": "System Corruption Scan",
    "category": "Fixes",
    "panel": "1",
    "Order": "a043_",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Fixes/DISM"
  },
  "WPFFixesWinget": {
    "Content": "WinGet Reinstall",
    "category": "Fixes",
    "panel": "1",
    "Order": "a044_",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Fixes/Winget"
  },
  "WPFRunAdobeCCCleanerTool": {
    "Content": "Remove Adobe Creative Cloud",
    "category": "Fixes",
    "panel": "1",
    "Order": "a045_",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Fixes/RunAdobeCCCleanerTool"
  },
  "WPFPanelnetwork": {
    "Content": "Network Connections",
    "category": "Legacy Windows Panels",
    "panel": "2",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Legacy-Windows-Panels/network"
  },
  "WPFPanelcontrol": {
    "Content": "Control Panel",
    "category": "Legacy Windows Panels",
    "panel": "2",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Legacy-Windows-Panels/control"
  },
  "WPFPanelpower": {
    "Content": "Power Panel",
    "category": "Legacy Windows Panels",
    "panel": "2",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Legacy-Windows-Panels/power"
  },
  "WPFPanelregion": {
    "Content": "Region",
    "category": "Legacy Windows Panels",
    "panel": "2",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Legacy-Windows-Panels/region"
  },
  "WPFPanelsound": {
    "Content": "Sound Settings",
    "category": "Legacy Windows Panels",
    "panel": "2",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Legacy-Windows-Panels/sound"
  },
  "WPFPanelprinter": {
    "Content": "Printer Panel",
    "category": "Legacy Windows Panels",
    "panel": "2",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Legacy-Windows-Panels/printer"
  },
  "WPFPanelsystem": {
    "Content": "System Properties",
    "category": "Legacy Windows Panels",
    "panel": "2",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Legacy-Windows-Panels/system"
  },
  "WPFPaneluser": {
    "Content": "User Accounts",
    "category": "Legacy Windows Panels",
    "panel": "2",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Legacy-Windows-Panels/user"
  },
  "WPFWinUtilInstallPSProfile": {
    "Content": "Install CTT PowerShell Profile",
    "category": "Powershell Profile",
    "panel": "2",
    "Order": "a083_",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Powershell-Profile/PSProfileInstall"
  },
  "WPFWinUtilUninstallPSProfile": {
    "Content": "Uninstall CTT PowerShell Profile",
    "category": "Powershell Profile",
    "panel": "2",
    "Order": "a084_",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/features/Powershell-Profile/PSProfileUninstall"
  },
  "WPFWinUtilSSHServer": {
    "Content": "Enable OpenSSH Server",
    "category": "Remote Access",
    "panel": "2",
    "Order": "a084_",
    "Type": "Button",
    "ButtonWidth": "300"
  }
}
'@ | ConvertFrom-Json
$sync.configs.preset = @'
{
  "Standard": [
    "WPFTweaksAH",
    "WPFTweaksConsumerFeatures",
    "WPFTweaksDVR",
    "WPFTweaksHiber",
    "WPFTweaksHome",
    "WPFTweaksLoc",
    "WPFTweaksServices",
    "WPFTweaksStorage",
    "WPFTweaksTele",
    "WPFTweaksWifi",
    "WPFTweaksDiskCleanup",
    "WPFTweaksDeleteTempFiles",
    "WPFTweaksEndTaskOnTaskbar",
    "WPFTweaksRestorePoint",
    "WPFTweaksPowershell7Tele"
  ],
  "Minimal": [
    "WPFTweaksConsumerFeatures",
    "WPFTweaksHome",
    "WPFTweaksServices",
    "WPFTweaksTele"
  ]
}
'@ | ConvertFrom-Json
$sync.configs.themes = $sync.configs.themes = @'
{
  "shared": {
    "CustomDialogFontSize": "12",
    "CustomDialogFontSizeHeader": "14",
    "CustomDialogLogoSize": "25",
    "CustomDialogWidth": "300",
    "CustomDialogHeight": "400",
    "FontSize": "15",
    "FontFamily": "Arial",
    "HeadingFontSize": "13",
    "HeaderFontFamily": "Consolas, Monaco",
    "CheckBoxBulletDecoratorSize": "14",
    "CheckBoxMargin": "15,0,0,2",
    "TabContentMargin": "5",
    "TabButtonFontSize": "14",
    "TabButtonWidth": "110",
    "TabButtonHeight": "26",
    "TabRowHeightInPixels": "50",
    "IconFontSize": "14",
    "IconButtonSize": "35",
    "SettingsIconFontSize": "18",
    "CloseIconFontSize": "18",
    "MicroWinLogoSize": "10",
    "MicrowinCheckBoxMargin": "-10,5,0,0",
    "GroupBorderBackgroundColor": "#2F3136",
    "ButtonFontSize": "12",
    "ButtonFontFamily": "Arial",
    "ButtonWidth": "200",
    "ButtonHeight": "25",
    "ConfigUpdateButtonFontSize": "14",
    "SearchBarWidth": "200",
    "SearchBarHeight": "26",
    "SearchBarTextBoxFontSize": "12",
    "SearchBarClearButtonFontSize": "14",
    "CheckboxMouseOverColor": "#FFA500",
    "ButtonBorderThickness": "1",
    "ButtonMargin": "1",
    "ButtonCornerRadius": "2"
  },
  "dark": {
    "ComboBoxForegroundColor": "#FFA500",
    "ComboBoxBackgroundColor": "#36393F",
    "LabelboxForegroundColor": "#FFA500",
    "MainForegroundColor": "#FFFFFF",
    "MainBackgroundColor": "#2F3136",
    "LabelBackgroundColor": "#2F3136",
    "LinkForegroundColor": "#FFA500",
    "LinkHoverForegroundColor": "#FF8C00",
    "ScrollBarBackgroundColor": "#202225",
    "ScrollBarHoverColor": "#FF8C00",
    "ScrollBarDraggingColor": "#FF4500",
    "ProgressBarForegroundColor": "#FF8C00",
    "ProgressBarBackgroundColor": "Transparent",
    "ProgressBarTextColor": "#FFA500",
    "ButtonInstallBackgroundColor": "#36393F",
    "ButtonTweaksBackgroundColor": "#40444B",
    "ButtonConfigBackgroundColor": "#484C52",
    "ButtonUpdatesBackgroundColor": "#4E5258",
    "ButtonInstallForegroundColor": "#FFA500",
    "ButtonTweaksForegroundColor": "#FFA500",
    "ButtonConfigForegroundColor": "#FFA500",
    "ButtonUpdatesForegroundColor": "#FFA500",
    "ButtonBackgroundColor": "#36393F",
    "ButtonBackgroundPressedColor": "#FF8C00",
    "ButtonBackgroundMouseoverColor": "#FF4500",
    "ButtonBackgroundSelectedColor": "#FF8C00",
    "ButtonForegroundColor": "#FFA500",
    "ToggleButtonOnColor": "#FF8C00",
    "ToggleButtonOffColor": "#707070",
    "BorderColor": "#FFA500",
    "BorderOpacity": "0.2"
  }
}

'@ | ConvertFrom-Json
$sync.configs.tweaks = @'
{
  "WPFTweaksAH": {
    "Content": "Disable Activity History",
    "Description": "This erases recent docs, clipboard, and run history.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a005_",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
        "Name": "EnableActivityFeed",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
        "Name": "PublishUserActivities",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
        "Name": "UploadUserActivities",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/AH"
  },
  "WPFTweaksHiber": {
    "Content": "Disable Hibernation",
    "Description": "Hibernation is really meant for laptops as it saves what's in memory before turning the pc off. It really should never be used, but some people are lazy and rely on it. Don't be like Bob. Bob likes hibernation.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a005_",
    "registry": [
      {
        "Path": "HKLM:\\System\\CurrentControlSet\\Control\\Session Manager\\Power",
        "Name": "HibernateEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FlyoutMenuSettings",
        "Name": "ShowHibernateOption",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      }
    ],
    "InvokeScript": [
      "powercfg.exe /hibernate off"
    ],
    "UndoScript": [
      "powercfg.exe /hibernate on"
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/Hiber"
  },
  "WPFTweaksLaptopHibernation": {
    "Content": "Set Hibernation as default (good for laptops)",
    "Description": "Most modern laptops have connected standby enabled which drains the battery, this sets hibernation as default which will not drain the battery. See issue https://github.com/tut-os/winutil/issues/1399",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a014_",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0",
        "OriginalValue": "1",
        "Name": "Attributes",
        "Value": "2",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\abfc2519-3608-4c2a-94ea-171b0ed546ab\\94ac6d29-73ce-41a6-809f-6363ba21b47e",
        "OriginalValue": "0",
        "Name": "Attributes ",
        "Value": "2",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "\r\n      Write-Host \"Turn on Hibernation\"\r\n      Start-Process -FilePath powercfg -ArgumentList \"/hibernate on\" -NoNewWindow -Wait\r\n\r\n      # Set hibernation as the default action\r\n      Start-Process -FilePath powercfg -ArgumentList \"/change standby-timeout-ac 60\" -NoNewWindow -Wait\r\n      Start-Process -FilePath powercfg -ArgumentList \"/change standby-timeout-dc 60\" -NoNewWindow -Wait\r\n      Start-Process -FilePath powercfg -ArgumentList \"/change monitor-timeout-ac 10\" -NoNewWindow -Wait\r\n      Start-Process -FilePath powercfg -ArgumentList \"/change monitor-timeout-dc 1\" -NoNewWindow -Wait\r\n      "
    ],
    "UndoScript": [
      "\r\n      Write-Host \"Turn off Hibernation\"\r\n      Start-Process -FilePath powercfg -ArgumentList \"/hibernate off\" -NoNewWindow -Wait\r\n\r\n      # Set standby to detault values\r\n      Start-Process -FilePath powercfg -ArgumentList \"/change standby-timeout-ac 15\" -NoNewWindow -Wait\r\n      Start-Process -FilePath powercfg -ArgumentList \"/change standby-timeout-dc 15\" -NoNewWindow -Wait\r\n      Start-Process -FilePath powercfg -ArgumentList \"/change monitor-timeout-ac 15\" -NoNewWindow -Wait\r\n      Start-Process -FilePath powercfg -ArgumentList \"/change monitor-timeout-dc 15\" -NoNewWindow -Wait\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/LaptopHibernation"
  },
  "WPFTweaksHome": {
    "Content": "Disable Homegroup",
    "Description": "Disables HomeGroup - HomeGroup is a password-protected home networking service that lets you share your stuff with other PCs that are currently running and connected to your network.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a005_",
    "service": [
      {
        "Name": "HomeGroupListener",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "HomeGroupProvider",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/Home"
  },
  "WPFTweaksLoc": {
    "Content": "Disable Location Tracking",
    "Description": "Disables Location Tracking...DUH!",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a005_",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location",
        "Name": "Value",
        "Type": "String",
        "Value": "Deny",
        "OriginalValue": "Allow"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Sensor\\Overrides\\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}",
        "Name": "SensorPermissionState",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      },
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration",
        "Name": "Status",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      },
      {
        "Path": "HKLM:\\SYSTEM\\Maps",
        "Name": "AutoUpdateEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/Loc"
  },
  "WPFTweaksServices": {
    "Content": "Set Services to Manual",
    "Description": "Turns a bunch of system services to manual that don't need to be running all the time. This is pretty harmless as if the service is needed, it will simply start on demand.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a014_",
    "service": [
      {
        "Name": "AJRouter",
        "StartupType": "Disabled",
        "OriginalType": "Manual"
      },
      {
        "Name": "ALG",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AppIDSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AppMgmt",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AppReadiness",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AppVClient",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "AppXSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Appinfo",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AssignedAccessManagerSvc",
        "StartupType": "Disabled",
        "OriginalType": "Manual"
      },
      {
        "Name": "AudioEndpointBuilder",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "AudioSrv",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Audiosrv",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "AxInstSV",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BDESVC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BFE",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "BITS",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "BTAGService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BcastDVRUserService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BluetoothUserService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BrokerInfrastructure",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Browser",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BthAvctpSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "BthHFSrv",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CDPSvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CDPUserSvc_*",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "COMSysApp",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "CaptureService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "CertPropSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "ClipSVC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "ConsentUxUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "CoreMessagingRegistrar",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CredentialEnrollmentManagerUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "CryptSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CscService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DPS",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DcomLaunch",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DcpSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DevQueryBroker",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DeviceAssociationBrokerSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DeviceAssociationService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DeviceInstall",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DevicePickerUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DevicesFlowUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Dhcp",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DiagTrack",
        "StartupType": "Disabled",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DialogBlockingService",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "DispBrokerDesktopSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DisplayEnhancementService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DmEnrollmentSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Dnscache",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DoSvc",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DsSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DsmSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DusmSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "EFS",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "EapHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "EntAppSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "EventLog",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "EventSystem",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "FDResPub",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Fax",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "FontCache",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "FrameServer",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "FrameServerMonitor",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "GraphicsPerfSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "HomeGroupListener",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "HomeGroupProvider",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "HvHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "IEEtwCollectorService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "IKEEXT",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "InstallService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "InventorySvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "IpxlatCfgSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "KeyIso",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "KtmRm",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "LSM",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "LanmanServer",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "LanmanWorkstation",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "LicenseManager",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "LxpSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MSDTC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MSiSCSI",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MapsBroker",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "McpManagementService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MessagingService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MicrosoftEdgeElevationService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MixedRealityOpenXRSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MpsSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "MsKeyboardFilter",
        "StartupType": "Manual",
        "OriginalType": "Disabled"
      },
      {
        "Name": "NPSMSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NaturalAuthentication",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NcaSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NcbService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NcdAutoSetup",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NetSetupSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NetTcpPortSharing",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "Netlogon",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Netman",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NgcCtnrSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NgcSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NlaSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "OneSyncSvc_*",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "P9RdrService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PNRPAutoReg",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PNRPsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PcaSvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "PeerDistSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PenService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PerfHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PhoneSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PimIndexMaintenanceSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PlugPlay",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PolicyAgent",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Power",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "PrintNotify",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PrintWorkflowUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "ProfSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "PushToInstall",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "QWAVE",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RasAuto",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RasMan",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RemoteAccess",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "RemoteRegistry",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "RetailDemo",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RmSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RpcEptMapper",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "RpcLocator",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RpcSs",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SCPolicySvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SCardSvr",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SDRSVC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SEMgrSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SENS",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SNMPTRAP",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SNMPTrap",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SSDPSRV",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SamSs",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "ScDeviceEnum",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Schedule",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SecurityHealthService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Sense",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SensorDataService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SensorService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SensrSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SessionEnv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SgrmBroker",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SharedAccess",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SharedRealitySvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "ShellHWDetection",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SmsRouter",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Spooler",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SstpSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "StateRepository",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "StiSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "StorSvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SysMain",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SystemEventsBroker",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "TabletInputService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TapiSrv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TermService",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "TextInputManagementService",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Themes",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "TieringEngineService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TimeBroker",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TimeBrokerSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TokenBroker",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TrkWks",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "TroubleshootingSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TrustedInstaller",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UI0Detect",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UdkUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UevAgentService",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "UmRdpService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UnistoreSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UserDataSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UserManager",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "UsoSvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "VGAuthService",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "VMTools",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "VSS",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "VacSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "VaultSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "W32Time",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WEPHOSTSVC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WFDSConMgrSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WMPNetworkSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WManSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WPDBusEnum",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WSService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WSearch",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WaaSMedicSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WalletService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WarpJITSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WbioSrvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Wcmsvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WcsPlugInService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WdNisSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WdiServiceHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WdiSystemHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WebClient",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Wecsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WerSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WiaRpc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WinDefend",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WinHttpAutoProxySvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WinRM",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Winmgmt",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WlanSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WpcMonSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WpnService",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WpnUserService_*",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "XblAuthManager",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "XblGameSave",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "XboxGipSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "XboxNetApiSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "autotimesvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "bthserv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "camsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "cbdhsvc_*",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "cloudidsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "dcsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "defragsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "diagnosticshub.standardcollector.service",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "diagsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "dmwappushservice",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "dot3svc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "edgeupdate",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "edgeupdatem",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "embeddedmode",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "fdPHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "fhsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "gpsvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "hidserv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "icssvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "iphlpsvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "lfsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "lltdsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "lmhosts",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "mpssvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "msiserver",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "netprofm",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "nsi",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "p2pimsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "p2psvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "perceptionsimulation",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "pla",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "seclogon",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "shpamsvc",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "smphost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "spectrum",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "sppsvc",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "ssh-agent",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "svsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "swprv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "tiledatamodelsvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "tzautoupdate",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "uhssvc",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "upnphost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vds",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vm3dservice",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "vmicguestinterface",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicheartbeat",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmickvpexchange",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicrdv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicshutdown",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmictimesync",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicvmsession",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicvss",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmvss",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wbengine",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wcncsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "webthreatdefsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "webthreatdefusersvc_*",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "wercplsupport",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wisvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wlidsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wlpasvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wmiApSrv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "workfolderssvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wscsvc",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "wuauserv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wudfsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/Services"
  },
  "WPFTweaksEdgeDebloat": {
    "Content": "Debloat Edge",
    "Description": "Disables various telemetry options, popups, and other annoyances in Edge.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a016_",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\EdgeUpdate",
        "Name": "CreateDesktopShortcutDefault",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "PersonalizationReportingEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "ShowRecommendationsEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "HideFirstRunExperience",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "UserFeedbackAllowed",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "ConfigureDoNotTrack",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "AlternateErrorPagesEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "EdgeCollectionsEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "EdgeShoppingAssistantEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "MicrosoftEdgeInsiderPromotionEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "PersonalizationReportingEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "ShowMicrosoftRewards",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "WebWidgetAllowed",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "DiagnosticData",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "EdgeAssetDeliveryServiceEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "EdgeCollectionsEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "CryptoWalletEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        "Name": "WalletDonationEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/EdgeDebloat"
  },
  "WPFTweaksConsumerFeatures": {
    "Content": "Disable ConsumerFeatures",
    "Description": "Windows 10 will not automatically install any games, third-party apps, or application links from the Windows Store for the signed-in user. Some default Apps will be inaccessible (eg. Phone Link)",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a003_",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent",
        "OriginalValue": "<RemoveEntry>",
        "Name": "DisableWindowsConsumerFeatures",
        "Value": "1",
        "Type": "DWord"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/ConsumerFeatures"
  },
  "WPFTweaksTele": {
    "Content": "Disable Telemetry",
    "Description": "Disables Microsoft Telemetry. Note: This will lock many Edge Browser settings. Microsoft spies heavily on you when using the Edge browser.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a003_",
    "ScheduledTask": [
      {
        "Name": "Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Autochk\\Proxy",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Feedback\\Siuf\\DmClient",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Feedback\\Siuf\\DmClientOnScenarioDownload",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Windows Error Reporting\\QueueReporting",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Application Experience\\MareBackup",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Application Experience\\StartupAppTask",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Application Experience\\PcaPatchDbTask",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Maps\\MapsUpdateTask",
        "State": "Disabled",
        "OriginalState": "Enabled"
      }
    ],
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection",
        "Type": "DWord",
        "Value": "0",
        "Name": "AllowTelemetry",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
        "OriginalValue": "<RemoveEntry>",
        "Name": "AllowTelemetry",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "ContentDeliveryAllowed",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "OemPreInstalledAppsEnabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "PreInstalledAppsEnabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "PreInstalledAppsEverEnabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "SilentInstalledAppsEnabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "SubscribedContent-338387Enabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "SubscribedContent-338388Enabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "SubscribedContent-338389Enabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "SubscribedContent-353698Enabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "SystemPaneSuggestionsEnabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Siuf\\Rules",
        "OriginalValue": "0",
        "Name": "NumberOfSIUFInPeriod",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
        "OriginalValue": "<RemoveEntry>",
        "Name": "DoNotShowFeedbackNotifications",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent",
        "OriginalValue": "<RemoveEntry>",
        "Name": "DisableTailoredExperiencesWithDiagnosticData",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo",
        "OriginalValue": "<RemoveEntry>",
        "Name": "DisabledByGroupPolicy",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting",
        "OriginalValue": "0",
        "Name": "Disabled",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config",
        "OriginalValue": "1",
        "Name": "DODownloadMode",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance",
        "OriginalValue": "1",
        "Name": "fAllowToGetHelp",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\OperationStatusManager",
        "OriginalValue": "0",
        "Name": "EnthusiastMode",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "ShowTaskViewButton",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\People",
        "OriginalValue": "1",
        "Name": "PeopleBand",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "LaunchTo",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\FileSystem",
        "OriginalValue": "0",
        "Name": "LongPathsEnabled",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "_Comment": "Driver searching is a function that should be left in",
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching",
        "OriginalValue": "1",
        "Name": "SearchOrderConfig",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile",
        "OriginalValue": "1",
        "Name": "SystemResponsiveness",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile",
        "OriginalValue": "1",
        "Name": "NetworkThrottlingIndex",
        "Value": "4294967295",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Control Panel\\Desktop",
        "OriginalValue": "1",
        "Name": "MenuShowDelay",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Control Panel\\Desktop",
        "OriginalValue": "1",
        "Name": "AutoEndTasks",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
        "OriginalValue": "0",
        "Name": "ClearPageFileAtShutdown",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SYSTEM\\ControlSet001\\Services\\Ndu",
        "OriginalValue": "1",
        "Name": "Start",
        "Value": "2",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Control Panel\\Mouse",
        "OriginalValue": "400",
        "Name": "MouseHoverTime",
        "Value": "400",
        "Type": "String"
      },
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        "OriginalValue": "20",
        "Name": "IRPStackSize",
        "Value": "30",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Feeds",
        "OriginalValue": "<RemoveEntry>",
        "Name": "EnableFeeds",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Feeds",
        "OriginalValue": "1",
        "Name": "ShellFeedsTaskbarViewMode",
        "Value": "2",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        "OriginalValue": "<RemoveEntry>",
        "Name": "HideSCAMeetNow",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\UserProfileEngagement",
        "OriginalValue": "1",
        "Name": "ScoobeSystemSettingEnabled",
        "Value": "0",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "\r\n      bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null\r\n        If ((get-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" -Name CurrentBuild).CurrentBuild -lt 22557) {\r\n            $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru\r\n            Do {\r\n                Start-Sleep -Milliseconds 100\r\n                $preferences = Get-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\TaskManager\" -Name \"Preferences\" -ErrorAction SilentlyContinue\r\n            } Until ($preferences)\r\n            Stop-Process $taskmgr\r\n            $preferences.Preferences[28] = 0\r\n            Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\TaskManager\" -Name \"Preferences\" -Type Binary -Value $preferences.Preferences\r\n        }\r\n        Remove-Item -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}\" -Recurse -ErrorAction SilentlyContinue\r\n\r\n        # Fix Managed by your organization in Edge if regustry path exists then remove it\r\n\r\n        If (Test-Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge\") {\r\n            Remove-Item -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge\" -Recurse -ErrorAction SilentlyContinue\r\n        }\r\n\r\n        # Group svchost.exe processes\r\n        $ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb\r\n        Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\" -Name \"SvcHostSplitThresholdInKB\" -Type DWord -Value $ram -Force\r\n\r\n        $autoLoggerDir = \"$env:PROGRAMDATA\\Microsoft\\Diagnosis\\ETLLogs\\AutoLogger\"\r\n        If (Test-Path \"$autoLoggerDir\\AutoLogger-Diagtrack-Listener.etl\") {\r\n            Remove-Item \"$autoLoggerDir\\AutoLogger-Diagtrack-Listener.etl\"\r\n        }\r\n        icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null\r\n\r\n        # Disable Defender Auto Sample Submission\r\n        Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue | Out-Null\r\n        "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/Tele"
  },
  "WPFTweaksWifi": {
    "Content": "Disable Wifi-Sense",
    "Description": "Wifi Sense is a spying service that phones home all nearby scanned wifi networks and your current geo location.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a005_",
    "registry": [
      {
        "Path": "HKLM:\\Software\\Microsoft\\PolicyManager\\default\\WiFi\\AllowWiFiHotSpotReporting",
        "Name": "Value",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      },
      {
        "Path": "HKLM:\\Software\\Microsoft\\PolicyManager\\default\\WiFi\\AllowAutoConnectToWiFiSenseHotspots",
        "Name": "Value",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/Wifi"
  },
  "WPFTweaksUTC": {
    "Content": "Set Time to UTC (Dual Boot)",
    "Description": "Essential for computers that are dual booting. Fixes the time sync with Linux Systems.",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a027_",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
        "Name": "RealTimeIsUniversal",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "0"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/UTC"
  },
  "WPFTweaksRemoveHomeGallery": {
    "Content": "Remove Home and Gallery from explorer",
    "Description": "Removes the Home and Gallery from explorer and sets This PC as default",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a029_",
    "InvokeScript": [
      "\r\n      REG DELETE \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}\" /f\r\n      REG DELETE \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}\" /f\r\n      REG ADD \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /f /v \"LaunchTo\" /t REG_DWORD /d \"1\"\r\n      "
    ],
    "UndoScript": [
      "\r\n      REG ADD \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}\" /f /ve /t REG_SZ /d \"{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}\"\r\n      REG ADD \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}\" /f /ve /t REG_SZ /d \"CLSID_MSGraphHomeFolder\"\r\n      REG DELETE \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /f /v \"LaunchTo\"\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/RemoveHomeGallery"
  },
  "WPFTweaksDisplay": {
    "Content": "Set Display for Performance",
    "Description": "Sets the system preferences to performance. You can do this manually with sysdm.cpl as well.",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a027_",
    "registry": [
      {
        "Path": "HKCU:\\Control Panel\\Desktop",
        "OriginalValue": "1",
        "Name": "DragFullWindows",
        "Value": "0",
        "Type": "String"
      },
      {
        "Path": "HKCU:\\Control Panel\\Desktop",
        "OriginalValue": "1",
        "Name": "MenuShowDelay",
        "Value": "200",
        "Type": "String"
      },
      {
        "Path": "HKCU:\\Control Panel\\Desktop\\WindowMetrics",
        "OriginalValue": "1",
        "Name": "MinAnimate",
        "Value": "0",
        "Type": "String"
      },
      {
        "Path": "HKCU:\\Control Panel\\Keyboard",
        "OriginalValue": "1",
        "Name": "KeyboardDelay",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "ListviewAlphaSelect",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "ListviewShadow",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "TaskbarAnimations",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects",
        "OriginalValue": "1",
        "Name": "VisualFXSetting",
        "Value": "3",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\DWM",
        "OriginalValue": "1",
        "Name": "EnableAeroPeek",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "TaskbarMn",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "TaskbarDa",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "ShowTaskViewButton",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Search",
        "OriginalValue": "1",
        "Name": "SearchboxTaskbarMode",
        "Value": "0",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "Set-ItemProperty -Path \"HKCU:\\Control Panel\\Desktop\" -Name \"UserPreferencesMask\" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))"
    ],
    "UndoScript": [
      "Remove-ItemProperty -Path \"HKCU:\\Control Panel\\Desktop\" -Name \"UserPreferencesMask\""
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/Display"
  },
  "WPFTweaksDeBloat": {
    "Content": "Remove ALL MS Store Apps - NOT RECOMMENDED",
    "Description": "USE WITH CAUTION!!!!! This will remove ALL Microsoft store apps other than the essentials to make winget work. Games installed by MS Store ARE INCLUDED!",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a028_",
    "appx": [
      "Microsoft.Microsoft3DViewer",
      "Microsoft.AppConnector",
      "Microsoft.BingFinance",
      "Microsoft.BingNews",
      "Microsoft.BingSports",
      "Microsoft.BingTranslator",
      "Microsoft.BingWeather",
      "Microsoft.BingFoodAndDrink",
      "Microsoft.BingHealthAndFitness",
      "Microsoft.BingTravel",
      "Microsoft.MinecraftUWP",
      "Microsoft.GamingServices",
      "Microsoft.GetHelp",
      "Microsoft.Getstarted",
      "Microsoft.Messaging",
      "Microsoft.Microsoft3DViewer",
      "Microsoft.MicrosoftSolitaireCollection",
      "Microsoft.NetworkSpeedTest",
      "Microsoft.News",
      "Microsoft.Office.Lens",
      "Microsoft.Office.Sway",
      "Microsoft.Office.OneNote",
      "Microsoft.OneConnect",
      "Microsoft.People",
      "Microsoft.Print3D",
      "Microsoft.SkypeApp",
      "Microsoft.Wallet",
      "Microsoft.Whiteboard",
      "Microsoft.WindowsAlarms",
      "microsoft.windowscommunicationsapps",
      "Microsoft.WindowsFeedbackHub",
      "Microsoft.WindowsMaps",
      "Microsoft.WindowsSoundRecorder",
      "Microsoft.ConnectivityStore",
      "Microsoft.ScreenSketch",
      "Microsoft.MixedReality.Portal",
      "Microsoft.ZuneMusic",
      "Microsoft.ZuneVideo",
      "Microsoft.Getstarted",
      "Microsoft.MicrosoftOfficeHub",
      "*EclipseManager*",
      "*ActiproSoftwareLLC*",
      "*AdobeSystemsIncorporated.AdobePhotoshopExpress*",
      "*Duolingo-LearnLanguagesforFree*",
      "*PandoraMediaInc*",
      "*CandyCrush*",
      "*BubbleWitch3Saga*",
      "*Wunderlist*",
      "*Flipboard*",
      "*Twitter*",
      "*Facebook*",
      "*Royal Revolt*",
      "*Sway*",
      "*Speed Test*",
      "*Dolby*",
      "*Viber*",
      "*ACGMediaPlayer*",
      "*Netflix*",
      "*OneCalendar*",
      "*LinkedInforWindows*",
      "*HiddenCityMysteryofShadows*",
      "*Hulu*",
      "*HiddenCity*",
      "*AdobePhotoshopExpress*",
      "*HotspotShieldFreeVPN*",
      "*Microsoft.Advertising.Xaml*"
    ],
    "InvokeScript": [
      "\r\n        $TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams')\r\n        $TeamsUpdateExePath = [System.IO.Path]::Combine($TeamsPath, 'Update.exe')\r\n\r\n        Write-Host \"Stopping Teams process...\"\r\n        Stop-Process -Name \"*teams*\" -Force -ErrorAction SilentlyContinue\r\n\r\n        Write-Host \"Uninstalling Teams from AppData\\Microsoft\\Teams\"\r\n        if ([System.IO.File]::Exists($TeamsUpdateExePath)) {\r\n            # Uninstall app\r\n            $proc = Start-Process $TeamsUpdateExePath \"-uninstall -s\" -PassThru\r\n            $proc.WaitForExit()\r\n        }\r\n\r\n        Write-Host \"Removing Teams AppxPackage...\"\r\n        Get-AppxPackage \"*Teams*\" | Remove-AppxPackage -ErrorAction SilentlyContinue\r\n        Get-AppxPackage \"*Teams*\" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue\r\n\r\n        Write-Host \"Deleting Teams directory\"\r\n        if ([System.IO.Directory]::Exists($TeamsPath)) {\r\n            Remove-Item $TeamsPath -Force -Recurse -ErrorAction SilentlyContinue\r\n        }\r\n\r\n        Write-Host \"Deleting Teams uninstall registry key\"\r\n        # Uninstall from Uninstall registry key UninstallString\r\n        $us = (Get-ChildItem -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall, HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like '*Teams*'}).UninstallString\r\n        if ($us.Length -gt 0) {\r\n            $us = ($us.Replace('/I', '/uninstall ') + ' /quiet').Replace('  ', ' ')\r\n            $FilePath = ($us.Substring(0, $us.IndexOf('.exe') + 4).Trim())\r\n            $ProcessArgs = ($us.Substring($us.IndexOf('.exe') + 5).Trim().replace('  ', ' '))\r\n            $proc = Start-Process -FilePath $FilePath -Args $ProcessArgs -PassThru\r\n            $proc.WaitForExit()\r\n        }\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/DeBloat"
  },
  "WPFTweaksRestorePoint": {
    "Content": "Create Restore Point",
    "Description": "Creates a restore point at runtime in case a revert is needed from WinUtil modifications",
    "category": "Essential Tweaks",
    "panel": "1",
    "Checked": "False",
    "Order": "a001_",
    "InvokeScript": [
      "\r\n        # Check if System Restore is enabled for the main drive\r\n        try {\r\n            # Try getting restore points to check if System Restore is enabled\r\n            Enable-ComputerRestore -Drive \"$env:SystemDrive\"\r\n        } catch {\r\n            Write-Host \"An error occurred while enabling System Restore: $_\"\r\n        }\r\n\r\n        # Check if the SystemRestorePointCreationFrequency value exists\r\n        $exists = Get-ItemProperty -path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\" -Name \"SystemRestorePointCreationFrequency\" -ErrorAction SilentlyContinue\r\n        if($null -eq $exists) {\r\n            write-host 'Changing system to allow multiple restore points per day'\r\n            Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\" -Name \"SystemRestorePointCreationFrequency\" -Value \"0\" -Type DWord -Force -ErrorAction Stop | Out-Null\r\n        }\r\n\r\n        # Attempt to load the required module for Get-ComputerRestorePoint\r\n        try {\r\n            Import-Module Microsoft.PowerShell.Management -ErrorAction Stop\r\n        } catch {\r\n            Write-Host \"Failed to load the Microsoft.PowerShell.Management module: $_\"\r\n            return\r\n        }\r\n\r\n        # Get all the restore points for the current day\r\n        try {\r\n            $existingRestorePoints = Get-ComputerRestorePoint | Where-Object { $_.CreationTime.Date -eq (Get-Date).Date }\r\n        } catch {\r\n            Write-Host \"Failed to retrieve restore points: $_\"\r\n            return\r\n        }\r\n\r\n        # Check if there is already a restore point created today\r\n        if ($existingRestorePoints.Count -eq 0) {\r\n            $description = \"System Restore Point created by WinUtil\"\r\n\r\n            Checkpoint-Computer -Description $description -RestorePointType \"MODIFY_SETTINGS\"\r\n            Write-Host -ForegroundColor Green \"System Restore Point Created Successfully\"\r\n        }\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/RestorePoint"
  },
  "WPFTweaksEndTaskOnTaskbar": {
    "Content": "Enable End Task With Right Click",
    "Description": "Enables option to end task when right clicking a program in the taskbar",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a006_",
    "InvokeScript": [
      "$path = \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\TaskbarDeveloperSettings\"\r\n      $name = \"TaskbarEndTask\"\r\n      $value = 1\r\n\r\n      # Ensure the registry key exists\r\n      if (-not (Test-Path $path)) {\r\n        New-Item -Path $path -Force | Out-Null\r\n      }\r\n\r\n      # Set the property, creating it if it doesn't exist\r\n      New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value $value -Force | Out-Null"
    ],
    "UndoScript": [
      "$path = \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\TaskbarDeveloperSettings\"\r\n      $name = \"TaskbarEndTask\"\r\n      $value = 0\r\n\r\n      # Ensure the registry key exists\r\n      if (-not (Test-Path $path)) {\r\n        New-Item -Path $path -Force | Out-Null\r\n      }\r\n\r\n      # Set the property, creating it if it doesn't exist\r\n      New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value $value -Force | Out-Null"
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/EndTaskOnTaskbar"
  },
  "WPFTweaksPowershell7": {
    "Content": "Change Windows Terminal default: PowerShell 5 -> PowerShell 7",
    "Description": "This will edit the config file of the Windows Terminal replacing PowerShell 5 with PowerShell 7 and installing PS7 if necessary",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a009_",
    "InvokeScript": [
      "Invoke-WPFTweakPS7 -action \"PS7\""
    ],
    "UndoScript": [
      "Invoke-WPFTweakPS7 -action \"PS5\""
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/Powershell7"
  },
  "WPFTweaksPowershell7Tele": {
    "Content": "Disable Powershell 7 Telemetry",
    "Description": "This will create an Environment Variable called 'POWERSHELL_TELEMETRY_OPTOUT' with a value of '1' which will tell Powershell 7 to not send Telemetry Data.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a009_",
    "InvokeScript": [
      "[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine')"
    ],
    "UndoScript": [
      "[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '', 'Machine')"
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/Powershell7Tele"
  },
  "WPFTweaksStorage": {
    "Content": "Disable Storage Sense",
    "Description": "Storage Sense deletes temp files automatically.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a005_",
    "InvokeScript": [
      "Set-ItemProperty -Path \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\StoragePolicy\" -Name \"01\" -Value 0 -Type Dword -Force"
    ],
    "UndoScript": [
      "Set-ItemProperty -Path \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\StoragePolicy\" -Name \"01\" -Value 1 -Type Dword -Force"
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/Storage"
  },
  "WPFTweaksRemoveEdge": {
    "Content": "Remove Microsoft Edge",
    "Description": "Removes MS Edge when it gets reinstalled by updates. Credit: Psyirius",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a029_",
    "InvokeScript": [
      "Uninstall-WinUtilEdgeBrowser -action \"Uninstall\""
    ],
    "UndoScript": [
      "Uninstall-WinUtilEdgeBrowser -action \"Install\""
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/RemoveEdge"
  },
  "WPFTweaksRemoveCopilot": {
    "Content": "Disable Microsoft Copilot",
    "Description": "Disables MS Copilot AI built into Windows since 23H2.",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a025_",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsCopilot",
        "Name": "TurnOffWindowsCopilot",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKCU:\\Software\\Policies\\Microsoft\\Windows\\WindowsCopilot",
        "Name": "TurnOffWindowsCopilot",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "Name": "ShowCopilotButton",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      }
    ],
    "InvokeScript": [
      "\r\n      Write-Host \"Remove Copilot\"\r\n      dism /online /remove-package /package-name:Microsoft.Windows.Copilot\r\n      "
    ],
    "UndoScript": [
      "\r\n      Write-Host \"Install Copilot\"\r\n      dism /online /add-package /package-name:Microsoft.Windows.Copilot\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/RemoveCopilot"
  },
  "WPFTweaksRecallOff": {
    "Content": "Disable Recall",
    "Description": "Turn Recall off",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a011_",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI",
        "Name": "DisableAIDataAnalysis",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "<RemoveEntry>"
      }
    ],
    "InvokeScript": [
      "\r\n      Write-Host \"Disable Recall\"\r\n      DISM /Online /Disable-Feature /FeatureName:Recall\r\n      "
    ],
    "UndoScript": [
      "\r\n      Write-Host \"Enable Recall\"\r\n      DISM /Online /Enable-Feature /FeatureName:Recall\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/DisableRecall"
  },
  "WPFTweaksDisableLMS1": {
    "Content": "Disable Intel MM (vPro LMS)",
    "Description": "Intel LMS service is always listening on all ports and could be a huge security risk. There is no need to run LMS on home machines and even in the Enterprise there are better solutions.",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a026_",
    "InvokeScript": [
      "\r\n        Write-Host \"Kill LMS\"\r\n        $serviceName = \"LMS\"\r\n        Write-Host \"Stopping and disabling service: $serviceName\"\r\n        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue;\r\n        Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue;\r\n\r\n        Write-Host \"Removing service: $serviceName\";\r\n        sc.exe delete $serviceName;\r\n\r\n        Write-Host \"Removing LMS driver packages\";\r\n        $lmsDriverPackages = Get-ChildItem -Path \"C:\\Windows\\System32\\DriverStore\\FileRepository\" -Recurse -Filter \"lms.inf*\";\r\n        foreach ($package in $lmsDriverPackages) {\r\n            Write-Host \"Removing driver package: $($package.Name)\";\r\n            pnputil /delete-driver $($package.Name) /uninstall /force;\r\n        }\r\n        if ($lmsDriverPackages.Count -eq 0) {\r\n            Write-Host \"No LMS driver packages found in the driver store.\";\r\n        } else {\r\n            Write-Host \"All found LMS driver packages have been removed.\";\r\n        }\r\n\r\n        Write-Host \"Searching and deleting LMS executable files\";\r\n        $programFilesDirs = @(\"C:\\Program Files\", \"C:\\Program Files (x86)\");\r\n        $lmsFiles = @();\r\n        foreach ($dir in $programFilesDirs) {\r\n            $lmsFiles += Get-ChildItem -Path $dir -Recurse -Filter \"LMS.exe\" -ErrorAction SilentlyContinue;\r\n        }\r\n        foreach ($file in $lmsFiles) {\r\n            Write-Host \"Taking ownership of file: $($file.FullName)\";\r\n            & icacls $($file.FullName) /grant Administrators:F /T /C /Q;\r\n            & takeown /F $($file.FullName) /A /R /D Y;\r\n            Write-Host \"Deleting file: $($file.FullName)\";\r\n            Remove-Item $($file.FullName) -Force -ErrorAction SilentlyContinue;\r\n        }\r\n        if ($lmsFiles.Count -eq 0) {\r\n            Write-Host \"No LMS.exe files found in Program Files directories.\";\r\n        } else {\r\n            Write-Host \"All found LMS.exe files have been deleted.\";\r\n        }\r\n        Write-Host 'Intel LMS vPro service has been disabled, removed, and blocked.';\r\n       "
    ],
    "UndoScript": [
      "\r\n      Write-Host \"LMS vPro needs to be redownloaded from intel.com\"\r\n\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/DisableLMS1"
  },
  "WPFTweaksRemoveOnedrive": {
    "Content": "Remove OneDrive",
    "Description": "Moves OneDrive files to Default Home Folders and Uninstalls it.",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a030_",
    "InvokeScript": [
      "\r\n      $OneDrivePath = $($env:OneDrive)\r\n      Write-Host \"Removing OneDrive\"\r\n\r\n      # Check both traditional and Microsoft Store installations\r\n      $regPath = \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OneDriveSetup.exe\"\r\n      $msStorePath = \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Appx\\AppxAllUserStore\\Applications\\*OneDrive*\"\r\n\r\n      if (Test-Path $regPath) {\r\n          $OneDriveUninstallString = Get-ItemPropertyValue \"$regPath\" -Name \"UninstallString\"\r\n          $OneDriveExe, $OneDriveArgs = $OneDriveUninstallString.Split(\" \")\r\n          Start-Process -FilePath $OneDriveExe -ArgumentList \"$OneDriveArgs /silent\" -NoNewWindow -Wait\r\n      } elseif (Test-Path $msStorePath) {\r\n          Write-Host \"OneDrive appears to be installed via Microsoft Store\" -ForegroundColor Yellow\r\n          # Attempt to uninstall via winget\r\n          Start-Process -FilePath winget -ArgumentList \"uninstall -e --purge --accept-source-agreements Microsoft.OneDrive\" -NoNewWindow -Wait\r\n      } else {\r\n          Write-Host \"OneDrive doesn't seem to be installed\" -ForegroundColor Red\r\n          Write-Host \"Running cleanup if OneDrive path exists\" -ForegroundColor Red\r\n      }\r\n\r\n      # Check if OneDrive got Uninstalled (both paths)\r\n      if (Test-Path $OneDrivePath) {\r\n        Write-Host \"Copy downloaded Files from the OneDrive Folder to Root UserProfile\"\r\n        Start-Process -FilePath powershell -ArgumentList \"robocopy '$($OneDrivePath)' '$($env:USERPROFILE.TrimEnd())\\' /mov /e /xj\" -NoNewWindow -Wait\r\n\r\n        Write-Host \"Removing OneDrive leftovers\"\r\n        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue \"$env:localappdata\\Microsoft\\OneDrive\"\r\n        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue \"$env:localappdata\\OneDrive\"\r\n        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue \"$env:programdata\\Microsoft OneDrive\"\r\n        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue \"$env:systemdrive\\OneDriveTemp\"\r\n        reg delete \"HKEY_CURRENT_USER\\Software\\Microsoft\\OneDrive\" -f\r\n        # check if directory is empty before removing:\r\n        If ((Get-ChildItem \"$OneDrivePath\" -Recurse | Measure-Object).Count -eq 0) {\r\n            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue \"$OneDrivePath\"\r\n        }\r\n\r\n        Write-Host \"Remove Onedrive from explorer sidebar\"\r\n        Set-ItemProperty -Path \"HKCR:\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\" -Name \"System.IsPinnedToNameSpaceTree\" -Value 0\r\n        Set-ItemProperty -Path \"HKCR:\\Wow6432Node\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\" -Name \"System.IsPinnedToNameSpaceTree\" -Value 0\r\n\r\n        Write-Host \"Removing run hook for new users\"\r\n        reg load \"hku\\Default\" \"C:\\Users\\Default\\NTUSER.DAT\"\r\n        reg delete \"HKEY_USERS\\Default\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"OneDriveSetup\" /f\r\n        reg unload \"hku\\Default\"\r\n\r\n        Write-Host \"Removing autostart key\"\r\n        reg delete \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"OneDrive\" /f\r\n\r\n        Write-Host \"Removing startmenu entry\"\r\n        Remove-Item -Force -ErrorAction SilentlyContinue \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\OneDrive.lnk\"\r\n\r\n        Write-Host \"Removing scheduled task\"\r\n        Get-ScheduledTask -TaskPath '\\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false\r\n\r\n        # Add Shell folders restoring default locations\r\n        Write-Host \"Shell Fixing\"\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"AppData\" -Value \"$env:userprofile\\AppData\\Roaming\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Cache\" -Value \"$env:userprofile\\AppData\\Local\\Microsoft\\Windows\\INetCache\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Cookies\" -Value \"$env:userprofile\\AppData\\Local\\Microsoft\\Windows\\INetCookies\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Favorites\" -Value \"$env:userprofile\\Favorites\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"History\" -Value \"$env:userprofile\\AppData\\Local\\Microsoft\\Windows\\History\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Local AppData\" -Value \"$env:userprofile\\AppData\\Local\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"My Music\" -Value \"$env:userprofile\\Music\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"My Video\" -Value \"$env:userprofile\\Videos\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"NetHood\" -Value \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\Network Shortcuts\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"PrintHood\" -Value \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Programs\" -Value \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Recent\" -Value \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\Recent\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"SendTo\" -Value \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\SendTo\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Start Menu\" -Value \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Startup\" -Value \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Templates\" -Value \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\Templates\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"{374DE290-123F-4565-9164-39C4925E467B}\" -Value \"$env:userprofile\\Downloads\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Desktop\" -Value \"$env:userprofile\\Desktop\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"My Pictures\" -Value \"$env:userprofile\\Pictures\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Personal\" -Value \"$env:userprofile\\Documents\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"{F42EE2D3-909F-4907-8871-4C22FC0BF756}\" -Value \"$env:userprofile\\Documents\" -Type ExpandString\r\n        Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"{0DDD015D-B06C-45D5-8C4C-F59713854639}\" -Value \"$env:userprofile\\Pictures\" -Type ExpandString\r\n        Write-Host \"Restarting explorer\"\r\n        taskkill.exe /F /IM \"explorer.exe\"\r\n        Start-Process \"explorer.exe\"\r\n\r\n        Write-Host \"Waiting for explorer to complete loading\"\r\n        Write-Host \"Please Note - The OneDrive folder at $OneDrivePath may still have items in it. You must manually delete it, but all the files should already be copied to the base user folder.\"\r\n        Write-Host \"If there are Files missing afterwards, please Login to Onedrive.com and Download them manually\" -ForegroundColor Yellow\r\n        Start-Sleep 5\r\n      } else {\r\n        Write-Host \"Nothing to Cleanup with OneDrive\" -ForegroundColor Red\r\n      }\r\n      "
    ],
    "UndoScript": [
      "\r\n      Write-Host \"Install OneDrive\"\r\n      Start-Process -FilePath winget -ArgumentList \"install -e --accept-source-agreements --accept-package-agreements --silent Microsoft.OneDrive \" -NoNewWindow -Wait\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/RemoveOnedrive"
  },
  "WPFTweaksRazerBlock": {
    "Content": "Block Razer Software Installs",
    "Description": "Blocks ALL Razer Software installations. The hardware works fine without any software.",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a031_",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching",
        "Name": "SearchOrderConfig",
        "Value": "0",
        "OriginalValue": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Device Installer",
        "Name": "DisableCoInstallers",
        "Value": "1",
        "OriginalValue": "0",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "\r\n          $RazerPath = \"C:\\Windows\\Installer\\Razer\"\r\n          Remove-Item $RazerPath -Recurse -Force\r\n          New-Item -Path \"C:\\Windows\\Installer\\\" -Name \"Razer\" -ItemType \"directory\"\r\n          $Acl = Get-Acl $RazerPath\r\n          $Ar = New-Object System.Security.AccessControl.FileSystemAccessRule(\"NT AUTHORITY\\SYSTEM\",\"Write\",\"ContainerInherit,ObjectInherit\",\"None\",\"Deny\")\r\n          $Acl.SetAccessRule($Ar)\r\n          Set-Acl $RazerPath $Acl\r\n      "
    ],
    "UndoScript": [
      "\r\n          $RazerPath = \"C:\\Windows\\Installer\\Razer\"\r\n          Remove-Item $RazerPath -Recurse -Force\r\n          New-Item -Path \"C:\\Windows\\Installer\\\" -Name \"Razer\" -ItemType \"directory\"\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/RazerBlock"
  },
  "WPFTweaksDisableNotifications": {
    "Content": "Disable Notification Tray/Calendar",
    "Description": "Disables all Notifications INCLUDING Calendar",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a026_",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Policies\\Microsoft\\Windows\\Explorer",
        "Name": "DisableNotificationCenter",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "<RemoveEntry>"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications",
        "Name": "ToastEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/DisableNotifications"
  },
  "WPFTweaksDebloatAdobe": {
    "Content": "Adobe Debloat",
    "Description": "Manages Adobe Services, Adobe Desktop Service, and Acrobat Updates",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a021_",
    "InvokeScript": [
      "\r\n      function CCStopper {\r\n        $path = \"C:\\Program Files (x86)\\Common Files\\Adobe\\Adobe Desktop Common\\ADS\\Adobe Desktop Service.exe\"\r\n\r\n        # Test if the path exists before proceeding\r\n        if (Test-Path $path) {\r\n            Takeown /f $path\r\n            $acl = Get-Acl $path\r\n            $acl.SetOwner([System.Security.Principal.NTAccount]\"Administrators\")\r\n            $acl | Set-Acl $path\r\n\r\n            Rename-Item -Path $path -NewName \"Adobe Desktop Service.exe.old\" -Force\r\n        } else {\r\n            Write-Host \"Adobe Desktop Service is not in the default location.\"\r\n        }\r\n      }\r\n\r\n\r\n      function AcrobatUpdates {\r\n        # Editing Acrobat Updates. The last folder before the key is dynamic, therefore using a script.\r\n        # Possible Values for the edited key:\r\n        # 0 = Do not download or install updates automatically\r\n        # 2 = Automatically download updates but let the user choose when to install them\r\n        # 3 = Automatically download and install updates (default value)\r\n        # 4 = Notify the user when an update is available but don't download or install it automatically\r\n        #   = It notifies the user using Windows Notifications. It runs on startup without having to have a Service/Acrobat/Reader running, therefore 0 is the next best thing.\r\n\r\n        $rootPath = \"HKLM:\\SOFTWARE\\WOW6432Node\\Adobe\\Adobe ARM\\Legacy\\Acrobat\"\r\n\r\n        # Get all subkeys under the specified root path\r\n        $subKeys = Get-ChildItem -Path $rootPath | Where-Object { $_.PSChildName -like \"{*}\" }\r\n\r\n        # Loop through each subkey\r\n        foreach ($subKey in $subKeys) {\r\n            # Get the full registry path\r\n            $fullPath = Join-Path -Path $rootPath -ChildPath $subKey.PSChildName\r\n            try {\r\n                Set-ItemProperty -Path $fullPath -Name Mode -Value 0\r\n                Write-Host \"Acrobat Updates have been disabled.\"\r\n            } catch {\r\n                Write-Host \"Registry Key for changing Acrobat Updates does not exist in $fullPath\"\r\n            }\r\n        }\r\n      }\r\n\r\n      CCStopper\r\n      AcrobatUpdates\r\n      "
    ],
    "UndoScript": [
      "\r\n      function RestoreCCService {\r\n        $originalPath = \"C:\\Program Files (x86)\\Common Files\\Adobe\\Adobe Desktop Common\\ADS\\Adobe Desktop Service.exe.old\"\r\n        $newPath = \"C:\\Program Files (x86)\\Common Files\\Adobe\\Adobe Desktop Common\\ADS\\Adobe Desktop Service.exe\"\r\n\r\n        if (Test-Path -Path $originalPath) {\r\n            Rename-Item -Path $originalPath -NewName \"Adobe Desktop Service.exe\" -Force\r\n            Write-Host \"Adobe Desktop Service has been restored.\"\r\n        } else {\r\n            Write-Host \"Backup file does not exist. No changes were made.\"\r\n        }\r\n      }\r\n\r\n      function AcrobatUpdates {\r\n        # Default Value:\r\n        # 3 = Automatically download and install updates\r\n\r\n        $rootPath = \"HKLM:\\SOFTWARE\\WOW6432Node\\Adobe\\Adobe ARM\\Legacy\\Acrobat\"\r\n\r\n        # Get all subkeys under the specified root path\r\n        $subKeys = Get-ChildItem -Path $rootPath | Where-Object { $_.PSChildName -like \"{*}\" }\r\n\r\n        # Loop through each subkey\r\n        foreach ($subKey in $subKeys) {\r\n            # Get the full registry path\r\n            $fullPath = Join-Path -Path $rootPath -ChildPath $subKey.PSChildName\r\n            try {\r\n                Set-ItemProperty -Path $fullPath -Name Mode -Value 3\r\n            } catch {\r\n                Write-Host \"Registry Key for changing Acrobat Updates does not exist in $fullPath\"\r\n            }\r\n        }\r\n      }\r\n\r\n      RestoreCCService\r\n      AcrobatUpdates\r\n      "
    ],
    "service": [
      {
        "Name": "AGSService",
        "StartupType": "Disabled",
        "OriginalType": "Automatic"
      },
      {
        "Name": "AGMService",
        "StartupType": "Disabled",
        "OriginalType": "Automatic"
      },
      {
        "Name": "AdobeUpdateService",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Adobe Acrobat Update",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Adobe Genuine Monitor Service",
        "StartupType": "Disabled",
        "OriginalType": "Automatic"
      },
      {
        "Name": "AdobeARMservice",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Adobe Licensing Console",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CCXProcess",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "AdobeIPCBroker",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CoreSync",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/DebloatAdobe"
  },
  "WPFTweaksBlockAdobeNet": {
    "Content": "Adobe Network Block",
    "Description": "Reduce user interruptions by selectively blocking connections to Adobe's activation and telemetry servers. Credit: Ruddernation-Designs",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a021_",
    "InvokeScript": [
      "\r\n      # Define the URL of the remote HOSTS file and the local paths\r\n      $remoteHostsUrl = \"https://raw.githubusercontent.com/Ruddernation-Designs/Adobe-URL-Block-List/master/hosts\"\r\n      $localHostsPath = \"C:\\Windows\\System32\\drivers\\etc\\hosts\"\r\n      $tempHostsPath = \"C:\\Windows\\System32\\drivers\\etc\\temp_hosts\"\r\n\r\n      # Download the remote HOSTS file to a temporary location\r\n      try {\r\n          Invoke-WebRequest -Uri $remoteHostsUrl -OutFile $tempHostsPath\r\n          Write-Output \"Downloaded the remote HOSTS file to a temporary location.\"\r\n      } catch {\r\n          Write-Error \"Failed to download the HOSTS file. Error: $_\"\r\n      }\r\n\r\n      # Check if the AdobeNetBlock has already been started\r\n      try {\r\n          $localHostsContent = Get-Content $localHostsPath -ErrorAction Stop\r\n\r\n          # Check if AdobeNetBlock markers exist\r\n          $blockStartExists = $localHostsContent -like \"*#AdobeNetBlock-start*\"\r\n          if ($blockStartExists) {\r\n              Write-Output \"AdobeNetBlock-start already exists. Skipping addition of new block.\"\r\n          } else {\r\n              # Load the new block from the downloaded file\r\n              $newBlockContent = Get-Content $tempHostsPath -ErrorAction Stop\r\n              $newBlockContent = $newBlockContent | Where-Object { $_ -notmatch \"^\\s*#\" -and $_ -ne \"\" } # Exclude empty lines and comments\r\n              $newBlockHeader = \"#AdobeNetBlock-start\"\r\n              $newBlockFooter = \"#AdobeNetBlock-end\"\r\n\r\n              # Combine the contents, ensuring new block is properly formatted\r\n              $combinedContent = $localHostsContent + $newBlockHeader, $newBlockContent, $newBlockFooter | Out-String\r\n\r\n              # Write the combined content back to the original HOSTS file\r\n              $combinedContent | Set-Content $localHostsPath -Encoding ASCII\r\n              Write-Output \"Successfully added the AdobeNetBlock.\"\r\n          }\r\n      } catch {\r\n          Write-Error \"Error during processing: $_\"\r\n      }\r\n\r\n      # Clean up temporary file\r\n      Remove-Item $tempHostsPath -ErrorAction Ignore\r\n\r\n      # Flush the DNS resolver cache\r\n      try {\r\n          Invoke-Expression \"ipconfig /flushdns\"\r\n          Write-Output \"DNS cache flushed successfully.\"\r\n      } catch {\r\n          Write-Error \"Failed to flush DNS cache. Error: $_\"\r\n      }\r\n      "
    ],
    "UndoScript": [
      "\r\n      # Define the local path of the HOSTS file\r\n      $localHostsPath = \"C:\\Windows\\System32\\drivers\\etc\\hosts\"\r\n\r\n      # Load the content of the HOSTS file\r\n      try {\r\n          $hostsContent = Get-Content $localHostsPath -ErrorAction Stop\r\n      } catch {\r\n          Write-Error \"Failed to load the HOSTS file. Error: $_\"\r\n          return\r\n      }\r\n\r\n      # Initialize flags and buffer for new content\r\n      $recording = $true\r\n      $newContent = @()\r\n\r\n      # Iterate over each line of the HOSTS file\r\n      foreach ($line in $hostsContent) {\r\n          if ($line -match \"#AdobeNetBlock-start\") {\r\n              $recording = $false\r\n          }\r\n          if ($recording) {\r\n              $newContent += $line\r\n          }\r\n          if ($line -match \"#AdobeNetBlock-end\") {\r\n              $recording = $true\r\n          }\r\n      }\r\n\r\n      # Write the filtered content back to the HOSTS file\r\n      try {\r\n          $newContent | Set-Content $localHostsPath -Encoding ASCII\r\n          Write-Output \"Successfully removed the AdobeNetBlock section from the HOSTS file.\"\r\n      } catch {\r\n          Write-Error \"Failed to write back to the HOSTS file. Error: $_\"\r\n      }\r\n\r\n      # Flush the DNS resolver cache\r\n      try {\r\n          Invoke-Expression \"ipconfig /flushdns\"\r\n          Write-Output \"DNS cache flushed successfully.\"\r\n      } catch {\r\n          Write-Error \"Failed to flush DNS cache. Error: $_\"\r\n      }\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/BlockAdobeNet"
  },
  "WPFTweaksRightClickMenu": {
    "Content": "Set Classic Right-Click Menu ",
    "Description": "Great Windows 11 tweak to bring back good context menus when right clicking things in explorer.",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a027_",
    "InvokeScript": [
      "\r\n      New-Item -Path \"HKCU:\\Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\" -Name \"InprocServer32\" -force -value \"\"\r\n      Write-Host Restarting explorer.exe ...\r\n      $process = Get-Process -Name \"explorer\"\r\n      Stop-Process -InputObject $process\r\n      "
    ],
    "UndoScript": [
      "\r\n      Remove-Item -Path \"HKCU:\\Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\" -Recurse -Confirm:$false -Force\r\n      # Restarting Explorer in the Undo Script might not be necessary, as the Registry change without restarting Explorer does work, but just to make sure.\r\n      Write-Host Restarting explorer.exe ...\r\n      $process = Get-Process -Name \"explorer\"\r\n      Stop-Process -InputObject $process\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/RightClickMenu"
  },
  "WPFTweaksDiskCleanup": {
    "Content": "Run Disk Cleanup",
    "Description": "Runs Disk Cleanup on Drive C: and removes old Windows Updates.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a009_",
    "InvokeScript": [
      "\r\n      cleanmgr.exe /d C: /VERYLOWDISK\r\n      Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/DiskCleanup"
  },
  "WPFTweaksDeleteTempFiles": {
    "Content": "Delete Temporary Files",
    "Description": "Erases TEMP Folders",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a002_",
    "InvokeScript": [
      "Get-ChildItem -Path \"C:\\Windows\\Temp\" *.* -Recurse | Remove-Item -Force -Recurse\r\n    Get-ChildItem -Path $env:TEMP *.* -Recurse | Remove-Item -Force -Recurse"
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/DeleteTempFiles"
  },
  "WPFTweaksDVR": {
    "Content": "Disable GameDVR",
    "Description": "GameDVR is a Windows App that is a dependency for some Store Games. I've never met someone that likes it, but it's there for the XBOX crowd.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a005_",
    "registry": [
      {
        "Path": "HKCU:\\System\\GameConfigStore",
        "Name": "GameDVR_FSEBehavior",
        "Value": "2",
        "OriginalValue": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\System\\GameConfigStore",
        "Name": "GameDVR_Enabled",
        "Value": "0",
        "OriginalValue": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\System\\GameConfigStore",
        "Name": "GameDVR_HonorUserFSEBehaviorMode",
        "Value": "1",
        "OriginalValue": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\System\\GameConfigStore",
        "Name": "GameDVR_EFSEFeatureFlags",
        "Value": "0",
        "OriginalValue": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR",
        "Name": "AllowGameDVR",
        "Value": "0",
        "OriginalValue": "<RemoveEntry>",
        "Type": "DWord"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/DVR"
  },
  "WPFTweaksIPv46": {
    "Content": "Prefer IPv4 over IPv6",
    "Description": "To set the IPv4 preference can have latency and security benefits on private networks where IPv6 is not configured.",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a023_",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
        "Name": "DisabledComponents",
        "Value": "32",
        "OriginalValue": "0",
        "Type": "DWord"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Essential-Tweaks/IPv46"
  },
  "WPFTweaksTeredo": {
    "Content": "Disable Teredo",
    "Description": "Teredo network tunneling is a ipv6 feature that can cause additional latency, but may cause problems with some games",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a023_",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
        "Name": "DisabledComponents",
        "Value": "1",
        "OriginalValue": "0",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "netsh interface teredo set state disabled"
    ],
    "UndoScript": [
      "netsh interface teredo set state default"
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/Teredo"
  },
  "WPFTweaksDisableipsix": {
    "Content": "Disable IPv6",
    "Description": "Disables IPv6.",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a023_",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
        "Name": "DisabledComponents",
        "Value": "255",
        "OriginalValue": "0",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "Disable-NetAdapterBinding -Name \"*\" -ComponentID ms_tcpip6"
    ],
    "UndoScript": [
      "Enable-NetAdapterBinding -Name \"*\" -ComponentID ms_tcpip6"
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/Disableipsix"
  },
  "WPFTweaksDisableBGapps": {
    "Content": "Disable Background Apps",
    "Description": "Disables all Microsoft Store apps from running in the background, which has to be done individually since Win11",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a024_",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications",
        "Name": "GlobalUserDisabled",
        "Value": "1",
        "OriginalValue": "0",
        "Type": "DWord"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/DisableBGapps"
  },
  "WPFTweaksDisableFSO": {
    "Content": "Disable Fullscreen Optimizations",
    "Description": "Disables FSO in all applications. NOTE: This will disable Color Management in Exclusive Fullscreen",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a024_",
    "registry": [
      {
        "Path": "HKCU:\\System\\GameConfigStore",
        "Name": "GameDVR_DXGIHonorFSEWindowsCompatible",
        "Value": "1",
        "OriginalValue": "0",
        "Type": "DWord"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/DisableFSO"
  },
  "WPFToggleDarkMode": {
    "Content": "Dark Theme for Windows",
    "Description": "Enable/Disable Dark Mode.",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a100_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
        "Name": "AppsUseLightTheme",
        "Value": "0",
        "OriginalValue": "1",
        "DefaultState": "false",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
        "Name": "SystemUsesLightTheme",
        "Value": "0",
        "OriginalValue": "1",
        "DefaultState": "false",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "\r\n      Invoke-WinUtilExplorerUpdate\r\n      if ($sync.ThemeButton.Content -eq [char]0xF08C) {\r\n        Invoke-WinutilThemeChange -theme \"Auto\"\r\n      }\r\n      "
    ],
    "UndoScript": [
      "\r\n      Invoke-WinUtilExplorerUpdate\r\n      if ($sync.ThemeButton.Content -eq [char]0xF08C) {\r\n        Invoke-WinutilThemeChange -theme \"Auto\"\r\n      }\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/DarkMode"
  },
  "WPFToggleBingSearch": {
    "Content": "Bing Search in Start Menu",
    "Description": "If enable then includes web search results from Bing in your Start Menu search.",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a101_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Search",
        "Name": "BingSearchEnabled",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/BingSearch"
  },
  "WPFToggleNumLock": {
    "Content": "NumLock on Startup",
    "Description": "Toggle the Num Lock key state when your computer starts.",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a102_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKU:\\.Default\\Control Panel\\Keyboard",
        "Name": "InitialKeyboardIndicators",
        "Value": "2",
        "OriginalValue": "0",
        "DefaultState": "false",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Control Panel\\Keyboard",
        "Name": "InitialKeyboardIndicators",
        "Value": "2",
        "OriginalValue": "0",
        "DefaultState": "false",
        "Type": "DWord"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/NumLock"
  },
  "WPFToggleVerboseLogon": {
    "Content": "Verbose Messages During Logon",
    "Description": "Show detailed messages during the login process for troubleshooting and diagnostics.",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a103_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        "Name": "VerboseStatus",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "false",
        "Type": "DWord"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/VerboseLogon"
  },
  "WPFToggleStartMenuRecommendations": {
    "Content": "Recommendations in Start Menu",
    "Description": "If disabled then you will not see recommendations in the Start Menu. | Enables 'iseducationenvironment' | Relogin Required.",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a104_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start",
        "Name": "HideRecommendedSection",
        "Value": "0",
        "OriginalValue": "1",
        "DefaultState": "true",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Education",
        "Name": "IsEducationEnvironment",
        "Value": "0",
        "OriginalValue": "1",
        "DefaultState": "true",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer",
        "Name": "HideRecommendedSection",
        "Value": "0",
        "OriginalValue": "1",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/WPFToggleStartMenuRecommendations"
  },
  "WPFToggleSnapWindow": {
    "Content": "Snap Window",
    "Description": "If enabled you can align windows by dragging them. | Relogin Required",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a105_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKCU:\\Control Panel\\Desktop",
        "Name": "WindowArrangementActive",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "String"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/SnapWindow"
  },
  "WPFToggleSnapFlyout": {
    "Content": "Snap Assist Flyout",
    "Description": "If enabled then Snap preview is disabled when maximize button is hovered.",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a106_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "Name": "EnableSnapAssistFlyout",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "\r\n      Invoke-WinUtilExplorerUpdate -action \"restart\"\r\n      "
    ],
    "UndoScript": [
      "\r\n      Invoke-WinUtilExplorerUpdate -action \"restart\"\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/SnapFlyout"
  },
  "WPFToggleSnapSuggestion": {
    "Content": "Snap Assist Suggestion",
    "Description": "If enabled then you will get suggestions to snap other applications in the left over spaces.",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a107_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "Name": "SnapAssist",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "\r\n      Invoke-WinUtilExplorerUpdate -action \"restart\"\r\n      "
    ],
    "UndoScript": [
      "\r\n      Invoke-WinUtilExplorerUpdate -action \"restart\"\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/SnapSuggestion"
  },
  "WPFToggleMouseAcceleration": {
    "Content": "Mouse Acceleration",
    "Description": "If Enabled then Cursor movement is affected by the speed of your physical mouse movements.",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a108_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKCU:\\Control Panel\\Mouse",
        "Name": "MouseSpeed",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Control Panel\\Mouse",
        "Name": "MouseThreshold1",
        "Value": "6",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Control Panel\\Mouse",
        "Name": "MouseThreshold2",
        "Value": "10",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/MouseAcceleration"
  },
  "WPFToggleStickyKeys": {
    "Content": "Sticky Keys",
    "Description": "If Enabled then Sticky Keys is activated - Sticky keys is an accessibility feature of some graphical user interfaces which assists users who have physical disabilities or help users reduce repetitive strain injury.",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a109_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKCU:\\Control Panel\\Accessibility\\StickyKeys",
        "Name": "Flags",
        "Value": "510",
        "OriginalValue": "58",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/StickyKeys"
  },
  "WPFToggleHiddenFiles": {
    "Content": "Show Hidden Files",
    "Description": "If Enabled then Hidden Files will be shown.",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a200_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "Name": "Hidden",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "false",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "\r\n      Invoke-WinUtilExplorerUpdate -action \"restart\"\r\n      "
    ],
    "UndoScript": [
      "\r\n      Invoke-WinUtilExplorerUpdate -action \"restart\"\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/HiddenFiles"
  },
  "WPFToggleShowExt": {
    "Content": "Show File Extensions",
    "Description": "If enabled then File extensions (e.g., .txt, .jpg) are visible.",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a201_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "Name": "HideFileExt",
        "Value": "0",
        "OriginalValue": "1",
        "DefaultState": "false",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "\r\n      Invoke-WinUtilExplorerUpdate -action \"restart\"\r\n      "
    ],
    "UndoScript": [
      "\r\n      Invoke-WinUtilExplorerUpdate -action \"restart\"\r\n      "
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/ShowExt"
  },
  "WPFToggleTaskbarSearch": {
    "Content": "Search Button in Taskbar",
    "Description": "If Enabled Search Button will be on the taskbar.",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a202_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Search",
        "Name": "SearchboxTaskbarMode",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/TaskbarSearch"
  },
  "WPFToggleTaskView": {
    "Content": "Task View Button in Taskbar",
    "Description": "If Enabled then Task View Button in Taskbar will be shown.",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a203_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "Name": "ShowTaskViewButton",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/TaskView"
  },
  "WPFToggleTaskbarWidgets": {
    "Content": "Widgets Button in Taskbar",
    "Description": "If Enabled then Widgets Button in Taskbar will be shown.",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a204_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "Name": "TaskbarDa",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/TaskbarWidgets"
  },
  "WPFToggleTaskbarAlignment": {
    "Content": "Center Taskbar Items",
    "Description": "[Windows 11] If Enabled then the Taskbar Items will be shown on the Center, otherwise the Taskbar Items will be shown on the Left.",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a204_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "Name": "TaskbarAl",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "true",
        "Type": "DWord"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/TaskbarAlignment"
  },
  "WPFToggleDetailedBSoD": {
    "Content": "Detailed BSoD",
    "Description": "If Enabled then you will see a detailed Blue Screen of Death (BSOD) with more information.",
    "category": "Customize Preferences",
    "panel": "2",
    "Order": "a205_",
    "Type": "Toggle",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl",
        "Name": "DisplayParameters",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "false",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl",
        "Name": "DisableEmoticon",
        "Value": "1",
        "OriginalValue": "0",
        "DefaultState": "false",
        "Type": "DWord"
      }
    ],
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Customize-Preferences/DetailedBSoD"
  },
  "WPFOOSUbutton": {
    "Content": "Run OO Shutup 10",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a039_",
    "Type": "Button",
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/OOSUbutton"
  },
  "WPFchangedns": {
    "Content": "DNS",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a040_",
    "Type": "Combobox",
    "ComboItems": "Default DHCP Google Cloudflare Cloudflare_Malware Cloudflare_Malware_Adult Open_DNS Quad9 AdGuard_Ads_Trackers AdGuard_Ads_Trackers_Malware_Adult dns0.eu_Open dns0.eu_ZERO dns0.eu_KIDS",
    "link": "https://tut-os.github.io/winutil/dev/tweaks/z--Advanced-Tweaks---CAUTION/changedns"
  },
  "WPFAddUltPerf": {
    "Content": "Add and Activate Ultimate Performance Profile",
    "category": "Performance Plans",
    "panel": "2",
    "Order": "a080_",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Performance-Plans/AddUltPerf"
  },
  "WPFRemoveUltPerf": {
    "Content": "Remove Ultimate Performance Profile",
    "category": "Performance Plans",
    "panel": "2",
    "Order": "a081_",
    "Type": "Button",
    "ButtonWidth": "300",
    "link": "https://tut-os.github.io/winutil/dev/tweaks/Performance-Plans/RemoveUltPerf"
  }
}
'@ | ConvertFrom-Json
$inputXML = @'
<Window x:Class="WinUtility.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:WinUtility"
        mc:Ignorable="d"
        WindowStartupLocation="CenterScreen"
        UseLayoutRounding="True"
        WindowStyle="None"
        Width="Auto"
        Height="Auto"
        MaxWidth="1380"
        MaxHeight="800"
        Title="TUTOS - UNF*CK WINDOWS">
    <WindowChrome.WindowChrome>
        <WindowChrome CaptionHeight="0" CornerRadius="10"/>
    </WindowChrome.WindowChrome>
    <Window.Resources>
    <Style TargetType="ToolTip">
        <Setter Property="Background" Value="{DynamicResource MainBackgroundColor}"/>
        <Setter Property="Foreground" Value="{DynamicResource MainForegroundColor}"/>
        <Setter Property="BorderBrush" Value="{DynamicResource ButtonBackgroundSelectedColor}"/>
        <Setter Property="BorderThickness" Value="1"/>
        <Setter Property="Padding" Value="5"/>
        <Setter Property="FontSize" Value="{DynamicResource FontSize}"/>
        <Setter Property="FontFamily" Value="{DynamicResource FontFamily}"/>
    </Style>

    <Style TargetType="{x:Type MenuItem}">
        <Setter Property="Background" Value="{DynamicResource MainBackgroundColor}"/>
        <Setter Property="Foreground" Value="{DynamicResource MainForegroundColor}"/>
        <Setter Property="FontSize" Value="{DynamicResource FontSize}"/>
        <Setter Property="FontFamily" Value="{DynamicResource FontFamily}"/>
        <Setter Property="Padding" Value="5,2,5,2"/>
        <Setter Property="BorderThickness" Value="0"/>
    </Style>

    <!--Scrollbar Thumbs-->
    <Style x:Key="ScrollThumbs" TargetType="{x:Type Thumb}">
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="{x:Type Thumb}">
                    <Grid x:Name="Grid">
                        <Rectangle HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Width="Auto" Height="Auto" Fill="Transparent" />
                        <Border x:Name="Rectangle1" CornerRadius="5" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Width="Auto" Height="Auto"  Background="{TemplateBinding Background}" />
                    </Grid>
                    <ControlTemplate.Triggers>
                        <Trigger Property="Tag" Value="Horizontal">
                            <Setter TargetName="Rectangle1" Property="Width" Value="Auto" />
                            <Setter TargetName="Rectangle1" Property="Height" Value="7" />
                        </Trigger>
                    </ControlTemplate.Triggers>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>

    <Style TargetType="TextBlock" x:Key="HoverTextBlockStyle">
        <Setter Property="Foreground" Value="{DynamicResource LinkForegroundColor}" />
        <Setter Property="TextDecorations" Value="Underline" />
        <Style.Triggers>
            <Trigger Property="IsMouseOver" Value="True">
                <Setter Property="Foreground" Value="{DynamicResource LinkHoverForegroundColor}" />
                <Setter Property="TextDecorations" Value="Underline" />
                <Setter Property="Cursor" Value="Hand" />
            </Trigger>
        </Style.Triggers>
    </Style>

    <Style TargetType="Button" x:Key="HoverButtonStyle">
        <Setter Property="Foreground" Value="{DynamicResource MainForegroundColor}" />
        <Setter Property="FontWeight" Value="Normal" />
        <Setter Property="FontSize" Value="{DynamicResource ButtonFontSize}" />
        <Setter Property="TextElement.FontFamily" Value="{DynamicResource ButtonFontFamily}"/>
        <Setter Property="Background" Value="{DynamicResource MainBackgroundColor}" />
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="Button">
                    <Border Background="{TemplateBinding Background}">
                        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <ControlTemplate.Triggers>
                        <Trigger Property="IsMouseOver" Value="True">
                            <Setter Property="FontWeight" Value="Bold" />
                            <Setter Property="Foreground" Value="{DynamicResource MainForegroundColor}" />
                            <Setter Property="Cursor" Value="Hand" />
                        </Trigger>
                    </ControlTemplate.Triggers>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>

    <!--ScrollBars-->
    <Style x:Key="{x:Type ScrollBar}" TargetType="{x:Type ScrollBar}">
        <Setter Property="Stylus.IsFlicksEnabled" Value="false" />
        <Setter Property="Foreground" Value="{DynamicResource ScrollBarBackgroundColor}" />
        <Setter Property="Background" Value="{DynamicResource MainBackgroundColor}" />
        <Setter Property="Width" Value="6" />
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="{x:Type ScrollBar}">
                    <Grid x:Name="GridRoot" Width="7" Background="{TemplateBinding Background}" >
                        <Grid.RowDefinitions>
                            <RowDefinition Height="0.00001*" />
                        </Grid.RowDefinitions>

                        <Track x:Name="PART_Track" Grid.Row="0" IsDirectionReversed="true" Focusable="false">
                            <Track.Thumb>
                                <Thumb x:Name="Thumb" Background="{TemplateBinding Foreground}" Style="{DynamicResource ScrollThumbs}" />
                            </Track.Thumb>
                            <Track.IncreaseRepeatButton>
                                <RepeatButton x:Name="PageUp" Command="ScrollBar.PageDownCommand" Opacity="0" Focusable="false" />
                            </Track.IncreaseRepeatButton>
                            <Track.DecreaseRepeatButton>
                                <RepeatButton x:Name="PageDown" Command="ScrollBar.PageUpCommand" Opacity="0" Focusable="false" />
                            </Track.DecreaseRepeatButton>
                        </Track>
                    </Grid>

                    <ControlTemplate.Triggers>
                        <Trigger SourceName="Thumb" Property="IsMouseOver" Value="true">
                            <Setter Value="{DynamicResource ScrollBarHoverColor}" TargetName="Thumb" Property="Background" />
                        </Trigger>
                        <Trigger SourceName="Thumb" Property="IsDragging" Value="true">
                            <Setter Value="{DynamicResource ScrollBarDraggingColor}" TargetName="Thumb" Property="Background" />
                        </Trigger>

                        <Trigger Property="IsEnabled" Value="false">
                            <Setter TargetName="Thumb" Property="Visibility" Value="Collapsed" />
                        </Trigger>
                        <Trigger Property="Orientation" Value="Horizontal">
                            <Setter TargetName="GridRoot" Property="LayoutTransform">
                                <Setter.Value>
                                    <RotateTransform Angle="-90" />
                                </Setter.Value>
                            </Setter>
                            <Setter TargetName="PART_Track" Property="LayoutTransform">
                                <Setter.Value>
                                    <RotateTransform Angle="-90" />
                                </Setter.Value>
                            </Setter>
                            <Setter Property="Width" Value="Auto" />
                            <Setter Property="Height" Value="8" />
                            <Setter TargetName="Thumb" Property="Tag" Value="Horizontal" />
                            <Setter TargetName="PageDown" Property="Command" Value="ScrollBar.PageLeftCommand" />
                            <Setter TargetName="PageUp" Property="Command" Value="ScrollBar.PageRightCommand" />
                        </Trigger>
                    </ControlTemplate.Triggers>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
        </Style>
        <Style TargetType="ComboBox">
            <Setter Property="Foreground" Value="{DynamicResource ComboBoxForegroundColor}" />
            <Setter Property="Background" Value="{DynamicResource ComboBoxBackgroundColor}" />
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ComboBox">
                        <Grid>
                            <ToggleButton x:Name="ToggleButton"
                                          Background="{TemplateBinding Background}"
                                          BorderBrush="{TemplateBinding Background}"
                                          BorderThickness="0"
                                          IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}"
                                          ClickMode="Press">
                                <TextBlock Text="{TemplateBinding SelectionBoxItem}"
                                           Foreground="{TemplateBinding Foreground}"
                                           Background="Transparent"
                                           HorizontalAlignment="Center" VerticalAlignment="Center" Margin="2"
                                           />
                            </ToggleButton>
                            <Popup x:Name="Popup"
                                   IsOpen="{TemplateBinding IsDropDownOpen}"
                                   Placement="Bottom"
                                   Focusable="False"
                                   AllowsTransparency="True"
                                   PopupAnimation="Slide">
                                <Border x:Name="DropDownBorder"
                                        Background="{TemplateBinding Background}"
                                        BorderBrush="{TemplateBinding Foreground}"
                                        BorderThickness="1"
                                        CornerRadius="4">
                                    <ScrollViewer>
                                        <ItemsPresenter HorizontalAlignment="Center" VerticalAlignment="Center" Margin="2"/>
                                    </ScrollViewer>
                                </Border>
                            </Popup>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style TargetType="Label">
            <Setter Property="Foreground" Value="{DynamicResource LabelboxForegroundColor}"/>
            <Setter Property="Background" Value="{DynamicResource LabelBackgroundColor}"/>
            <Setter Property="FontFamily" Value="{DynamicResource FontFamily}"/>
        </Style>

        <!-- TextBlock template -->
        <Style TargetType="TextBlock">
            <Setter Property="FontSize" Value="{DynamicResource FontSize}"/>
            <Setter Property="Foreground" Value="{DynamicResource LabelboxForegroundColor}"/>
            <Setter Property="Background" Value="{DynamicResource LabelBackgroundColor}"/>
        </Style>
        <!-- Toggle button template x:Key="TabToggleButton" -->
        <Style TargetType="{x:Type ToggleButton}">
            <Setter Property="Margin" Value="{DynamicResource ButtonMargin}"/>
            <Setter Property="Content" Value=""/>
            <Setter Property="FontFamily" Value="{DynamicResource FontFamily}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ToggleButton">
                        <Grid>
                            <Border x:Name="ButtonGlow"
                                        Background="{TemplateBinding Background}"
                                        BorderBrush="{DynamicResource ButtonForegroundColor}"
                                        BorderThickness="{DynamicResource ButtonBorderThickness}"
                                        CornerRadius="{DynamicResource ButtonCornerRadius}">
                                <Grid>
                                    <Border x:Name="BackgroundBorder"
                                        Background="{TemplateBinding Background}"
                                        BorderBrush="{DynamicResource ButtonBackgroundColor}"
                                        BorderThickness="{DynamicResource ButtonBorderThickness}"
                                        CornerRadius="{DynamicResource ButtonCornerRadius}">
                                        <ContentPresenter
                                            HorizontalAlignment="Center"
                                            VerticalAlignment="Center"
                                            Margin="10,2,10,2"/>
                                    </Border>
                                </Grid>
                            </Border>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="BackgroundBorder" Property="Background" Value="{DynamicResource ButtonBackgroundMouseoverColor}"/>
                                <Setter Property="Effect">
                                    <Setter.Value>
                                        <DropShadowEffect Opacity="1" ShadowDepth="5" Color="{DynamicResource CButtonBackgroundMouseoverColor}" Direction="-100" BlurRadius="15"/>
                                    </Setter.Value>
                                </Setter>
                                <Setter Property="Panel.ZIndex" Value="2000"/>
                            </Trigger>
                            <Trigger Property="IsChecked" Value="True">
                                <Setter Property="BorderBrush" Value="Pink"/>
                                <Setter Property="BorderThickness" Value="2"/>
                                <Setter TargetName="BackgroundBorder" Property="Background" Value="{DynamicResource ButtonBackgroundSelectedColor}"/>
                                <Setter Property="Effect">
                                    <Setter.Value>
                                        <DropShadowEffect Opacity="1" ShadowDepth="2" Color="{DynamicResource CButtonBackgroundMouseoverColor}" Direction="-111" BlurRadius="10"/>
                                    </Setter.Value>
                                </Setter>
                            </Trigger>
                            <Trigger Property="IsChecked" Value="False">
                                <Setter Property="BorderBrush" Value="Transparent"/>
                                <Setter Property="BorderThickness" Value="{DynamicResource ButtonBorderThickness}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <!-- Button Template -->
        <Style TargetType="Button">
            <Setter Property="Margin" Value="{DynamicResource ButtonMargin}"/>
            <Setter Property="Foreground" Value="{DynamicResource ButtonForegroundColor}"/>
            <Setter Property="Background" Value="{DynamicResource ButtonBackgroundColor}"/>
            <Setter Property="Height" Value="{DynamicResource ButtonHeight}"/>
            <Setter Property="Width" Value="{DynamicResource ButtonWidth}"/>
            <Setter Property="FontSize" Value="{DynamicResource ButtonFontSize}"/>
            <Setter Property="FontFamily" Value="{DynamicResource FontFamily}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Grid>
                            <Border x:Name="BackgroundBorder"
                                    Background="{TemplateBinding Background}"
                                    BorderBrush="{TemplateBinding BorderBrush}"
                                    BorderThickness="{DynamicResource ButtonBorderThickness}"
                                    CornerRadius="{DynamicResource ButtonCornerRadius}">
                                <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" Margin="10,2,10,2"/>
                            </Border>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="BackgroundBorder" Property="Background" Value="{DynamicResource ButtonBackgroundPressedColor}"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="BackgroundBorder" Property="Background" Value="{DynamicResource ButtonBackgroundMouseoverColor}"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="BackgroundBorder" Property="Background" Value="{DynamicResource ButtonBackgroundSelectedColor}"/>
                                <Setter Property="Foreground" Value="DimGray"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="SearchBarClearButtonStyle" TargetType="Button">
            <Setter Property="FontFamily" Value="{DynamicResource FontFamily}"/>
            <Setter Property="FontSize" Value="{DynamicResource SearchBarClearButtonFontSize}"/>
            <Setter Property="Content" Value="X"/>
            <Setter Property="Height" Value="{DynamicResource SearchBarClearButtonFontSize}"/>
            <Setter Property="Width" Value="{DynamicResource SearchBarClearButtonFontSize}"/>
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="{DynamicResource MainForegroundColor}"/>
            <Setter Property="Padding" Value="0"/>
            <Setter Property="BorderBrush" Value="Transparent"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Foreground" Value="Red"/>
                    <Setter Property="Background" Value="Transparent"/>
                    <Setter Property="BorderThickness" Value="10"/>
                    <Setter Property="Cursor" Value="Hand"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        <!-- Checkbox template -->
        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="{DynamicResource MainForegroundColor}"/>
            <Setter Property="Background" Value="{DynamicResource MainBackgroundColor}"/>
            <Setter Property="FontSize" Value="{DynamicResource FontSize}" />
            <Setter Property="FontFamily" Value="{DynamicResource FontFamily}"/>
            <Setter Property="TextElement.FontFamily" Value="{DynamicResource FontFamily}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="CheckBox">
                        <Grid Background="{TemplateBinding Background}" Margin="{DynamicResource CheckBoxMargin}">
                            <BulletDecorator Background="Transparent">
                                <BulletDecorator.Bullet>
                                    <Grid Width="{DynamicResource CheckBoxBulletDecoratorSize}" Height="{DynamicResource CheckBoxBulletDecoratorSize}">
                                        <Border x:Name="Border"
                                                BorderBrush="{TemplateBinding BorderBrush}"
                                                Background="{DynamicResource ButtonBackgroundColor}"
                                                BorderThickness="1"
                                                Width="{DynamicResource CheckBoxBulletDecoratorSize *0.85}"
                                                Height="{DynamicResource CheckBoxBulletDecoratorSize *0.85}"
                                                Margin="2"
                                                SnapsToDevicePixels="True"/>
                                        <Path x:Name="CheckMark"
                                              Stroke="{DynamicResource ToggleButtonOnColor}"
                                              StrokeThickness="2"
                                              Data="M 0 5 L 5 10 L 12 0"
                                              Visibility="Collapsed"/>
                                    </Grid>
                                </BulletDecorator.Bullet>
                                <ContentPresenter Margin="4,0,0,0"
                                                  HorizontalAlignment="Left"
                                                  VerticalAlignment="Center"
                                                  RecognizesAccessKey="True"/>
                            </BulletDecorator>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsChecked" Value="True">
                                <Setter TargetName="CheckMark" Property="Visibility" Value="Visible"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="True">
                                <!--Setter TargetName="Border" Property="Background" Value="{DynamicResource ButtonBackgroundPressedColor}"/-->
                                <Setter Property="Foreground" Value="{DynamicResource ButtonBackgroundPressedColor}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                 </Setter.Value>
            </Setter>
        </Style>
        <Style TargetType="RadioButton">
            <Setter Property="Foreground" Value="{DynamicResource MainForegroundColor}"/>
            <Setter Property="Background" Value="{DynamicResource MainBackgroundColor}"/>
            <Setter Property="FontSize" Value="{DynamicResource FontSize}" />
            <Setter Property="FontFamily" Value="{DynamicResource FontFamily}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="RadioButton">
                        <StackPanel Orientation="Horizontal" Margin="{DynamicResource CheckBoxMargin}">
                            <Grid Width="14" Height="14">
                                <Ellipse x:Name="OuterCircle"
                                        Stroke="{DynamicResource ToggleButtonOffColor}"
                                        Fill="{DynamicResource ButtonBackgroundColor}"
                                        StrokeThickness="1"
                                        Width="14"
                                        Height="14"
                                        SnapsToDevicePixels="True"/>
                                <Ellipse x:Name="InnerCircle"
                                        Fill="{DynamicResource ToggleButtonOnColor}"
                                        Width="8"
                                        Height="8"
                                        Visibility="Collapsed"
                                        HorizontalAlignment="Center"
                                        VerticalAlignment="Center"/>
                            </Grid>
                            <ContentPresenter Margin="4,0,0,0"
                                            VerticalAlignment="Center"
                                            RecognizesAccessKey="True"/>
                        </StackPanel>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsChecked" Value="True">
                                <Setter TargetName="InnerCircle" Property="Visibility" Value="Visible"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="OuterCircle" Property="Stroke" Value="{DynamicResource ToggleButtonOnColor}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="ToggleSwitchStyle" TargetType="CheckBox">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="CheckBox">
                        <StackPanel>
                            <Grid>
                                <Border Width="45"
                                        Height="20"
                                        Background="#555555"
                                        CornerRadius="10"
                                        Margin="5,0"
                                />
                                <Border Name="WPFToggleSwitchButton"
                                        Width="25"
                                        Height="25"
                                        Background="Black"
                                        CornerRadius="12.5"
                                        HorizontalAlignment="Left"
                                />
                                <ContentPresenter Name="WPFToggleSwitchContent"
                                                  Margin="10,0,0,0"
                                                  Content="{TemplateBinding Content}"
                                                  VerticalAlignment="Center"
                                />
                            </Grid>
                        </StackPanel>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsChecked" Value="false">
                                <Trigger.ExitActions>
                                    <RemoveStoryboard BeginStoryboardName="WPFToggleSwitchLeft" />
                                    <BeginStoryboard x:Name="WPFToggleSwitchRight">
                                        <Storyboard>
                                            <ThicknessAnimation Storyboard.TargetProperty="Margin"
                                                    Storyboard.TargetName="WPFToggleSwitchButton"
                                                    Duration="0:0:0:0"
                                                    From="0,0,0,0"
                                                    To="28,0,0,0">
                                            </ThicknessAnimation>
                                        </Storyboard>
                                    </BeginStoryboard>
                                </Trigger.ExitActions>
                                <Setter TargetName="WPFToggleSwitchButton"
                                        Property="Background"
                                        Value="#fff9f4f4"
                                />
                            </Trigger>
                            <Trigger Property="IsChecked" Value="true">
                                <Trigger.ExitActions>
                                    <RemoveStoryboard BeginStoryboardName="WPFToggleSwitchRight" />
                                    <BeginStoryboard x:Name="WPFToggleSwitchLeft">
                                        <Storyboard>
                                            <ThicknessAnimation Storyboard.TargetProperty="Margin"
                                                    Storyboard.TargetName="WPFToggleSwitchButton"
                                                    Duration="0:0:0:0"
                                                    From="28,0,0,0"
                                                    To="0,0,0,0">
                                            </ThicknessAnimation>
                                        </Storyboard>
                                    </BeginStoryboard>
                                </Trigger.ExitActions>
                                <Setter TargetName="WPFToggleSwitchButton"
                                        Property="Background"
                                        Value="#ff060600"
                                />
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="ColorfulToggleSwitchStyle" TargetType="{x:Type CheckBox}">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="{x:Type ToggleButton}">
                        <Grid x:Name="toggleSwitch">

                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>

                        <Border Grid.Column="1" x:Name="Border" CornerRadius="8"
                                BorderThickness="1"
                                Width="34" Height="17">
                            <Ellipse x:Name="Ellipse" Fill="{DynamicResource MainForegroundColor}" Stretch="Uniform"
                                    Margin="2,2,2,1"
                                    HorizontalAlignment="Left" Width="10.8"
                                    RenderTransformOrigin="0.5, 0.5">
                                <Ellipse.RenderTransform>
                                    <ScaleTransform ScaleX="1" ScaleY="1" />
                                </Ellipse.RenderTransform>
                            </Ellipse>
                        </Border>
                        </Grid>

                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Border" Property="BorderBrush" Value="{DynamicResource MainForegroundColor}" />
                                <Setter TargetName="Border" Property="Background" Value="{DynamicResource LinkHoverForegroundColor}"/>
                                <Setter Property="Cursor" Value="Hand" />
                                <Setter Property="Panel.ZIndex" Value="1000"/>
                                <Trigger.EnterActions>
                                    <BeginStoryboard>
                                        <Storyboard>
                                            <DoubleAnimation Storyboard.TargetName="Ellipse"
                                                            Storyboard.TargetProperty="(UIElement.RenderTransform).(ScaleTransform.ScaleX)"
                                                            To="1.1" Duration="0:0:0.1" />
                                            <DoubleAnimation Storyboard.TargetName="Ellipse"
                                                            Storyboard.TargetProperty="(UIElement.RenderTransform).(ScaleTransform.ScaleY)"
                                                            To="1.1" Duration="0:0:0.1" />
                                        </Storyboard>
                                    </BeginStoryboard>
                                </Trigger.EnterActions>
                                <Trigger.ExitActions>
                                    <BeginStoryboard>
                                        <Storyboard>
                                            <DoubleAnimation Storyboard.TargetName="Ellipse"
                                                            Storyboard.TargetProperty="(UIElement.RenderTransform).(ScaleTransform.ScaleX)"
                                                            To="1.0" Duration="0:0:0.1" />
                                            <DoubleAnimation Storyboard.TargetName="Ellipse"
                                                            Storyboard.TargetProperty="(UIElement.RenderTransform).(ScaleTransform.ScaleY)"
                                                            To="1.0" Duration="0:0:0.1" />
                                        </Storyboard>
                                    </BeginStoryboard>
                                </Trigger.ExitActions>
                            </Trigger>
                            <Trigger Property="ToggleButton.IsChecked" Value="False">
                                <Setter TargetName="Border" Property="Background" Value="{DynamicResource MainBackgroundColor}" />
                                <Setter TargetName="Border" Property="BorderBrush" Value="{DynamicResource ToggleButtonOffColor}" />
                                <Setter TargetName="Ellipse" Property="Fill" Value="{DynamicResource ToggleButtonOffColor}" />
                            </Trigger>

                            <Trigger Property="ToggleButton.IsChecked" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="{DynamicResource ToggleButtonOnColor}" />
                                <Setter TargetName="Border" Property="BorderBrush" Value="{DynamicResource ToggleButtonOnColor}" />
                                <Setter TargetName="Ellipse" Property="Fill" Value="White" />

                                <Trigger.EnterActions>
                                    <BeginStoryboard>
                                        <Storyboard>
                                            <ThicknessAnimation Storyboard.TargetName="Ellipse"
                                                    Storyboard.TargetProperty="Margin"
                                                    To="18,2,2,2" Duration="0:0:0.1" />
                                        </Storyboard>
                                    </BeginStoryboard>
                                </Trigger.EnterActions>
                                <Trigger.ExitActions>
                                    <BeginStoryboard>
                                        <Storyboard>
                                            <ThicknessAnimation Storyboard.TargetName="Ellipse"
                                                    Storyboard.TargetProperty="Margin"
                                                    To="2,2,2,1" Duration="0:0:0.1" />
                                        </Storyboard>
                                    </BeginStoryboard>
                                </Trigger.ExitActions>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Setter Property="VerticalContentAlignment" Value="Center" />
        </Style>

        <Style x:Key="labelfortweaks" TargetType="{x:Type Label}">
            <Setter Property="Foreground" Value="{DynamicResource MainForegroundColor}" />
            <Setter Property="Background" Value="{DynamicResource MainBackgroundColor}" />
            <Setter Property="FontFamily" Value="{DynamicResource FontFamily}"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Foreground" Value="White" />
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="BorderStyle" TargetType="Border">
            <Setter Property="Background" Value="{DynamicResource MainBackgroundColor}"/>
            <Setter Property="BorderBrush" Value="{DynamicResource BorderColor}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CornerRadius" Value="5"/>
            <Setter Property="Padding" Value="5"/>
            <Setter Property="Margin" Value="5"/>
            <Setter Property="Effect">
                <Setter.Value>
                    <DropShadowEffect ShadowDepth="5" BlurRadius="5" Opacity="{DynamicResource BorderOpacity}" Color="{DynamicResource CBorderColor}"/>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="TextBox">
            <Setter Property="Background" Value="{DynamicResource MainBackgroundColor}"/>
            <Setter Property="BorderBrush" Value="{DynamicResource MainForegroundColor}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Foreground" Value="{DynamicResource MainForegroundColor}"/>
            <Setter Property="FontSize" Value="{DynamicResource FontSize}"/>
            <Setter Property="FontFamily" Value="{DynamicResource FontFamily}"/>
            <Setter Property="Padding" Value="5"/>
            <Setter Property="HorizontalAlignment" Value="Stretch"/>
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
            <Setter Property="ContextMenu">
                <Setter.Value>
                    <ContextMenu>
                        <ContextMenu.Style>
                            <Style TargetType="ContextMenu">
                                <Setter Property="Template">
                                    <Setter.Value>
                                        <ControlTemplate TargetType="ContextMenu">
                                            <Border Background="{DynamicResource MainBackgroundColor}" BorderBrush="{DynamicResource BorderColor}" BorderThickness="1" CornerRadius="5" Padding="5">
                                                <StackPanel>
                                                    <MenuItem Command="Cut" Header="Cut"/>
                                                    <MenuItem Command="Copy" Header="Copy"/>
                                                    <MenuItem Command="Paste" Header="Paste"/>
                                                </StackPanel>
                                            </Border>
                                        </ControlTemplate>
                                    </Setter.Value>
                                </Setter>
                            </Style>
                        </ContextMenu.Style>
                    </ContextMenu>
                </Setter.Value>
            </Setter>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TextBox">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="5">
                            <Grid>
                                <ScrollViewer x:Name="PART_ContentHost" />
                            </Grid>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Setter Property="Effect">
                <Setter.Value>
                    <DropShadowEffect ShadowDepth="5" BlurRadius="5" Opacity="{DynamicResource BorderOpacity}" Color="{DynamicResource CBorderColor}"/>
                </Setter.Value>
            </Setter>
        </Style>
        <Style TargetType="PasswordBox">
            <Setter Property="Background" Value="{DynamicResource MainBackgroundColor}"/>
            <Setter Property="BorderBrush" Value="{DynamicResource MainForegroundColor}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Foreground" Value="{DynamicResource MainForegroundColor}"/>
            <Setter Property="FontSize" Value="{DynamicResource FontSize}"/>
            <Setter Property="FontFamily" Value="{DynamicResource FontFamily}"/>
            <Setter Property="Padding" Value="5"/>
            <Setter Property="HorizontalAlignment" Value="Stretch"/>
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="PasswordBox">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="5">
                            <Grid>
                                <ScrollViewer x:Name="PART_ContentHost" />
                            </Grid>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Setter Property="Effect">
                <Setter.Value>
                    <DropShadowEffect ShadowDepth="5" BlurRadius="5" Opacity="{DynamicResource BorderOpacity}" Color="{DynamicResource CBorderColor}"/>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="ScrollVisibilityRectangle" TargetType="Rectangle">
            <Setter Property="Visibility" Value="Collapsed"/>
            <Style.Triggers>
                <MultiDataTrigger>
                    <MultiDataTrigger.Conditions>
                        <Condition Binding="{Binding Path=ComputedHorizontalScrollBarVisibility, ElementName=scrollViewer}" Value="Visible"/>
                        <Condition Binding="{Binding Path=ComputedVerticalScrollBarVisibility, ElementName=scrollViewer}" Value="Visible"/>
                    </MultiDataTrigger.Conditions>
                    <Setter Property="Visibility" Value="Visible"/>
                </MultiDataTrigger>
            </Style.Triggers>
        </Style>
    </Window.Resources>
    <Grid Background="{DynamicResource MainBackgroundColor}" ShowGridLines="False" Name="WPFMainGrid" Width="Auto" Height="Auto" HorizontalAlignment="Stretch">
        <Grid.RowDefinitions>
            <RowDefinition Height="{DynamicResource TabRowHeightInPixels}"/>
            <RowDefinition Height=".9*"/>
        </Grid.RowDefinitions>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <DockPanel HorizontalAlignment="Stretch" Background="{DynamicResource MainBackgroundColor}" SnapsToDevicePixels="True" Grid.Row="0" Width="Auto">
            <StackPanel Name="NavLogoPanel" Orientation="Horizontal" HorizontalAlignment="Left" Background="{DynamicResource MainBackgroundColor}" SnapsToDevicePixels="True" Margin="10,0,20,0">
            </StackPanel>
            <ToggleButton Margin="0,0,5,0" HorizontalAlignment="Left" Height="{DynamicResource TabButtonHeight}" Width="{DynamicResource TabButtonWidth}"
                Background="{DynamicResource ButtonInstallBackgroundColor}" Foreground="white" FontWeight="Bold" Name="WPFTab1BT">
                <ToggleButton.Content>
                    <TextBlock FontSize="{DynamicResource TabButtonFontSize}" Background="Transparent" Foreground="{DynamicResource ButtonInstallForegroundColor}" >
                        <Underline>I</Underline>nstall
                    </TextBlock>
                </ToggleButton.Content>
            </ToggleButton>
            <ToggleButton Margin="0,0,5,0" HorizontalAlignment="Left" Height="{DynamicResource TabButtonHeight}" Width="{DynamicResource TabButtonWidth}"
                Background="{DynamicResource ButtonTweaksBackgroundColor}" Foreground="{DynamicResource ButtonTweaksForegroundColor}" FontWeight="Bold" Name="WPFTab2BT">
                <ToggleButton.Content>
                    <TextBlock FontSize="{DynamicResource TabButtonFontSize}" Background="Transparent" Foreground="{DynamicResource ButtonTweaksForegroundColor}">
                        <Underline>T</Underline>weaks
                    </TextBlock>
                </ToggleButton.Content>
            </ToggleButton>
            <ToggleButton Margin="0,0,5,0" HorizontalAlignment="Left" Height="{DynamicResource TabButtonHeight}" Width="{DynamicResource TabButtonWidth}"
                Background="{DynamicResource ButtonConfigBackgroundColor}" Foreground="{DynamicResource ButtonConfigForegroundColor}" FontWeight="Bold" Name="WPFTab3BT">
                <ToggleButton.Content>
                    <TextBlock FontSize="{DynamicResource TabButtonFontSize}" Background="Transparent" Foreground="{DynamicResource ButtonConfigForegroundColor}">
                        <Underline>C</Underline>onfig
                    </TextBlock>
                </ToggleButton.Content>
            </ToggleButton>
            <ToggleButton Margin="0,0,5,0" HorizontalAlignment="Left" Height="{DynamicResource TabButtonHeight}" Width="{DynamicResource TabButtonWidth}"
                Background="{DynamicResource ButtonUpdatesBackgroundColor}" Foreground="{DynamicResource ButtonUpdatesForegroundColor}" FontWeight="Bold" Name="WPFTab4BT">
                <ToggleButton.Content>
                    <TextBlock FontSize="{DynamicResource TabButtonFontSize}" Background="Transparent" Foreground="{DynamicResource ButtonUpdatesForegroundColor}">
                        <Underline>U</Underline>pdates
                    </TextBlock>
                </ToggleButton.Content>
            </ToggleButton>
            <ToggleButton Margin="0,0,5,0" HorizontalAlignment="Left" Height="{DynamicResource TabButtonHeight}" Width="{DynamicResource TabButtonWidth}"
                Background="{DynamicResource ButtonUpdatesBackgroundColor}" Foreground="{DynamicResource ButtonUpdatesForegroundColor}" FontWeight="Bold" Name="WPFTab5BT">
                <ToggleButton.Content>
                    <TextBlock FontSize="{DynamicResource TabButtonFontSize}" Background="Transparent" Foreground="{DynamicResource ButtonUpdatesForegroundColor}">
                        <Underline>M</Underline>icroWin
                    </TextBlock>
                </ToggleButton.Content>
            </ToggleButton>
            <Grid Background="{DynamicResource MainBackgroundColor}" ShowGridLines="False" Width="Auto" Height="Auto" HorizontalAlignment="Stretch">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/> <!-- Main content area -->
                    <ColumnDefinition Width="Auto"/><!-- Space for options button -->
                    <ColumnDefinition Width="Auto"/><!-- Space for close button -->
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <!--
                  TODO:
                    Make this SearchBar TextBox Position itself and still
                    house the Magnifying Glass Character in place,
                    even if that Magnifying Icon changed its Size,
                    it should be positioned relative to the SearchBar.
                    Consider using a Math Solver, will help in making
                    development of these things much easier
                -->
                <TextBox
                    Grid.Column="0"
                    Width="{DynamicResource SearchBarWidth}"
                    Height="{DynamicResource SearchBarHeight}"
                    FontSize="{DynamicResource SearchBarTextBoxFontSize}"
                    VerticalAlignment="Center" HorizontalAlignment="Left"
                    BorderThickness="1"
                    Name="SearchBar"
                    Foreground="{DynamicResource MainForegroundColor}" Background="{DynamicResource MainBackgroundColor}"
                    Padding="3,3,30,0"
                    Margin="5,0,0,0"
                    ToolTip="Press Ctrl-F and type app name to filter application list below. Press Esc to reset the filter">
                </TextBox>
                <TextBlock
                    Grid.Column="0"
                    VerticalAlignment="Center" HorizontalAlignment="Left"
                    FontFamily="Segoe MDL2 Assets"
                    Foreground="{DynamicResource ButtonBackgroundSelectedColor}"
                    FontSize="{DynamicResource IconFontSize}"
                    Margin="180,0,0,0">&#xE721;
                </TextBlock>
                <!--
                  TODO:
                    Make this ClearButton Positioning react to
                    SearchBar Width Value changing, so it'll look correct.
                    Consider using a Math Solver, will help in making
                    development of these things much easier
                -->
                <Button Grid.Column="0"
                    VerticalAlignment="Center" HorizontalAlignment="Left"
                    Name="SearchBarClearButton"
                    Style="{StaticResource SearchBarClearButtonStyle}"
                    Margin="210,0,0,0" Visibility="Collapsed">
                </Button>

                <ProgressBar
                    Grid.Column="1"
                    Minimum="0"
                    Maximum="100"
                    Width="250"
                    Height="{DynamicResource SearchBarHeight}"
                    Foreground="{DynamicResource ProgressBarForegroundColor}" Background="{DynamicResource ProgressBarBackgroundColor}" BorderBrush="{DynamicResource ProgressBarForegroundColor}"
                    Visibility="Collapsed"
                    VerticalAlignment="Center" HorizontalAlignment="Left"
                    Margin="2,0,0,0" BorderThickness="1" Padding="6,2,2,2"
                    Name="ProgressBar">
                </ProgressBar>
                <Label
                    Grid.Column="1"
                    Width="250"
                    Height="{DynamicResource SearchBarHeight}"
                    VerticalAlignment="Center" HorizontalAlignment="Left"
                    FontSize="{DynamicResource SearchBarTextBoxFontSize}"
                    Background="Transparent"
                    Visibility="Collapsed"
                    Margin="2,0,0,0" BorderThickness="0" Padding="6,2,2,2"
                    Name="ProgressBarLabel">
                    <TextBlock
                        TextTrimming="CharacterEllipsis"
                        Background="Transparent"
                        Foreground="{DynamicResource ProgressBarTextColor}">
                    </TextBlock>
                </Label>
                <Button Name="ThemeButton"
                    Style="{StaticResource HoverButtonStyle}"
                    Grid.Column="2" BorderBrush="Transparent"
                    Background="{DynamicResource MainBackgroundColor}"
                    Foreground="{DynamicResource MainForegroundColor}"
                    FontSize="{DynamicResource SettingsIconFontSize}"
                    Width="{DynamicResource IconButtonSize}" Height="{DynamicResource IconButtonSize}"
                    HorizontalAlignment="Right" VerticalAlignment="Top"
                    Margin="0,5,5,0"
                    FontFamily="Segoe MDL2 Assets"
                    Content="N/A"
                    ToolTip="Change the Winutil UI Theme"
                />
                <Popup Grid.Column="2" Name="ThemePopup"
                    IsOpen="False"
                    PlacementTarget="{Binding ElementName=ThemeButton}" Placement="Bottom"
                    HorizontalAlignment="Right" VerticalAlignment="Top">
                    <Border Background="{DynamicResource MainBackgroundColor}" BorderBrush="{DynamicResource MainForegroundColor}" BorderThickness="1" CornerRadius="0" Margin="0">
                        <StackPanel Background="{DynamicResource MainBackgroundColor}" HorizontalAlignment="Stretch" VerticalAlignment="Stretch">
                            <MenuItem FontSize="{DynamicResource ButtonFontSize}" Header="Auto" Name="AutoThemeMenuItem" Foreground="{DynamicResource MainForegroundColor}">
                                <MenuItem.ToolTip>
                                    <ToolTip Content="Follow the Windows Theme"/>
                                </MenuItem.ToolTip>
                            </MenuItem>
                            <MenuItem FontSize="{DynamicResource ButtonFontSize}" Header="Dark" Name="DarkThemeMenuItem" Foreground="{DynamicResource MainForegroundColor}">
                                <MenuItem.ToolTip>
                                    <ToolTip Content="Use Dark Theme"/>
                                </MenuItem.ToolTip>
                            </MenuItem>
                            <MenuItem FontSize="{DynamicResource ButtonFontSize}" Header="Light" Name="LightThemeMenuItem" Foreground="{DynamicResource MainForegroundColor}">
                                <MenuItem.ToolTip>
                                    <ToolTip Content="Use Light Theme"/>
                                </MenuItem.ToolTip>
                            </MenuItem>
                        </StackPanel>
                    </Border>
                </Popup>


                <Button Name="SettingsButton"
                    Style="{StaticResource HoverButtonStyle}"
                    Grid.Column="3" BorderBrush="Transparent"
                    Background="{DynamicResource MainBackgroundColor}"
                    Foreground="{DynamicResource MainForegroundColor}"
                    FontSize="{DynamicResource SettingsIconFontSize}"
                    Width="{DynamicResource IconButtonSize}" Height="{DynamicResource IconButtonSize}"
                    HorizontalAlignment="Right" VerticalAlignment="Top"
                    Margin="5,5,5,0"
                    FontFamily="Segoe MDL2 Assets"
                    Content="&#xE713;"/>
                <Popup Grid.Column="3" Name="SettingsPopup"
                    IsOpen="False"
                    PlacementTarget="{Binding ElementName=SettingsButton}" Placement="Bottom"
                    HorizontalAlignment="Right" VerticalAlignment="Top">
                    <Border Background="{DynamicResource MainBackgroundColor}" BorderBrush="{DynamicResource MainForegroundColor}" BorderThickness="1" CornerRadius="0" Margin="0">
                        <StackPanel Background="{DynamicResource MainBackgroundColor}" HorizontalAlignment="Stretch" VerticalAlignment="Stretch">
                            <MenuItem FontSize="{DynamicResource ButtonFontSize}" Header="Import" Name="ImportMenuItem" Foreground="{DynamicResource MainForegroundColor}">
                                <MenuItem.ToolTip>
                                    <ToolTip Content="Import Configuration from exported file."/>
                                </MenuItem.ToolTip>
                            </MenuItem>
                            <MenuItem FontSize="{DynamicResource ButtonFontSize}" Header="Export" Name="ExportMenuItem" Foreground="{DynamicResource MainForegroundColor}">
                                <MenuItem.ToolTip>
                                    <ToolTip Content="Export Selected Elements and copy execution command to clipboard."/>
                                </MenuItem.ToolTip>
                            </MenuItem>
                            <Separator/>
                            <MenuItem FontSize="{DynamicResource ButtonFontSize}" Header="About" Name="AboutMenuItem" Foreground="{DynamicResource MainForegroundColor}"/>
                            <MenuItem FontSize="{DynamicResource ButtonFontSize}" Header="Sponsors" Name="SponsorMenuItem" Foreground="{DynamicResource MainForegroundColor}"/>
                        </StackPanel>
                    </Border>
                </Popup>

            <Button
                Grid.Column="4"
                Content="&#xD7;" BorderThickness="0"
                BorderBrush="Transparent"
                Background="{DynamicResource MainBackgroundColor}"
                Width="{DynamicResource IconButtonSize}" Height="{DynamicResource IconButtonSize}"
                HorizontalAlignment="Right" VerticalAlignment="Top"
                Margin="0,5,5,0"
                FontFamily="{DynamicResource FontFamily}"
                Foreground="{DynamicResource MainForegroundColor}" FontSize="{DynamicResource CloseIconFontSize}" Name="WPFCloseButton" />
            </Grid>

        </DockPanel>

        <TabControl Name="WPFTabNav" Background="Transparent" Width="Auto" Height="Auto" BorderBrush="Transparent" BorderThickness="0" Grid.Row="1" Grid.Column="0" Padding="-1">
            <TabItem Header="Install" Visibility="Collapsed" Name="WPFTab1">
                <Grid Background="Transparent" >

                    <Grid.RowDefinitions>
                        <RowDefinition Height="45px"/>
                        <RowDefinition Height="0.95*"/>
                    </Grid.RowDefinitions>
                    <StackPanel Background="{DynamicResource MainBackgroundColor}" Orientation="Horizontal" Grid.Row="0" HorizontalAlignment="Left" VerticalAlignment="Top" Grid.Column="0" Grid.ColumnSpan="3" Margin="{DynamicResource TabContentMargin}">
                        <Button Name="WPFInstall" Content=" Install/Upgrade Selected" Margin="2" />
                        <Button Name="WPFInstallUpgrade" Content=" Upgrade All" Margin="2"/>
                        <Button Name="WPFUninstall" Content=" Uninstall Selected" Margin="2"/>
                        <Button Name="WPFGetInstalled" Content=" Get Installed" Margin="2"/>
                        <Button Name="WPFClearInstallSelection" Content=" Clear Selection" Margin="2"/>
                        <CheckBox Name="WPFpreferChocolatey" VerticalAlignment="Center" VerticalContentAlignment="Center" IsChecked="True">
                            <TextBlock Text="Prefer Chocolatey" ToolTip="Prefers Chocolatey as Download Engine instead of Winget" VerticalAlignment="Center" />
                        </CheckBox>
                    </StackPanel>

                    <ScrollViewer x:Name="scrollViewer" Grid.Row="1" Grid.Column="0" Margin="{DynamicResource TabContentMargin}" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                                BorderBrush="Transparent" BorderThickness="0" HorizontalAlignment="Stretch" VerticalAlignment="Stretch">
                        <Grid Name="appspanel" HorizontalAlignment="Stretch" VerticalAlignment="Stretch">
                        </Grid>
                    </ScrollViewer>

                    <Rectangle Grid.Row="1" Grid.Column="0" Width="22" Height="22" Fill="{DynamicResource MainBackgroundColor}" HorizontalAlignment="Right" VerticalAlignment="Bottom" Style="{StaticResource ScrollVisibilityRectangle}"/>

                </Grid>
            </TabItem>
            <TabItem Header="Tweaks" Visibility="Collapsed" Name="WPFTab2">
                <Grid>
                    <!-- Main content area with a ScrollViewer -->
                    <Grid.RowDefinitions>
                        <RowDefinition Height="*" />
                        <RowDefinition Height="Auto" />
                    </Grid.RowDefinitions>

                    <ScrollViewer VerticalScrollBarVisibility="Auto" Grid.Row="0" Margin="{DynamicResource TabContentMargin}">
                        <Grid Background="Transparent">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="45px"/>
                                <RowDefinition Height="*"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>

                            <StackPanel Background="{DynamicResource MainBackgroundColor}" Orientation="Horizontal" HorizontalAlignment="Left" Grid.Row="0" Grid.Column="0" Grid.ColumnSpan="2" Margin="5">
                                <Label Content="Recommended Selections:" FontSize="{DynamicResource FontSize}" VerticalAlignment="Center" Margin="2"/>
                                <Button Name="WPFstandard" Content=" Standard " Margin="2"/>
                                <Button Name="WPFminimal" Content=" Minimal " Margin="2"/>
                                <Button Name="WPFClearTweaksSelection" Content=" Clear " Margin="2"/>
                                <Button Name="WPFGetInstalledTweaks" Content=" Get Installed " Margin="2"/>
                            </StackPanel>

                            <Grid Name="tweakspanel" Grid.Row="1">
                                <!-- Your tweakspanel content goes here -->
                            </Grid>

                            <Border Grid.ColumnSpan="2" Grid.Row="2" Grid.Column="0" Style="{StaticResource BorderStyle}">
                                <StackPanel Background="{DynamicResource MainBackgroundColor}" Orientation="Horizontal" HorizontalAlignment="Left">
                                    <TextBlock Padding="10">
                                        Note: Hover over items to get a better description. Please be careful as many of these tweaks will heavily modify your system.
                                        <LineBreak/>Recommended selections are for normal users and if you are unsure do NOT check anything else!
                                    </TextBlock>
                                </StackPanel>
                            </Border>
                        </Grid>
                    </ScrollViewer>
                    <Border Grid.Row="1" Background="{DynamicResource MainBackgroundColor}" BorderBrush="{DynamicResource BorderColor}" BorderThickness="1" CornerRadius="5" HorizontalAlignment="Stretch" Padding="10">
                        <StackPanel Orientation="Horizontal" HorizontalAlignment="Left" VerticalAlignment="Center" Grid.Column="0">
                            <Button Name="WPFTweaksbutton" Content="Run Tweaks" Margin="5"/>
                            <Button Name="WPFUndoall" Content="Undo Selected Tweaks" Margin="5"/>
                        </StackPanel>
                    </Border>
                </Grid>
            </TabItem>
            <TabItem Header="Config" Visibility="Collapsed" Name="WPFTab3">
                <ScrollViewer VerticalScrollBarVisibility="Auto" Margin="{DynamicResource TabContentMargin}">
                    <Grid Name="featurespanel" Grid.Row="1" Background="Transparent">
                    </Grid>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="Updates" Visibility="Collapsed" Name="WPFTab4">
                <ScrollViewer VerticalScrollBarVisibility="Auto" Margin="{DynamicResource TabContentMargin}">
                    <Grid Background="Transparent">
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>  <!-- Row for the 3 columns -->
                            <RowDefinition Height="Auto"/>  <!-- Row for Windows Version -->
                        </Grid.RowDefinitions>

                        <!-- Three columns container -->
                        <Grid Grid.Row="0">
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>

                            <!-- Default Settings -->
                            <Border Grid.Column="0" Style="{StaticResource BorderStyle}">
                                <StackPanel>
                                    <Button Name="WPFFixesUpdate"
                                            FontSize="{DynamicResource ConfigTabButtonFontSize}"
                                            Content="Default Settings"
                                            Margin="10,5"
                                            Padding="10"/>
                                    <TextBlock Margin="10"
                                             TextWrapping="Wrap"
                                             Foreground="{DynamicResource MainForegroundColor}">
                                        <Run FontWeight="Bold">Default Windows Update Configuration</Run>
                                        <LineBreak/>
                                         - No modifications to Windows defaults
                                        <LineBreak/>
                                         - Removes any custom update settings
                                        <LineBreak/><LineBreak/>
                                        <Run FontStyle="Italic" FontSize="11">Note: This resets your Windows Update settings to default out of the box settings. It removes ANY policy or customization that has been done to Windows Update.</Run>
                                    </TextBlock>
                                </StackPanel>
                            </Border>

                            <!-- Security Settings -->
                            <Border Grid.Column="1" Style="{StaticResource BorderStyle}">
                                <StackPanel>
                                    <Button Name="WPFUpdatessecurity"
                                            FontSize="{DynamicResource ConfigTabButtonFontSize}"
                                            Content="Security Settings"
                                            Margin="10,5"
                                            Padding="10"/>
                                    <TextBlock Margin="10"
                                             TextWrapping="Wrap"
                                             Foreground="{DynamicResource MainForegroundColor}">
                                        <Run FontWeight="Bold">Balanced Security Configuration</Run>
                                        <LineBreak/>
                                         - Feature updates delayed by 2 years
                                        <LineBreak/>
                                         - Security updates installed after 4 days
                                        <LineBreak/><LineBreak/>
                                        <Run FontWeight="SemiBold">Feature Updates:</Run> New features and potential bugs
                                        <LineBreak/>
                                        <Run FontWeight="SemiBold">Security Updates:</Run> Critical security patches
                                    <LineBreak/><LineBreak/>
                                    <Run FontStyle="Italic" FontSize="11">Note: This only applies to Pro systems that can use group policy.</Run>
                                    </TextBlock>
                                </StackPanel>
                            </Border>

                            <!-- Disable Updates -->
                            <Border Grid.Column="2" Style="{StaticResource BorderStyle}">
                                <StackPanel>
                                    <Button Name="WPFUpdatesdisable"
                                            FontSize="{DynamicResource ConfigTabButtonFontSize}"
                                            Content="Disable All Updates"
                                            Foreground="Red"
                                            Margin="10,5"
                                            Padding="10"/>
                                    <TextBlock Margin="10"
                                             TextWrapping="Wrap"
                                             Foreground="{DynamicResource MainForegroundColor}">
                                        <Run FontWeight="Bold" Foreground="Red">!! Not Recommended !!</Run>
                                        <LineBreak/>
                                         - Disables ALL Windows Updates
                                        <LineBreak/>
                                         - Increases security risks
                                        <LineBreak/>
                                         - Only use for isolated systems
                                        <LineBreak/><LineBreak/>
                                        <Run FontStyle="Italic" FontSize="11">Warning: Your system will be vulnerable without security updates.</Run>
                                    </TextBlock>
                                </StackPanel>
                            </Border>
                        </Grid>

                        <!-- Future Implementation: Add Windows Version to updates panel -->
                        <Grid Name="updatespanel" Grid.Row="1" Background="Transparent">
                        </Grid>
                    </Grid>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="MicroWin" Visibility="Collapsed" Name="WPFTab5">
                <ScrollViewer VerticalScrollBarVisibility="Auto" Margin="{DynamicResource TabContentMargin}">
                <Grid Width="Auto" Height="Auto">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="3*"/>
                    </Grid.ColumnDefinitions>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="*" />
                    </Grid.RowDefinitions>
                    <Border Grid.Row="0" Grid.Column="0"
                        Style="{StaticResource BorderStyle}"
                        VerticalAlignment="Stretch"
                        HorizontalAlignment="Stretch">
                    <StackPanel Name="MicrowinMain" Background="{DynamicResource MainBackgroundColor}" SnapsToDevicePixels="True" Grid.Column="0" Grid.Row="0">
                        <StackPanel Background="Transparent" SnapsToDevicePixels="True" Margin="1">
                            <CheckBox x:Name="WPFMicrowinDownloadFromGitHub" Content="Download oscdimg.exe from CTT Github repo" IsChecked="True" Margin="{DynamicResource MicrowinCheckBoxMargin}" />
                            <TextBlock Margin="5" Padding="1" TextWrapping="Wrap" Foreground="{DynamicResource ComboBoxForegroundColor}">
                                Choose a Windows ISO file that you've downloaded <LineBreak/>
                                Check the status in the console
                            </TextBlock>
                            <Rectangle Fill="{DynamicResource MainForegroundColor}" Height="2" HorizontalAlignment="Stretch" Margin="0,10,0,10"/>
                            <TextBlock Margin="5" Padding="1" TextWrapping="Wrap" Foreground="{DynamicResource ComboBoxForegroundColor}" ToolTip="Scratch directories act as a custom destination for image files"><Bold>Scratch directory settings (optional)</Bold></TextBlock>
                            <CheckBox x:Name="WPFMicrowinISOScratchDir" Content="Use ISO directory for ScratchDir " IsChecked="False" Margin="{DynamicResource MicrowinCheckBoxMargin}"
                                ToolTip="Check this to use the path of the ISO file you specify as a scratch directory" />
                            <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*" /> <!-- Takes the remaining space -->
                                <ColumnDefinition Width="30" /> <!-- Fixed width for Button -->
                            </Grid.ColumnDefinitions>
                                <TextBox Name="MicrowinScratchDirBox" Background="Transparent" BorderBrush="{DynamicResource MainForegroundColor}"
                                        Text="Scratch"
                                        Margin="2"
                                        IsReadOnly="False"
                                        ToolTip="Specify an alternate path for the scratch directory"
                                        Grid.Column="0"
                                        VerticalAlignment="Center"
                                        Foreground="{DynamicResource LabelboxForegroundColor}">
                                </TextBox>
                                <Button Name="MicrowinScratchDirBT"
                                    Width="Auto"
                                    Height="Auto"
                                    Grid.Column="1"
                                    Margin="2"
                                    Padding="1"  VerticalAlignment="Center">
                                    <Button.Content>
                                    ...
                                    </Button.Content>
                                </Button>
                            </Grid>
                            <Rectangle Fill="{DynamicResource MainForegroundColor}" Height="2" HorizontalAlignment="Stretch" Margin="0,10,0,10"/>
                            <TextBox Name="MicrowinFinalIsoLocation" Background="Transparent" BorderBrush="{DynamicResource MainForegroundColor}"
                                Text="ISO location will be printed here"
                                Margin="2"
                                IsReadOnly="True"
                                TextWrapping="Wrap"
                                Foreground="{DynamicResource LabelboxForegroundColor}"
                            />
                            <RadioButton x:Name="ISOmanual" Content="Select your own ISO" GroupName="Options" Margin="0,10,0,0" IsChecked="True"/>
                            <RadioButton x:Name="ISOdownloader" Content="Get newest ISO automatically" GroupName="Options" Margin="0,5,0,5"/>
                            <ComboBox x:Name="ISORelease" Visibility="Collapsed"/>
                            <ComboBox x:Name="ISOLanguage" Visibility="Collapsed"/>
                            <Button Name="WPFGetIso" Margin="2" Padding="15">
                                <Button.Content>
                                    <TextBlock Background="Transparent" Foreground="{DynamicResource ButtonForegroundColor}">
                                        Get Windows <Underline>I</Underline>SO
                                    </TextBlock>
                                </Button.Content>
                            </Button>
                        </StackPanel>
                        <!-- Visibility="Hidden" -->
                        <StackPanel Name="MicrowinOptionsPanel" HorizontalAlignment="Left" SnapsToDevicePixels="True" Margin="1" Visibility="Hidden">
                            <TextBlock Margin="6" Padding="1" TextWrapping="Wrap">Choose Windows SKU</TextBlock>
                            <ComboBox x:Name = "MicrowinWindowsFlavors" Margin="1" />
                            <Rectangle Fill="{DynamicResource MainForegroundColor}" Height="2" HorizontalAlignment="Stretch" Margin="0,10,0,10"/>
                            <CheckBox Name="MicrowinInjectDrivers" Content="Inject drivers (I KNOW WHAT I'M DOING)" Margin="{DynamicResource MicrowinCheckBoxMargin}" IsChecked="False" ToolTip="Path to unpacked drivers all sys and inf files for devices that need drivers"/>
                            <TextBox Name="MicrowinDriverLocation" Background="Transparent" BorderThickness="1" BorderBrush="{DynamicResource MainForegroundColor}"
                                Margin="6"
                                Text=""
                                IsReadOnly="False"
                                TextWrapping="Wrap"
                                Foreground="{DynamicResource LabelboxForegroundColor}"
                                ToolTip="Path to unpacked drivers all sys and inf files for devices that need drivers"
                            />
                            <CheckBox Name="MicrowinImportDrivers" Content="Import drivers from current system" Margin="{DynamicResource MicrowinCheckBoxMargin}" IsChecked="False" ToolTip="Export all third-party drivers from your system and inject them to the MicroWin image"/>
                            <CheckBox Name="MicrowinCopyVirtIO" Content="Include VirtIO drivers" Margin="{DynamicResource MicrowinCheckBoxMargin}" IsChecked="False" ToolTip="Copy VirtIO Guest Tools drivers to your ISO file. Check this only if you want to use it on QEMU/Proxmox VE"/>
                            <Rectangle Fill="{DynamicResource MainForegroundColor}" Height="2" HorizontalAlignment="Stretch" Margin="0,10,0,10"/>
                            <CheckBox Name="WPFMicrowinCopyToUsb" Content="Copy to Ventoy" Margin="{DynamicResource MicrowinCheckBoxMargin}" IsChecked="False" ToolTip="Copy to USB disk with a label Ventoy"/>
                            <Rectangle Fill="{DynamicResource MainForegroundColor}" Height="2" HorizontalAlignment="Stretch" Margin="0,10,0,10"/>
                            <TextBlock Margin="6" Padding="1" TextWrapping="Wrap"><Bold>Custom user settings (leave empty for default user)</Bold></TextBlock>
                            <TextBlock Margin="6" Padding="1" TextWrapping="Wrap">User name (20 characters max.):</TextBlock>
                            <TextBox Name="MicrowinUserName" Background="Transparent" BorderThickness="1" BorderBrush="{DynamicResource MainForegroundColor}"
                                Margin="6"
                                Text=""
                                IsReadOnly="False"
                                TextWrapping="Wrap"
                                Foreground="{DynamicResource LabelboxForegroundColor}"
                                MaxLength="20"
                            />
                            <TextBlock Margin="6" Padding="1" TextWrapping="Wrap">Password (characters will not be shown for your security):</TextBlock>
                            <PasswordBox Name="MicrowinUserPassword" Background="Transparent" BorderThickness="1" BorderBrush="{DynamicResource MainForegroundColor}"
                                Margin="6"
                                PasswordChar="*"
                                Foreground="{DynamicResource LabelboxForegroundColor}"
                            />
                            <Rectangle Fill="{DynamicResource MainForegroundColor}" Height="2" HorizontalAlignment="Stretch" Margin="0,10,0,10"/>
                            <Button Name="WPFMicrowin" Content="Start the process" Margin="2" Padding="15"/>
                        </StackPanel>
                        <StackPanel HorizontalAlignment="Left" SnapsToDevicePixels="True" Margin="1" Visibility="Collapsed">
                            <TextBlock Name="MicrowinIsoDrive" VerticalAlignment="Center"  Margin="1" Padding="1" TextWrapping="WrapWithOverflow" Foreground="{DynamicResource ComboBoxForegroundColor}"/>
                            <TextBlock Name="MicrowinIsoLocation" VerticalAlignment="Center"  Margin="1" Padding="1" TextWrapping="WrapWithOverflow" Foreground="{DynamicResource ComboBoxForegroundColor}"/>
                            <TextBlock Name="MicrowinMountDir" VerticalAlignment="Center"  Margin="1" Padding="1" TextWrapping="WrapWithOverflow" Foreground="{DynamicResource ComboBoxForegroundColor}"/>
                            <TextBlock Name="MicrowinScratchDir" VerticalAlignment="Center"  Margin="1" Padding="1" TextWrapping="WrapWithOverflow" Foreground="{DynamicResource ComboBoxForegroundColor}"/>
                        </StackPanel>
                    </StackPanel>
                    </Border>
                    <Border
                        Style="{StaticResource BorderStyle}"
                        VerticalAlignment="Stretch"
                        HorizontalAlignment="Stretch"
                        Grid.Row="0" Grid.Column="1">
                        <StackPanel HorizontalAlignment="Left" Background="{DynamicResource MainBackgroundColor}" SnapsToDevicePixels="True" Visibility="Visible">

                            <Grid Name = "BusyMessage" Visibility="Collapsed">
                              <TextBlock Name = "BusyText" Text="NBusy" Padding="22,2,1,1" />
                              <TextBlock VerticalAlignment="Center" HorizontalAlignment="Left" FontFamily="Segoe MDL2 Assets"
                                  FontSize="{DynamicResource IconFontSize}" Margin="16,0,0,0">&#xE701;</TextBlock>
                            </Grid>

                            <TextBlock x:Name = "asciiTextBlock"
                                xml:space ="preserve"
                                HorizontalAlignment = "Center"
                                Margin = "0"
                                VerticalAlignment = "Top"
                                Height = "Auto"
                                Width = "Auto"
                                FontSize = "{DynamicResource MicroWinLogoSize}"
                                FontFamily = "Courier New"
                            >
  /\/\  (_)  ___  _ __   ___  / / /\ \ \(_) _ __
 /    \ | | / __|| '__| / _ \ \ \/  \/ /| || '_ \
/ /\/\ \| || (__ | |   | (_) | \  /\  / | || | | |
\/    \/|_| \___||_|    \___/   \/  \/  |_||_| |_|
                            </TextBlock>

                            <TextBlock Margin="15,15,15,0"
                                Padding="8,8,8,0"
                                VerticalAlignment="Center"
                                TextWrapping="WrapWithOverflow"
                                Height = "Auto"
                                Width = "Auto"
                                Foreground="{DynamicResource ComboBoxForegroundColor}">
                                <Bold>MicroWin features:</Bold><LineBreak/>
                                - Remove Telemetry and Tracking <LineBreak/>
                                - Fast Install using either the "User" local account or the account of your choosing <LineBreak/>
                                - No internet requirement for install <LineBreak/>
                                - Apps debloat <LineBreak/>
                                <LineBreak/>
                                <LineBreak/>

                                <Bold>INSTRUCTIONS</Bold> <LineBreak/>
                                - Download a Windows 11 ISO through the following options: <LineBreak/>
                                    <TextBlock Margin="15,0,0,0" Text="- Select your own ISO: Manually download the latest Windows 11 image from " Foreground="{DynamicResource ComboBoxForegroundColor}"/>
                                    <TextBlock Name="Win11DownloadLink" Style="{StaticResource HoverTextBlockStyle}" ToolTip="https://www.microsoft.com/software-download/windows11">Microsoft</TextBlock>. <LineBreak/>
                                    <TextBlock Margin="15,0,0,0" Text="- Get newest ISO automatically: Choose Windows 11 Edition and preferred language." Foreground="{DynamicResource ComboBoxForegroundColor}"/> <LineBreak/>
                                May take several minutes to process the ISO depending on your machine and connection <LineBreak/>
                                - Put it somewhere on the C:\ drive so it is easily accessible <LineBreak/>
                                - Launch WinUtil and MicroWin  <LineBreak/>
                                - Click on the "Select Windows ISO" button and wait for WinUtil to process the image <LineBreak/>
                                It will be processed and unpacked which may take some time <LineBreak/>
                                - Once complete, choose which Windows flavor you want to base your image on <LineBreak/>
                                - Click the "Start Process" button <LineBreak/>
                                The process of creating the Windows image may take some time, please check the console and wait for it to say "Done" <LineBreak/>
                                - Once complete, the target ISO file will be in the directory you have specified <LineBreak/>
                                - Copy this image to your Ventoy USB Stick, boot to this image, gg
                                <LineBreak/>
                                If you are injecting drivers ensure you put all your inf, sys, and dll files for each driver into a separate directory <LineBreak/><LineBreak/>
                                <Bold>Installing VirtIO drivers</Bold><LineBreak/>
                                If you plan on using your ISO on QEMU/Proxmox VE, you can bundle VirtIO drivers with your ISO to automatically install drivers. Simply tick the "Include VirtIO drivers" checkbox before starting the process. Then, follow these instructions:<LineBreak/><LineBreak/>
                                    <TextBlock TextWrapping="WrapWithOverflow" Margin="15,0,0,0" Text="1. Proceed with Setup until you reach the disk selection screen, in which you won't see any drives" Foreground="{DynamicResource ComboBoxForegroundColor}"/><LineBreak/>
                                    <TextBlock TextWrapping="WrapWithOverflow" Margin="15,0,0,0" Text="2. Click &quot;Load Driver&quot; and click Browse" Foreground="{DynamicResource ComboBoxForegroundColor}"/><LineBreak/>
                                    <TextBlock TextWrapping="WrapWithOverflow" Margin="15,0,0,0" Text="3. In the folder selection dialog, point to this path: &quot;D:\VirtIO\vioscsi\w11\amd64&quot; (replace amd64 with ARM64 if you are using Windows on ARM, and &quot;D:&quot; with the drive letter of the ISO)" Foreground="{DynamicResource ComboBoxForegroundColor}"/><LineBreak/>
                                    <TextBlock TextWrapping="WrapWithOverflow" Margin="15,0,0,0" Text="4. Select all drivers that will appear in the list box and click OK" Foreground="{DynamicResource ComboBoxForegroundColor}"/><LineBreak/>
                            </TextBlock>
                            <TextBlock Margin="15,0,15,15"
                                Padding = "1"
                                TextWrapping="WrapWithOverflow"
                                Height = "Auto"
                                Width = "Auto"
                                VerticalAlignment = "Top"
                                Foreground = "{DynamicResource ComboBoxForegroundColor}"
                                xml:space = "preserve"
                            >
<Bold>Driver structure example:</Bold>
     C:\drivers\
          |-- Driver1\
          |   |-- Driver1.inf
          |   |-- Driver1.sys
          |-- Driver2\
          |   |-- Driver2.inf
          |   |-- Driver2.sys
          |-- OtherFiles...
                            </TextBlock>
                            </StackPanel>
                        </Border>
                    </Grid>
                </ScrollViewer>
            </TabItem>
        </TabControl>
    </Grid>
</Window>

'@
# SPDX-License-Identifier: MIT
# Set the maximum number of threads for the RunspacePool to the number of threads on the machine
$maxthreads = [int]$env:NUMBER_OF_PROCESSORS

# Create a new session state for parsing variables into our runspace
$hashVars = New-object System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'sync',$sync,$Null
$InitialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

# Add the variable to the session state
$InitialSessionState.Variables.Add($hashVars)

# Get every private function and add them to the session state
$functions = Get-ChildItem function:\ | Where-Object { $_.Name -imatch 'winutil|Microwin|WPF' }
foreach ($function in $functions) {
    $functionDefinition = Get-Content function:\$($function.name)
    $functionEntry = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $($function.name), $functionDefinition

    $initialSessionState.Commands.Add($functionEntry)
}

# Create the runspace pool
$sync.runspace = [runspacefactory]::CreateRunspacePool(
    1,                      # Minimum thread count
    $maxthreads,            # Maximum thread count
    $InitialSessionState,   # Initial session state
    $Host                   # Machine to create runspaces on
)

# Open the RunspacePool instance
$sync.runspace.Open()

# Create classes for different exceptions

class WingetFailedInstall : Exception {
    [string]$additionalData
    WingetFailedInstall($Message) : base($Message) {}
}

class ChocoFailedInstall : Exception {
    [string]$additionalData
    ChocoFailedInstall($Message) : base($Message) {}
}

class GenericException : Exception {
    [string]$additionalData
    GenericException($Message) : base($Message) {}
}


$inputXML = $inputXML -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window'

[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
[xml]$XAML = $inputXML

# Read the XAML file
$readerOperationSuccessful = $false # There's more cases of failure then success.
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
try {
    $sync["Form"] = [Windows.Markup.XamlReader]::Load( $reader )
    $readerOperationSuccessful = $true
} catch [System.Management.Automation.MethodInvocationException] {
    Write-Host "We ran into a problem with the XAML code.  Check the syntax for this control..." -ForegroundColor Red
    Write-Host $error[0].Exception.Message -ForegroundColor Red

    If ($error[0].Exception.Message -like "*button*") {
        write-Host "Ensure your &lt;button in the `$inputXML does NOT have a Click=ButtonClick property.  PS can't handle this`n`n`n`n" -ForegroundColor Red
    }
} catch {
    Write-Host "Unable to load Windows.Markup.XamlReader. Double-check syntax and ensure .net is installed." -ForegroundColor Red
}

if (-NOT ($readerOperationSuccessful)) {
    Write-Host "Failed to parse xaml content using Windows.Markup.XamlReader's Load Method." -ForegroundColor Red
    Write-Host "Quitting winutil..." -ForegroundColor Red
    $sync.runspace.Dispose()
    $sync.runspace.Close()
    [System.GC]::Collect()
    exit 1
}

# Setup the Window to follow listen for windows Theme Change events and update the winutil theme
# throttle logic needed, because windows seems to send more than one theme change event per change
$lastThemeChangeTime = [datetime]::MinValue
$debounceInterval = [timespan]::FromSeconds(2)
$sync.Form.Add_Loaded({
    $interopHelper = New-Object System.Windows.Interop.WindowInteropHelper $sync.Form
    $hwndSource = [System.Windows.Interop.HwndSource]::FromHwnd($interopHelper.Handle)
    $hwndSource.AddHook({
        param (
            [System.IntPtr]$hwnd,
            [int]$msg,
            [System.IntPtr]$wParam,
            [System.IntPtr]$lParam,
            [ref]$handled
        )
        # Check for the Event WM_SETTINGCHANGE (0x1001A) and validate that Button shows the icon for "Auto" => [char]0xF08C
        if (($msg -eq 0x001A) -and $sync.ThemeButton.Content -eq [char]0xF08C) {
            $currentTime = [datetime]::Now
            if ($currentTime - $lastThemeChangeTime -gt $debounceInterval) {
                Invoke-WinutilThemeChange -theme "Auto"
                $script:lastThemeChangeTime = $currentTime
                $handled = $true
            }
        }
        return 0
    })
})

Invoke-WinutilThemeChange -init $true
# Load the configuration files
#Invoke-WPFUIElements -configVariable $sync.configs.nav -targetGridName "WPFMainGrid"
Invoke-WPFUIElements -configVariable $sync.configs.applications -targetGridName "appspanel" -columncount 5
Invoke-WPFUIElements -configVariable $sync.configs.tweaks -targetGridName "tweakspanel" -columncount 2
Invoke-WPFUIElements -configVariable $sync.configs.feature -targetGridName "featurespanel" -columncount 2
# Future implementation: Add Windows Version to updates panel
#Invoke-WPFUIElements -configVariable $sync.configs.updates -targetGridName "updatespanel" -columncount 1

#===========================================================================
# Store Form Objects In PowerShell
#===========================================================================

$xaml.SelectNodes("//*[@Name]") | ForEach-Object {$sync["$("$($psitem.Name)")"] = $sync["Form"].FindName($psitem.Name)}

#Persist the Chocolatey preference across winutil restarts
$ChocoPreferencePath = "$env:LOCALAPPDATA\winutil\preferChocolatey.ini"
$sync.WPFpreferChocolatey.Add_Checked({New-Item -Path $ChocoPreferencePath -Force })
$sync.WPFpreferChocolatey.Add_Unchecked({Remove-Item $ChocoPreferencePath -Force})
if (Test-Path $ChocoPreferencePath) {
    $sync.WPFpreferChocolatey.IsChecked = $true
}

$sync.keys | ForEach-Object {
    if($sync.$psitem) {
        if($($sync["$psitem"].GetType() | Select-Object -ExpandProperty Name) -eq "ToggleButton") {
            $sync["$psitem"].Add_Click({
                [System.Object]$Sender = $args[0]
                Invoke-WPFButton $Sender.name
            })
        }

        if($($sync["$psitem"].GetType() | Select-Object -ExpandProperty Name) -eq "Button") {
            $sync["$psitem"].Add_Click({
                [System.Object]$Sender = $args[0]
                Invoke-WPFButton $Sender.name
            })
        }

        if ($($sync["$psitem"].GetType() | Select-Object -ExpandProperty Name) -eq "TextBlock") {
            if ($sync["$psitem"].Name.EndsWith("Link")) {
                $sync["$psitem"].Add_MouseUp({
                    [System.Object]$Sender = $args[0]
                    Start-Process $Sender.ToolTip -ErrorAction Stop
                    Write-Debug "Opening: $($Sender.ToolTip)"
                })
            }

        }
    }
}

#===========================================================================
# Setup background config
#===========================================================================

# Load computer information in the background
Invoke-WPFRunspace -ScriptBlock {
    try {
        $oldProgressPreference = $ProgressPreference
        $ProgressPreference = "SilentlyContinue"
        $sync.ConfigLoaded = $False
        $sync.ComputerInfo = Get-ComputerInfo
        $sync.ConfigLoaded = $True
    }
    finally{
        $ProgressPreference = "Continue"
    }

} | Out-Null

#===========================================================================
# Setup and Show the Form
#===========================================================================

# Print the logo
Invoke-WPFFormVariables

# Progress bar in taskbaritem > Set-WinUtilProgressbar
$sync["Form"].TaskbarItemInfo = New-Object System.Windows.Shell.TaskbarItemInfo
Set-WinUtilTaskbaritem -state "None"

# Set the titlebar
$sync["Form"].title = $sync["Form"].title + " " + $sync.version
# Set the commands that will run when the form is closed
$sync["Form"].Add_Closing({
    $sync.runspace.Dispose()
    $sync.runspace.Close()
    [System.GC]::Collect()
})

# Attach the event handler to the Click event
$sync.SearchBarClearButton.Add_Click({
    $sync.SearchBar.Text = ""
    $sync.SearchBarClearButton.Visibility = "Collapsed"
})

# add some shortcuts for people that don't like clicking
$commonKeyEvents = {
    if ($sync.ProcessRunning -eq $true) {
        return
    }

    if ($_.Key -eq "Escape") {
        $sync.SearchBar.SelectAll()
        $sync.SearchBar.Text = ""
        $sync.SearchBarClearButton.Visibility = "Collapsed"
        return
    }

    # don't ask, I know what I'm doing, just go...
    if (($_.Key -eq "Q" -and $_.KeyboardDevice.Modifiers -eq "Ctrl")) {
        $this.Close()
    }
    if ($_.KeyboardDevice.Modifiers -eq "Alt") {
        if ($_.SystemKey -eq "I") {
            Invoke-WPFButton "WPFTab1BT"
        }
        if ($_.SystemKey -eq "T") {
            Invoke-WPFButton "WPFTab2BT"
        }
        if ($_.SystemKey -eq "C") {
            Invoke-WPFButton "WPFTab3BT"
        }
        if ($_.SystemKey -eq "U") {
            Invoke-WPFButton "WPFTab4BT"
        }
        if ($_.SystemKey -eq "M") {
            Invoke-WPFButton "WPFTab5BT"
        }
        if ($_.SystemKey -eq "P") {
            Write-Host "Your Windows Product Key: $((Get-WmiObject -query 'select * from SoftwareLicensingService').OA3xOriginalProductKey)"
        }
    }
    # shortcut for the filter box
    if ($_.Key -eq "F" -and $_.KeyboardDevice.Modifiers -eq "Ctrl") {
        if ($sync.SearchBar.Text -eq "Ctrl-F to filter") {
            $sync.SearchBar.SelectAll()
            $sync.SearchBar.Text = ""
        }
        $sync.SearchBar.Focus()
    }
}

$sync["Form"].Add_PreViewKeyDown($commonKeyEvents)

$sync["Form"].Add_MouseLeftButtonDown({
    Invoke-WPFPopup -Action "Hide" -Popups @("Settings", "Theme")
    $sync["Form"].DragMove()
})

$sync["Form"].Add_MouseDoubleClick({
    if ($_.OriginalSource -is [System.Windows.Controls.Grid] -or
        $_.OriginalSource -is [System.Windows.Controls.StackPanel]) {
            if ($sync["Form"].WindowState -eq [Windows.WindowState]::Normal) {
                $sync["Form"].WindowState = [Windows.WindowState]::Maximized
            }
            else{
                $sync["Form"].WindowState = [Windows.WindowState]::Normal
            }
    }
})

$sync["Form"].Add_Deactivated({
    Write-Debug "WinUtil lost focus"
    Invoke-WPFPopup -Action "Hide" -Popups @("Settings", "Theme")
})

$sync["Form"].Add_ContentRendered({

    try {
        [void][Window]
    } catch {
Add-Type @"
        using System;
        using System.Runtime.InteropServices;
        public class Window {
            [DllImport("user32.dll")]
            public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

            [DllImport("user32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

            [DllImport("user32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool MoveWindow(IntPtr handle, int x, int y, int width, int height, bool redraw);

            [DllImport("user32.dll")]
            public static extern int GetSystemMetrics(int nIndex);
        };
        public struct RECT {
            public int Left;   // x position of upper-left corner
            public int Top;    // y position of upper-left corner
            public int Right;  // x position of lower-right corner
            public int Bottom; // y position of lower-right corner
        }
"@
    }

   foreach ($proc in (Get-Process).where{ $_.MainWindowTitle -and $_.MainWindowTitle -like "*titus*" }) {
        # Check if the process's MainWindowHandle is valid
        if ($proc.MainWindowHandle -ne [System.IntPtr]::Zero) {
            Write-Debug "MainWindowHandle: $($proc.Id) $($proc.MainWindowTitle) $($proc.MainWindowHandle)"
            $windowHandle = $proc.MainWindowHandle
        } else {
            Write-Warning "Process found, but no MainWindowHandle: $($proc.Id) $($proc.MainWindowTitle)"

        }
    }

    $rect = New-Object RECT
    [Window]::GetWindowRect($windowHandle, [ref]$rect)
    $width  = $rect.Right  - $rect.Left
    $height = $rect.Bottom - $rect.Top

    Write-Debug "UpperLeft:$($rect.Left),$($rect.Top) LowerBottom:$($rect.Right),$($rect.Bottom). Width:$($width) Height:$($height)"

    # Load the Windows Forms assembly
    Add-Type -AssemblyName System.Windows.Forms
    $primaryScreen = [System.Windows.Forms.Screen]::PrimaryScreen
    # Check if the primary screen is found
    if ($primaryScreen) {
        # Extract screen width and height for the primary monitor
        $screenWidth = $primaryScreen.Bounds.Width
        $screenHeight = $primaryScreen.Bounds.Height

        # Print the screen size
        Write-Debug "Primary Monitor Width: $screenWidth pixels"
        Write-Debug "Primary Monitor Height: $screenHeight pixels"

        # Compare with the primary monitor size
        if ($width -gt $screenWidth -or $height -gt $screenHeight) {
            Write-Debug "The specified width and/or height is greater than the primary monitor size."
            [void][Window]::MoveWindow($windowHandle, 0, 0, $screenWidth, $screenHeight, $True)
        } else {
            Write-Debug "The specified width and height are within the primary monitor size limits."
        }
    } else {
        Write-Debug "Unable to retrieve information about the primary monitor."
    }

    Invoke-WPFTab "WPFTab1BT"
    $sync["Form"].Focus()

    # maybe this is not the best place to load and execute config file?
    # maybe community can help?
    if ($PARAM_CONFIG) {
        Invoke-WPFImpex -type "import" -Config $PARAM_CONFIG
        if ($PARAM_RUN) {
            while ($sync.ProcessRunning) {
                Start-Sleep -Seconds 5
            }
            Start-Sleep -Seconds 5

            Write-Host "Applying tweaks..."
            Invoke-WPFtweaksbutton
            while ($sync.ProcessRunning) {
                Start-Sleep -Seconds 5
            }
            Start-Sleep -Seconds 5

            Write-Host "Installing features..."
            Invoke-WPFFeatureInstall
            while ($sync.ProcessRunning) {
                Start-Sleep -Seconds 5
            }

            Start-Sleep -Seconds 5
            Write-Host "Installing applications..."
            while ($sync.ProcessRunning) {
                Start-Sleep -Seconds 1
            }
            Invoke-WPFInstall
            Start-Sleep -Seconds 5

            Write-Host "Done."
        }
    }

})

# Add event handlers for the RadioButtons
$sync["ISOdownloader"].add_Checked({
    $sync["ISORelease"].Visibility = [System.Windows.Visibility]::Visible
    $sync["ISOLanguage"].Visibility = [System.Windows.Visibility]::Visible
})

$sync["ISOmanual"].add_Checked({
    $sync["ISORelease"].Visibility = [System.Windows.Visibility]::Collapsed
    $sync["ISOLanguage"].Visibility = [System.Windows.Visibility]::Collapsed
})

$sync["ISORelease"].Items.Add("24H2") | Out-Null
$sync["ISORelease"].SelectedItem = "24H2"

$sync["ISOLanguage"].Items.Add("System Language ($(Microwin-GetLangFromCulture -langName $((Get-Culture).Name)))") | Out-Null
if ($currentCulture -ne "English International") {
    $sync["ISOLanguage"].Items.Add("English International") | Out-Null
}
if ($currentCulture -ne "English") {
    $sync["ISOLanguage"].Items.Add("English") | Out-Null
}
if ($sync["ISOLanguage"].Items.Count -eq 1) {
    $sync["ISOLanguage"].IsEnabled = $false
}
$sync["ISOLanguage"].SelectedIndex = 0


# Load Checkboxes and Labels outside of the Filter function only once on startup for performance reasons
$filter = Get-WinUtilVariables -Type CheckBox
$CheckBoxes = ($sync.GetEnumerator()).where{ $psitem.Key -in $filter }

$filter = Get-WinUtilVariables -Type Label
$labels = @{}
($sync.GetEnumerator()).where{$PSItem.Key -in $filter} | ForEach-Object {$labels[$_.Key] = $_.Value}

$allCategories = $checkBoxes.Name | ForEach-Object {$sync.configs.applications.$_} | Select-Object  -Unique -ExpandProperty category

$sync["SearchBar"].Add_TextChanged({
    if ($sync.SearchBar.Text -ne "") {
        $sync.SearchBarClearButton.Visibility = "Visible"
    } else {
        $sync.SearchBarClearButton.Visibility = "Collapsed"
    }

    $activeApplications = @()

    $textToSearch = $sync.SearchBar.Text.ToLower()

    foreach ($CheckBox in $CheckBoxes) {
        # Skip if the checkbox is null, it doesn't have content or it is the prefer Choco checkbox
        if ($CheckBox -eq $null -or $CheckBox.Value -eq $null -or $CheckBox.Value.Content -eq $null -or $CheckBox.Name -eq "WPFpreferChocolatey") {
            continue
        }

        $checkBoxName = $CheckBox.Key
        $textBlockName = $checkBoxName + "Link"

        # Retrieve the corresponding text block based on the generated name
        $textBlock = $sync[$textBlockName]

        if ($CheckBox.Value.Content.ToString().ToLower().Contains($textToSearch)) {
            $CheckBox.Value.Visibility = "Visible"
            $activeApplications += $sync.configs.applications.$checkboxName
            # Set the corresponding text block visibility
            if ($textBlock -ne $null -and $textBlock -is [System.Windows.Controls.TextBlock]) {
                $textBlock.Visibility = "Visible"
            }
        } else {
            $CheckBox.Value.Visibility = "Collapsed"
            # Set the corresponding text block visibility
            if ($textBlock -ne $null -and $textBlock -is [System.Windows.Controls.TextBlock]) {
                $textBlock.Visibility = "Collapsed"
            }
        }
    }

    $activeCategories = $activeApplications | Select-Object -ExpandProperty category -Unique

    foreach ($category in $activeCategories) {
        $sync[$category].Visibility = "Visible"
    }
    if ($activeCategories) {
        $inactiveCategories = Compare-Object -ReferenceObject $allCategories -DifferenceObject $activeCategories -PassThru
    } else {
        $inactiveCategories = $allCategories
    }
    foreach ($category in $inactiveCategories) {
        $sync[$category].Visibility = "Collapsed"
    }
})

$sync["Form"].Add_Loaded({
    param($e)
    $sync["Form"].MaxWidth = [Double]::PositiveInfinity
    $sync["Form"].MaxHeight = [Double]::PositiveInfinity
})

# ahmed
# Embedded Base64 string of the tutico.png image
$base64String = @"
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
"@

# Decode the Base64 string into a byte array
$imageBytes = [Convert]::FromBase64String($base64String)

# Create a MemoryStream from the byte array
$stream = New-Object System.IO.MemoryStream($imageBytes, $false)

# Load the image from the MemoryStream
$bitmap = New-Object System.Windows.Media.Imaging.BitmapImage
$bitmap.BeginInit()
$bitmap.StreamSource = $stream
$bitmap.EndInit()

# Create an Image control and set its source
$image = New-Object System.Windows.Controls.Image
$image.Source = $bitmap

# Add the image to the NavLogoPanel
$NavLogoPanel = $sync["Form"].FindName("NavLogoPanel")
$NavLogoPanel.Children.Add($image) | Out-Null

# Initialize the hashtable
$winutildir = @{}

# Set the path for the winutil directory
$winutildir["path"] = "$env:LOCALAPPDATA\winutil\"
[System.IO.Directory]::CreateDirectory($winutildir["path"]) | Out-Null

$winutildir["logo.ico"] = $winutildir["path"] + "cttlogo.ico"

if (Test-Path $winutildir["logo.ico"]) {
    $sync["logorender"] = $winutildir["logo.ico"]
} else {
    $sync["logorender"] = (Invoke-WinUtilAssets -Type "Logo" -Size 90 -Render)
}
$sync["checkmarkrender"] = (Invoke-WinUtilAssets -Type "checkmark" -Size 512 -Render)
$sync["warningrender"] = (Invoke-WinUtilAssets -Type "warning" -Size 512 -Render)

Set-WinUtilTaskbaritem -overlay "logo"

$sync["Form"].Add_Activated({
    Set-WinUtilTaskbaritem -overlay "logo"
})

$sync["ThemeButton"].Add_Click({
    Write-Debug "ThemeButton clicked"
    Invoke-WPFPopup -PopupActionTable @{ "Settings" = "Hide"; "Theme" = "Toggle" }
    $_.Handled = $false
})
$sync["AutoThemeMenuItem"].Add_Click({
    Write-Debug "About clicked"
    Invoke-WPFPopup -Action "Hide" -Popups @("Theme")
    Invoke-WinutilThemeChange -theme "Auto"
    $_.Handled = $false
})
$sync["DarkThemeMenuItem"].Add_Click({
    Write-Debug "Dark Theme clicked"
    Invoke-WPFPopup -Action "Hide" -Popups @("Theme")
    Invoke-WinutilThemeChange -theme "Dark"
    $_.Handled = $false
})
$sync["LightThemeMenuItem"].Add_Click({
    Write-Debug "Light Theme clicked"
    Invoke-WPFPopup -Action "Hide" -Popups @("Theme")
    Invoke-WinutilThemeChange -theme "Light"
    $_.Handled = $false
})


$sync["SettingsButton"].Add_Click({
    Write-Debug "SettingsButton clicked"
    Invoke-WPFPopup -PopupActionTable @{ "Settings" = "Toggle"; "Theme" = "Hide" }
    $_.Handled = $false
})
$sync["ImportMenuItem"].Add_Click({
    Write-Debug "Import clicked"
    Invoke-WPFPopup -Action "Hide" -Popups @("Settings")
    Invoke-WPFImpex -type "import"
    $_.Handled = $false
})
$sync["ExportMenuItem"].Add_Click({
    Write-Debug "Export clicked"
    Invoke-WPFPopup -Action "Hide" -Popups @("Settings")
    Invoke-WPFImpex -type "export"
    $_.Handled = $false
})
$sync["AboutMenuItem"].Add_Click({
    Write-Debug "About clicked"
    Invoke-WPFPopup -Action "Hide" -Popups @("Settings")

    $authorInfo = @"
Author   : <a href="https://github.com/tut-os">@TUT_OS</a>
"@
    Show-CustomDialog -Title "About" -Message $authorInfo
})
$sync["SponsorMenuItem"].Add_Click({
    Write-Debug "Sponsors clicked"
    Invoke-WPFPopup -Action "Hide" -Popups @("Settings")

    $authorInfo = @"
<a href="https://github.com/sponsors/tut-os">Current sponsors for tut-os:</a>
"@
    $authorInfo += "`n"
    try {
        $sponsors = Invoke-WinUtilSponsors
        foreach ($sponsor in $sponsors) {
            $authorInfo += "<a href=`"https://github.com/sponsors/tut-os`">$sponsor</a>`n"
        }
    } catch {
        $authorInfo += "An error occurred while fetching or processing the sponsors: $_`n"
    }
    Show-CustomDialog -Title "Sponsors" -Message $authorInfo -EnableScroll $true
})

$sync["Form"].ShowDialog() | out-null
Stop-Transcript

# List of URLs to open
$urls = @(
    "https://www.youtube.com/@TUT_OS",
    "https://www.youtube.com/@king-tutos"
)

# Function to open a random URL
function Open-RandomUrl {
    $randomUrl = $urls | Get-Random
    Start-Process $randomUrl
}

# Open a random URL when the script starts
Open-RandomUrl

# Wait for the user to press a key to exit
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Open a random URL when the script ends
Open-RandomUrl
