#Requires -RunAsAdministrator

param($strap_git_name, $strap_git_email, $strap_github_username, $strap_github_token)

# # Check to see if we are currently running "as Administrator"
# if (!(Verify-Elevated)) {
#    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
#    $newProcess.Arguments = $myInvocation.MyCommand.Definition;
#    $newProcess.Verb = "runas";
#    [System.Diagnostics.Process]::Start($newProcess);

#    exit
# }
#if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

function Check-Command($cmdname) {
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

function AddToPath {
    param (
        [string]$folder
    )

    Write-Host "Adding $folder to environment variables..." -ForegroundColor Yellow

    $currentEnv = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine).Trim(";");
    $addedEnv = $currentEnv + ";$folder"
    $trimmedEnv = (($addedEnv.Split(';') | Select-Object -Unique) -join ";").Trim(";")
    [Environment]::SetEnvironmentVariable(
        "Path",
        $trimmedEnv,
        [EnvironmentVariableTarget]::Machine)

    #Write-Host "Reloading environment variables..." -ForegroundColor Green
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

function Remove-UWP {
    param (
        [string]$name
    )

    Write-Host "Removing UWP $name..." -ForegroundColor Yellow
    Get-AppxPackage $name | Remove-AppxPackage | Out-Null
    Get-AppxPackage $name | Remove-AppxPackage -AllUsers | Out-Null
    # Get-AppXProvisionedPackage -Online | Where DisplayName -like $name | Remove-AppxProvisionedPackage -Online -AllUsers
}

###############################################################################
### Security and Identity                                                     #
###############################################################################
Write-Host "Configuring System..." -ForegroundColor "Yellow"

# Set Computer Name
# (Get-WmiObject Win32_ComputerSystem).Rename("CHOZO") | Out-Null
# $computerName = Read-Host 'Enter New Computer Name'
# Write-Host "Renaming this computer to: " $computerName  -ForegroundColor Yellow
# Rename-Computer -NewName $computerName

## Set DisplayName for my account. Use only if you are not using a Microsoft Account
#$myIdentity=[System.Security.Principal.WindowsIdentity]::GetCurrent()
#$user = Get-WmiObject Win32_UserAccount | Where {$_.Caption -eq $myIdentity.Name}
#$user.FullName = "Jay Harris"
#$user.Put() | Out-Null
#Remove-Variable user
#Remove-Variable myIdentity

###############################################################################
### Privacy                                                                   #
###############################################################################
Write-Host "Configuring Privacy..." -ForegroundColor "Yellow"

# # General: Don't let apps use advertising ID for experiences across apps: Allow: 1, Disallow: 0
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
# Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Id" -ErrorAction SilentlyContinue

# # General: Disable Application launch tracking: Enable: 1, Disable: 0
# Set-ItemProperty "HKCU:\\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Start-TrackProgs" 0

# # General: Disable SmartScreen Filter for Store Apps: Enable: 1, Disable: 0
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation" 0

# # General: Disable key logging & transmission to Microsoft: Enable: 1, Disable: 0
# # Disabled when Telemetry is set to Basic
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Input")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Input" -Type Folder | Out-Null}
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Input\TIPC" "Enabled" 0

# # General: Opt-out from websites from accessing language list: Opt-in: 0, Opt-out 1
# Set-ItemProperty "HKCU:\Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" 1

# # General: Disable SmartGlass: Enable: 1, Disable: 0
# #Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" "UserAuthPolicy" 0

# # General: Disable SmartGlass over BlueTooth: Enable: 1, Disable: 0
# #Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" "BluetoothPolicy" 0

# # General: Disable suggested content in settings app: Enable: 1, Disable: 0
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338393Enabled" 0
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338394Enabled" 0
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338396Enabled" 0

# # General: Disable tips and suggestions for welcome and what's new
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-310093Enabled" 0

# # General: Disable tips and suggestions when I use windows
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338389Enabled" 0

# # Start Menu: Disable suggested content: Enable: 1, Disable: 0
# #Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338388Enabled" 0

# # Start Menu: Disable search entries
# # if (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Type Folder | Out-Null}
# # Set-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\Explorer" "DisableSearchBoxSuggestions" 1

# # Camera: Don't let apps use camera: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" "Value" "Deny"

# # Microphone: Don't let apps use microphone: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" "Value" "Deny"

# # Notifications: Don't let apps access notifications: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" "Value" "Deny"

# # Speech, Inking, & Typing: Stop "Getting to know me"
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings" -Type Folder | Out-Null}
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" "HasAccepted" 0

# # Account Info: Don't let apps access name, picture, and other account info: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" "Value" "Deny"

# # Contacts: Don't let apps access contacts: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" "Value" "Deny"

# # Calendar: Don't let apps access calendar: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" "Value" "Deny"

# # Call History: Don't let apps make phone calls: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" "Value" "Deny"

# # Call History: Don't let apps access call history: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" "Value" "Deny"

# # Diagnostics: Don't let apps access diagnostics of other apps: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" "Value" "Deny"

# # Documents: Don't let apps access documents: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" "Value" "Deny"

# # Downloads: Don't let apps access downloads: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" "Value" "Deny"

# # Email: Don't let apps read and send email: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" "Value" "Deny"

# # File System: Don't let apps access the file system: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" "Value" "Deny"

# # Location: Don't let apps access the location: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" "Value" "Deny"

# # Messaging: Don't let apps read or send messages (text or MMS): Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" "Value" "Deny"

# # Music Library: Don't let apps access music library: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" "Value" "Deny"

# # Pictures: Don't let apps access pictures: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" "Value" "Deny"

# # Radios: Don't let apps control radios (like Bluetooth): Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" "Value" "Deny"

# # Screenshot: Don't let apps take screenshots: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic" "Value" "Deny"

# # Screenshot Borders: Don't let apps access screenshot border settings: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder" "Value" "Deny"

# # Tasks: Don't let apps access the tasks: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" "Value" "Deny"

# # Other Devices: Don't let apps share and sync with non-explicitly-paired wireless devices over uPnP: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" "Value" "Deny"

# # Videos: Don't let apps access videos: Allow, Deny
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" "Value" "Deny"

# # Feedback: Windows should never ask for my feedback
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf" -Type Folder | Out-Null}
# if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Type Folder | Out-Null}
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" 0

# # Feedback: Telemetry: Send Diagnostic and usage data: Basic: 1, Enhanced: 2, Full: 3
# Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 1
# Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "MaxTelemetryAllowed" 1

###############################################################################
### Devices, Power, and Startup                                               #
###############################################################################
Write-Host "Configuring Devices, Power, and Startup..." -ForegroundColor "Yellow"

# Sound: Disable Startup Sound
# Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableStartupSound" 1
# Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" "DisableStartupSound" 1
# Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EditionOverrides" "UserSetting_DisableStartupSound" 1

# Power: Disable Hibernation
powercfg /hibernate off

# Power: Disable Sleep on AC Power
powercfg /change /standby-timeout-ac 0

# Power: Monitor sleep
powercfg /change /monitor-timeout-ac 20

# SSD: Disable SuperFetch
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnableSuperfetch" 0

# Network: Disable WiFi Sense
#Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" 0

###############################################################################
### Desktop, Explorer, Taskbar, and System Tray                                        #
###############################################################################
Write-Host "Configuring Desktop, Explorer, Taskbar, and System Tray..." -ForegroundColor "Yellow"

# Ensure necessary registry paths
if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Type Folder | Out-Null}
if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState")) {New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Type Folder | Out-Null}
if (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search")) {New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Type Folder | Out-Null}

# Explorer: Show hidden files by default: Show Files: 1, Hide Files: 2
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1

# Explorer: Show file extensions by default
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0

# Explorer: Show path in title bar
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" "FullPath" 1

# Explorer: Avoid creating Thumbs.db files on network volumes
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "DisableThumbnailsOnNetworkFolders" 1

# Taskbar: Hide the Search, Task, Widget, and Chat buttons
# Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "SearchboxTaskbarMode" 0  # Search
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowTaskViewButton" 0 # Task
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarDa" 0 # Widgets
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarMn" 0 # Chat

# Taskbar: Show colors on Taskbar, Start, and SysTray: Disabled: 0, Taskbar, Start, & SysTray: 1, Taskbar Only: 2
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "ColorPrevalence" 1

# Titlebar: Disable theme colors on titlebar
# Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\DWM" "ColorPrevalence" 0

# Recycle Bin: Disable Delete Confirmation Dialog
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "ConfirmFileDelete" 0

# Desktop: Show 'This PC' Icon
$thisPCIconRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$thisPCRegValname = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" 
$item = Get-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -ErrorAction SilentlyContinue 
if ($item) { 
    Set-ItemProperty  -Path $thisPCIconRegPath -name $thisPCRegValname -Value 0  
} 
else { 
    New-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -Value 0 -PropertyType DWORD | Out-Null  
} 

###############################################################################
### Default Windows Applications                                              #
###############################################################################
Write-Host "Configuring Default Windows Applications..." -ForegroundColor "Yellow"

# Uninstall Windows Media Player
Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null

# Prevent "Suggested Applications" from returning
#Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1 -Force
#Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" "DisableCloudOptimizedContent" 1 -Force
#Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" "DisableConsumerAccountStateContent" 1 -Force

# To list all appx packages:
# Get-AppxPackage | Format-Table -Property Name,Version,PackageFullName
$uwpRubbishApps = @(
    "*.AutodeskSketchBook"
    "*.DisneyMagicKingdoms"
    "*.MarchofEmpires"
    "*.SlingTV"
    "*.TikTok"
    "*.Twitter"
    "*549981C3F5F10*"
    "*Microsoft.XboxApp*"
    "*Microsoft.XboxGamingOverlay*"
    "4DF9E0F8.Netflix"
    "AdobeSystemsIncorporated.AdobeCreativeCloudExpress"
    "AmazonVideo.PrimeVideo"
    "Clipchamp.Clipchamp"
    "Disney.37853FC22B2CE"
    "DolbyLaboratories.DolbyAccess"
    "Facebook.Facebook*"
    "Facebook.Instagram*"
    "king.com.*"
    "Microsoft.3DBuilder"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingWeather"
    "Microsoft.GamingApp"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.MicrosoftStickyNotes"
    "Microsoft.MixedReality.Portal"
    "Microsoft.MSPaint"
    "Microsoft.Office.OneNote"
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.Paint"
    "Microsoft.People"
    "Microsoft.PowerAutomateDesktop"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.ToDos"
    "Microsoft.Windows.Photos"
    "Microsoft.WindowsAlarms"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.YourPhone"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "MicrosoftTeams"
    "SpotifyAB.SpotifyMusic"
)

foreach ($uwp in $uwpRubbishApps) {
    Remove-UWP $uwp
}

###############################################################################
### Lock Screen                                                               #
###############################################################################

## Enable Custom Background on the Login / Lock Screen
## Background file: C:\someDirectory\someImage.jpg
## File Size Limit: 256Kb
# Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\Personalization" "LockScreenImage" "C:\someDirectory\someImage.jpg"

###############################################################################
### Accessibility and Ease of Use                                             #
###############################################################################
Write-Host "Configuring Accessibility..." -ForegroundColor "Yellow"

# Turn Off Windows Narrator Hotkey
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Narrator\NoRoam" "WinEnterLaunchEnabled" 0

# Disable "Window Snap" Automatic Window Arrangement
Set-ItemProperty "HKCU:\Control Panel\Desktop" "WindowArrangementActive" 0

# Disable automatic fill to space on Window Snap
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "SnapFill" 0

# Disable showing what can be snapped next to a window
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "SnapAssist" 0

# Disable automatic resize of adjacent windows on snap
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "JointResize" 0

# Disable auto-correct
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\TabletTip\1.7" "EnableAutocorrection" 0

###############################################################################
### Windows Update & Application Updates                                      #
###############################################################################
Write-Host "Configuring Windows Update..." -ForegroundColor "Yellow"

# Disable automatic reboot after install
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" "IsExpedited" 0

# Disable restart required notifications
# Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" "RestartNotificationsAllowed2" 0

# Disable updates over metered connections
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" 0

# Opt-In to Microsoft Update
# Opt-In to Microsoft Update
# $MU = New-Object -ComObject Microsoft.Update.ServiceManager -Strict
# $MU.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"") | Out-Null
# Remove-Variable MU

###############################################################################
### Windows Defender                                                          #
###############################################################################
Write-Host "Configuring Windows Defender..." -ForegroundColor "Yellow"

# Disable Cloud-Based Protection: Enabled Advanced: 2, Enabled Basic: 1, Disabled: 0
# Set-MpPreference -MAPSReporting 0

# Disable automatic sample submission: Prompt: 0, Auto Send Safe: 1, Never: 2, Auto Send All: 3
# Set-MpPreference -SubmitSamplesConsent 2

###############################################################################
### Internet Explorer                                                         #
###############################################################################
Write-Host "Configuring Internet Explorer..." -ForegroundColor "Yellow"

# Set home page to `about:blank` for faster loading
Set-ItemProperty "HKCU:\Software\Microsoft\Internet Explorer\Main" "Start Page" "about:blank"

# Disable 'Default Browser' check: "yes" or "no"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main" "Check_Associations" "no"

# Disable Password Caching [Disable Remember Password]
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "DisablePasswordCaching" 1

###############################################################################
### Disk Cleanup (CleanMgr.exe)                                               #
###############################################################################
Write-Host "Configuring Disk Cleanup..." -ForegroundColor "Yellow"

$diskCleanupRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\"

# Cleanup Files by Group: 0=Disabled, 2=Enabled
Set-ItemProperty $(Join-Path $diskCleanupRegPath "BranchCache"                                  ) "StateFlags6174" 0   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Downloaded Program Files"                     ) "StateFlags6174" 2   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Internet Cache Files"                         ) "StateFlags6174" 2   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Offline Pages Files"                          ) "StateFlags6174" 0   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Old ChkDsk Files"                             ) "StateFlags6174" 2   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Previous Installations"                       ) "StateFlags6174" 0   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Recycle Bin"                                  ) "StateFlags6174" 0   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "RetailDemo Offline Content"                   ) "StateFlags6174" 2   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Service Pack Cleanup"                         ) "StateFlags6174" 0   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Setup Log Files"                              ) "StateFlags6174" 2   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "System error memory dump files"               ) "StateFlags6174" 0   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "System error minidump files"                  ) "StateFlags6174" 0   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Temporary Files"                              ) "StateFlags6174" 2   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Temporary Setup Files"                        ) "StateFlags6174" 2   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Thumbnail Cache"                              ) "StateFlags6174" 2   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Update Cleanup"                               ) "StateFlags6174" 2   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Upgrade Discarded Files"                      ) "StateFlags6174" 0   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "User file versions"                           ) "StateFlags6174" 0   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Windows Defender"                             ) "StateFlags6174" 2   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Windows Error Reporting Archive Files"        ) "StateFlags6174" 0   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Windows Error Reporting Queue Files"          ) "StateFlags6174" 0   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Windows Error Reporting System Archive Files" ) "StateFlags6174" 0   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Windows Error Reporting System Queue Files"   ) "StateFlags6174" 0   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Windows Error Reporting Temp Files"           ) "StateFlags6174" 0   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Windows ESD installation files"               ) "StateFlags6174" 0   -ErrorAction SilentlyContinue
Set-ItemProperty $(Join-Path $diskCleanupRegPath "Windows Upgrade Log Files"                    ) "StateFlags6174" 0   -ErrorAction SilentlyContinue

Remove-Variable diskCleanupRegPath

###############################################################################
### PowerShell Console                                                        #
###############################################################################
Write-Host "Configuring Console..." -ForegroundColor "Yellow"

# Make 'Source Code Pro' an available Console font
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\TrueTypeFont' 000 'Source Code Pro'

# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "Enable Remote Desktop..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name "fDenyTSConnections" -Value 0
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name "UserAuthentication" -Value 1
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

###############################################################################
### Bootstrapping Dependencies                                                #
###############################################################################

if (Check-Command -cmdname 'choco')
{
    choco upgrade chocolatey | Out-Null
}
else
{
    Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

# Enable Developer Mode
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" "AllowDevelopmentWithoutDevLicense" 1

# Bash on Windows
# Enable-WindowsOptionalFeature -Online -All -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null

# Dependencies to continue bootstrapping
# $Apps = @(
#     "git"
# #     "powershell-core"
# )

# foreach ($app in $Apps) {
#     choco install $app -y
# }

choco install git --params "/GitOnlyOnPath /NoAutoCrlf /NoShellIntegration /SChannel /Symlinks /Editor:VisualStudioCode" -y

# Make `refreshenv` available right away, by defining the $env:ChocolateyInstall
# variable and importing the Chocolatey profile module.
# Note: Using `. $PROFILE` instead *may* work, but isn't guaranteed to.
$env:ChocolateyInstall = Convert-Path "$((Get-Command choco).Path)\..\.."   
Import-Module "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
refreshenv

# Setup Git configuration.
Write-Host "Setting up Git for Windows..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
if ($strap_git_name -and !(git config --global user.name))
{
    git config --global user.name "$strap_git_name"
}
if ($strap_git_email -and !(git config --global user.email))
{
    git config --global user.email "$strap_git_email"
}
if ($strap_github_username -and ((git config --global github.user) -ne $strap_github_usernam))
{
    git config --global github.user "$strap_github_username"
}

# Squelch git 2.x warning message when pushing
# if (! (git config push.default))
# {
#   git config --global push.default simple
# }

###############################################################################
### WSL2                                                                      #
###############################################################################

Write-Host "Installing Windows Subsystem for Linux..." -ForegroundColor "Yellow"
# wsl --install
Write-Host "------------------------------------" -ForegroundColor Green
Read-Host -Prompt "Setup is done, Windows needs to restart to continue, press [ENTER] to restart computer."
# Restart-Computer

# # gsudo
# PowerShell -Command "Set-ExecutionPolicy RemoteSigned -scope Process; [Net.ServicePointManager]::SecurityProtocol = 'Tls12'; iwr -useb https://raw.githubusercontent.com/gerardog/gsudo/master/installgsudo.ps1 | iex"


# Write-Host "Setting up dotnet for Windows..." -ForegroundColor Green
# Write-Host "------------------------------------" -ForegroundColor Green
# [Environment]::SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development", "Machine")
# [Environment]::SetEnvironmentVariable("DOTNET_PRINT_TELEMETRY_MESSAGE", "false", "Machine")
# [Environment]::SetEnvironmentVariable("DOTNET_CLI_TELEMETRY_OPTOUT", "1", "Machine")
# dotnet tool install --global dotnet-ef
# dotnet tool update --global dotnet-ef

# Write-Host "Excluding repos from Windows Defender..." -ForegroundColor Green
# Add-MpPreference -ExclusionPath "$env:USERPROFILE\source\repos"
# Add-MpPreference -ExclusionPath "$env:USERPROFILE\.nuget"
# Add-MpPreference -ExclusionPath "$env:USERPROFILE\.vscode"
# Add-MpPreference -ExclusionPath "$env:USERPROFILE\.dotnet"
# Add-MpPreference -ExclusionPath "$env:USERPROFILE\.ssh"
# Add-MpPreference -ExclusionPath "$env:APPDATA\npm"

# Write-Host "Enabling Hardware-Accelerated GPU Scheduling..." -ForegroundColor Green
# New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\" -Name 'HwSchMode' -Value '2' -PropertyType DWORD -Force

# Write-Host "Installing Github.com/microsoft/artifacts-credprovider..." -ForegroundColor Green
# Write-Host "------------------------------------" -ForegroundColor Green
# iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/microsoft/artifacts-credprovider/master/helpers/installcredprovider.ps1'))

# # -----------------------------------------------------------------------------
# Write-Host ""
# Write-Host "Checking Windows updates..." -ForegroundColor Green
# Write-Host "------------------------------------" -ForegroundColor Green
# Install-Module -Name PSWindowsUpdate -Force
# Write-Host "Installing updates... (Computer will reboot in minutes...)" -ForegroundColor Green
# Get-WindowsUpdate -AcceptAll -Install -ForceInstall -AutoReboot

# -----------------------------------------------------------------------------
# Write-Host "------------------------------------" -ForegroundColor Green
# Read-Host -Prompt "Setup is done, restart is needed, press [ENTER] to restart computer."
# Restart-Computer
