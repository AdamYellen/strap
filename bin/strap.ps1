#Requires -RunAsAdministrator

param($strap_git_name, $strap_git_email, $strap_github_user, $strap_github_token)

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
### Lock Screen                                                               #
###############################################################################

## Enable Custom Background on the Login / Lock Screen
## Background file: C:\someDirectory\someImage.jpg
## File Size Limit: 256Kb
# Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\Personalization" "LockScreenImage" "C:\someDirectory\someImage.jpg"

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
if ($strap_github_user -and ((git config --global github.user) -ne $strap_github_user))
{
    git config --global github.user "$strap_github_user"
}

# Squelch git 2.x warning message when pushing
# if (! (git config push.default))
# {
#   git config --global push.default simple
# }

# Setup GitHub HTTPS credentials.
if ($strap_github_user -and $strap_github_token)
{
    Write-Output "protocol=https`nhost=github.com`n`n" | git credential reject
    Write-Output "protocol=https`nhost=github.com`nusername=$strap_github_user`npassword=$strap_github_token`n`n" | git credential approve
}

# Setup dotfiles
if ($strap_github_user)
{
    $DOTFILES_URL="https://github.com/$strap_github_user/dotfiles"
    if (git ls-remote "$DOTFILES_URL")
    {
        Write-Host "Fetching/Updating $strap_github_user/dotfiles from GitHub:" -ForegroundColor Green
        Write-Host "------------------------------------" -ForegroundColor Green
        if (Test-Path "$HOME/.dotfiles")
        {
            Push-Location
            Set-Location "$HOME/.dotfiles"
            git pull --rebase --autostash
            Pop-Location
        }
        else
        {
            git clone "$DOTFILES_URL" "$HOME/.dotfiles"
        }
    }

    # run_dotfile_scripts script/setup script/bootstrap
    if (Test-Path "$HOME/.dotfiles/script/setup.ps1")
    {
        & "$HOME/.dotfiles/script/setup.ps1"
    }
}

###############################################################################
### WSL2                                                                      #
###############################################################################

Write-Host "Installing Windows Subsystem for Linux..." -ForegroundColor "Yellow"
wsl --install
Write-Host "------------------------------------" -ForegroundColor Green

###############################################################################
### Updates                                                                   #
###############################################################################
Write-Host "Checking Windows updates..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Install-Module -Name PSWindowsUpdate -Force
Write-Host "Installing updates... (Computer will reboot in minutes...)" -ForegroundColor Green
Get-WindowsUpdate -AcceptAll -Install -ForceInstall -AutoReboot

# Read-Host -Prompt "Setup is done, Windows needs to restart to continue, press [ENTER] to restart computer."
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

# -----------------------------------------------------------------------------
# Write-Host "------------------------------------" -ForegroundColor Green
# Read-Host -Prompt "Setup is done, restart is needed, press [ENTER] to restart computer."
# Restart-Computer
