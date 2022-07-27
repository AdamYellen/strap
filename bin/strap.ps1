#Requires -RunAsAdministrator

param($strap_git_name, $strap_git_email, $strap_github_user, $strap_github_token, $strap_mobile, $strap_ci)

function Check-Command($cmdname) {
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

function AddToPath {
    param (
        [string]$folder
    )

    Write-Host "Adding $folder to PATH..." -ForegroundColor Yellow

    $currentEnv = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine).Trim(";");
    $addedEnv = $currentEnv + ";$folder"
    $trimmedEnv = (($addedEnv.Split(';') | Select-Object -Unique) -join ";").Trim(";")
    [Environment]::SetEnvironmentVariable("Path", $trimmedEnv, [EnvironmentVariableTarget]::Machine)

    Write-Host "Reloading environment variables..." -ForegroundColor Yellow
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

###############################################################################
### Security and Identity                                                     #
###############################################################################
Write-Host "Configuring System..." -ForegroundColor "Yellow"

# Set Computer Name
# (Get-WmiObject Win32_ComputerSystem).Rename("COMPUTER") | Out-Null
# $computerName = Read-Host 'Enter New Computer Name'
# Write-Host "Renaming this computer to: " $computerName  -ForegroundColor Yellow
# Rename-Computer -NewName $computerName

## Set DisplayName for my account. Use only if you are not using a Microsoft Account
if ($strap_git_name) {
    $myIdentity=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $user = Get-WmiObject Win32_UserAccount | Where {$_.Caption -eq $myIdentity.Name}
    $user.FullName = "$strap_git_name"
    $user.Put() | Out-Null
    Remove-Variable user
    Remove-Variable myIdentity
}

###############################################################################
### Lock Screen                                                               #
###############################################################################
Write-Host "Configuring Lock Screen..." -ForegroundColor "Yellow"

## Enable Custom Background on the Login / Lock Screen
## Background file: C:\someDirectory\someImage.jpg
## File Size Limit: 256Kb
# Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\Personalization" "LockScreenImage" "C:\someDirectory\someImage.jpg"
if ($strap_git_name -and $strap_git_email) {
    Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "legalnoticecaption" "Found this computer?"
    if($strap_mobile) {
        Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "legalnoticetext" "Please contact $strap_git_name at $strap_mobile"
    }
    else {
        Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "legalnoticetext" "Please contact $strap_git_name at $strap_git_email."
    }
}

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
Write-Host "Installing dependencies..." -ForegroundColor "Yellow"

# Chocolatey
# if (-not (Check-Command -cmdname 'choco')) {
#     Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) | Out-Null
# }
# else {
#     choco upgrade chocolatey | Out-Null
# }
# if (-not (Check-Command -cmdname 'choco')) {
#     Write-Host "!! Exiting: Can't find Chocolatey !!" -ForegroundColor "Red"
#     Exit 1
# }

# Install Scoop
iex "& {$(irm get.scoop.sh)} -RunAsAdmin" | Out-Null

# Install Git
# choco upgrade git --params "/GitOnlyOnPath /NoAutoCrlf /NoShellIntegration /SChannel /Symlinks /Editor:VisualStudioCode" -y | Out-Null
scoop install git | Out-Null

# Make `refreshenv` available right away, by defining the $env:ChocolateyInstall variable and importing the Chocolatey profile module.
# $env:ChocolateyInstall = Convert-Path "$((Get-Command choco).Path)\..\.."   
# Import-Module "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
# refreshenv

# Setup Git configuration
Write-Host "Setting up Git for Windows..." -ForegroundColor Yellow
if (-not (Check-Command -cmdname 'git')) {
    Write-Host "!! Exiting: Can't find git !!" -ForegroundColor "Red"
    Exit 1
}
git config --global credential.helper manager-core
if ($strap_git_name -and !(git config --global user.name)) {
    git config --global user.name "$strap_git_name"
}
if ($strap_git_email -and !(git config --global user.email)) {
    git config --global user.email "$strap_git_email"
}
if ($strap_github_user -and ((git config --global github.user) -ne $strap_github_user)) {
    git config --global github.user "$strap_github_user"
}

# Setup GitHub HTTPS credentials
if ($strap_github_user -and $strap_github_token) {
    Write-Output "protocol=https`nhost=github.com`n`n" | git credential reject
    Write-Output "protocol=https`nhost=github.com`nusername=$strap_github_user`npassword=$strap_github_token`n`n" | git credential approve
}

###############################################################################
### Dotfiles                                                                  #
###############################################################################
if ($strap_github_user) {
    # Clone/update dotfiles repo
    $DOTFILES_URL="https://github.com/$strap_github_user/dotfiles"
    if (git ls-remote "$DOTFILES_URL") {
        Write-Host "Fetching/Updating $strap_github_user/dotfiles from GitHub..." -ForegroundColor Yellow
        if (Test-Path "$HOME/.dotfiles") {
            Push-Location
            Set-Location "$HOME/.dotfiles"
            git pull --rebase --autostash
            Pop-Location
        }
        else {
            git clone "$DOTFILES_URL" "$HOME/.dotfiles"
        }
    }

    # Run our setup script if it exists
    if (Test-Path "$HOME/.dotfiles/script/setup.ps1") {
        Write-Host "Running dotfiles/script/setup.ps1..." -ForegroundColor Yellow
        & "$HOME/.dotfiles/script/setup.ps1"
    }
}

###############################################################################
### Updates                                                                   #
###############################################################################
Write-Host "Checking for Windows updates..." -ForegroundColor Yellow
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
Install-Module -Name PSWindowsUpdate -Force

# Tell Windows Store to update (no way to wait for it to complete *sigh*)
$wmiObj = Get-WmiObject -Namespace "root\cimv2\mdm\dmmap" -Class "MDM_EnterpriseModernAppManagement_AppManagement01"
$wmiObj.UpdateScanMethod() | Out-Null
Remove-Variable wmiObj

if (-not $strap_ci) {
    Write-Host "Installing updates... (Computer will reboot when complete)" -ForegroundColor Red
    Get-WindowsUpdate -AcceptAll -Install -ForceInstall -AutoReboot | Out-Null
}
else {
    Write-Host "Skipping updates... (Computer will reboot now)" -ForegroundColor Red
    Restart-Computer
}
