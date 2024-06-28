#Requires -RunAsAdministrator

param($strap_git_name, $strap_git_email, $strap_github_user, $strap_github_token, $strap_mobile, $strap_op_uri)

# TODO:
# * SetDisplayName fails on a managed account

function CheckCommand($cmdname)
{
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

function AddToPath
{
    param
    (
        [string]$folder
    )

    $currentEnv = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine).Trim(";");
    $addedEnv = $currentEnv + ";$folder"
    $trimmedEnv = (($addedEnv.Split(';') | Select-Object -Unique) -join ";").Trim(";")
    [Environment]::SetEnvironmentVariable("Path", $trimmedEnv, [EnvironmentVariableTarget]::Machine)
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

function RefreshEnv
{
   $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

$gitinf = @"
[Setup]
Lang=default
Dir=C:\Program Files\Git
Group=Git
NoIcons=0
SetupType=default
Components=gitlfs
Tasks=
EditorOption=VisualStudioCode
CustomEditorPath=
DefaultBranchOption=main
PathOption=Cmd
SSHOption=OpenSSH
TortoiseOption=false
CURLOption=WinSSL
CRLFOption=CRLFCommitAsIs
BashTerminalOption=ConHost
GitPullBehaviorOption=Merge
UseCredentialManager=Enabled
PerformanceTweaksFSCache=Enabled
EnableSymlinks=Enabled
EnablePseudoConsoleSupport=Disabled
EnableFSMonitor=Disabled
"@

###############################################################################
### Security and Identity                                                     #
###############################################################################
Write-Host "Configuring System..." -ForegroundColor "Yellow"

## Set DisplayName for my account. Use only if you are not using a Microsoft Account
if($strap_git_name)
{
    $myIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $user = Get-WmiObject Win32_UserAccount | Where-Object {$_.Caption -eq $myIdentity.Name}
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
if($strap_git_name -and $strap_git_email)
{
    # Don't override anything already set by IT
    if(-not (Get-ItemPropertyValue "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "legalnoticecaption"))
    {
        Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "legalnoticecaption" "Found this computer?"
        if($strap_mobile)
        {
            Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "legalnoticetext" "Please contact $strap_git_name at $strap_mobile"
        }
        else
        {
            Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "legalnoticetext" "Please contact $strap_git_name at $strap_git_email."
        }
    }
}

###############################################################################
### Bootstrapping Dependencies                                                #
###############################################################################
Write-Host "Installing dependencies..." -ForegroundColor "Yellow"

# git
if(-not (CheckCommand -cmdname 'git'))
{
    if(-not (CheckCommand -cmdname 'winget'))
    {
        # winget
        Invoke-WebRequest -Uri "https://github.com/asheroto/winget-install/releases/latest/download/winget-install.ps1" -OutFile $ENV:TEMP\winget-install.ps1
        . $ENV:TEMP\winget-install.ps1 | Out-Null
    }

    $git_install_inf = "$ENV:TEMP\git.inf"
    $gitinf | Out-File -FilePath $git_install_inf
    $git_install_args = "/SP- /VERYSILENT /SUPPRESSMSGBOXES /NOCANCEL /NORESTART /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /LOADINF=""$git_install_inf"""
    winget install Git.Git --override "$git_install_args" | Out-Null
    Remove-Item -Path $git_install_inf -Force
    RefreshEnv
}

# Setup Git configuration
Write-Host "Setting up Git for Windows..." -ForegroundColor Yellow
if(-not (CheckCommand -cmdname 'git'))
{
    Write-Host "!! Exiting: Can't find git !!" -ForegroundColor "Red"
    Exit 1
}
git config --system credential.helper manager-core
git config --system core.autocrlf off
git config --system core.symlinks true
if($strap_git_name -and !(git config --global user.name))
{
    git config --global user.name "$strap_git_name"
}
if($strap_git_email -and !(git config --global user.email))
{
    git config --global user.email "$strap_git_email"
}
if($strap_github_user -and ((git config --global github.user) -ne $strap_github_user))
{
    git config --global github.user "$strap_github_user"
}

# Setup GitHub HTTPS credentials
# Only necessary if the repo is private
if($strap_github_user -and $strap_github_token)
{
    Write-Output "protocol=https`nhost=github.com`n`n" | git credential reject
    Write-Output "protocol=https`nhost=github.com`nusername=$strap_github_user`npassword=$strap_github_token`n`n" | git credential approve
}

###############################################################################
### Dotfiles                                                                  #
###############################################################################
if($strap_github_user)
{
    # Clone/update dotfiles repo
    $DOTFILES_URL="https://github.com/$strap_github_user/dotfiles"
    if(git ls-remote "$DOTFILES_URL")
    {
        Write-Host "Fetching/Updating $strap_github_user/dotfiles from GitHub..." -ForegroundColor Yellow
        if(Test-Path "$HOME/.dotfiles")
        {
            Push-Location
            Set-Location "$HOME/.dotfiles"
            git pull -q --rebase --autostash | Out-Null
            Pop-Location
        }
        else
        {
            git clone -q "$DOTFILES_URL" "$HOME/.dotfiles" | Out-Null

            # TODO: Fix ownership of .dotfiles
        }
    }
}

# Run our setup script if it exists
if(Test-Path "$HOME/.dotfiles/script/setup.ps1")
{
    Write-Host "Running dotfiles/script/setup.ps1..." -ForegroundColor Yellow
    & "$HOME/.dotfiles/script/setup.ps1"
}

# Run the strap-after-setup scripts
if(Test-Path "$HOME/.dotfiles/script/strap-after-setup.ps1")
{
    Write-Host "Running dotfiles/script/strap-after-setup.ps1..." -ForegroundColor Yellow
    if($strap_op_uri)
    {
        & "$HOME/.dotfiles/script/strap-after-setup.ps1" -strap_op_uri "$strap_op_uri" | Out-Null
    }
    else
    {
        & "$HOME/.dotfiles/script/strap-after-setup.ps1" | Out-Null
    }
}

Write-Host "Your system is now Strap'd!" -ForegroundColor "Green"