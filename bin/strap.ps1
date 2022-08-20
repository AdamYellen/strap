#Requires -RunAsAdministrator

param($strap_git_name, $strap_git_email, $strap_github_user, $strap_github_token, $strap_mobile, $strap_op_uri, $strap_stage, $strap_ci)

# TODO:
# * SetDisplayName fails on a managed account
# * Do a better job of constructing the stage2 script; strip off anything before the call to the strap.ps1 script (Set-ExecutionPolicy, etc.)

function CheckCommand($cmdname)
{
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

function IsWindows10()
{
    return([System.Environment]::OSVersion.Version.Build -lt 22000)
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

function UpdateStoreApps
{
    $wmiObj = Get-WmiObject -Namespace "root\cimv2\mdm\dmmap" -Class "MDM_EnterpriseModernAppManagement_AppManagement01"
    $wmiObj.UpdateScanMethod() | Out-Null
    Start-Sleep -Seconds 30
    Remove-Variable wmiObj    
}

# Which stage are we in?
if((-not $strap_stage) -or ($strap_stage -lt 2))
{
    ###############################################################################
    ### Stage 1                                                                   #
    ###############################################################################

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

    # Install Scoop since winget isn't available until the MSStore apps are updated
    if(-not (CheckCommand -cmdname 'scoop'))
    {
        Invoke-Expression "& {$(Invoke-RestMethod get.scoop.sh)} -RunAsAdmin" | Out-Null
    }

    # Install Git
    if(-not (CheckCommand -cmdname 'git'))
    {
        scoop install git 6>&1 | Out-Null
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
            }
        }

        # Run our setup script if it exists
        if(Test-Path "$HOME/.dotfiles/script/setup.ps1")
        {
            Write-Host "Running dotfiles/script/setup.ps1..." -ForegroundColor Yellow
            & "$HOME/.dotfiles/script/setup.ps1"
        }
    }

    ###############################################################################
    ### Setup stage 2 for next reboot                                             #
    ###############################################################################
    Write-Host "Setup stage 2 for next reboot..." -ForegroundColor Yellow

    # Create our stage2 bootstrap
    $stage2CLI = ""
    $stage2CLI += $myinvocation.Line + ' -strap_stage 2'
    $stage2Script = @"
powershell.exe -NoExit -File $stage2CLI
"@
    $stage2File="C:\strap2.ps1"
    if(Test-Path -Path $stage2File)
    {
        Remove-Item $stage2File | Out-Null
    }
    $stage2Script | Out-File $stage2File -Encoding ASCII
    
    # Setup a scheduled task that will run on next logon to run strap again with the same args plus -strap_stage 2
    schtasks /create /f /tn "StrapStage2" /sc onlogon /delay 0000:30 /rl highest /it /tr "powershell.exe -NoExit -File $stage2File" | Out-Null

    ###############################################################################
    ### Updates                                                                   #
    ###############################################################################
    Write-Host "Checking for Windows updates..." -ForegroundColor Yellow

    # Update store apps
    UpdateStoreApps

    # Windows updates
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    Install-Module -Name PSWindowsUpdate -Force | Out-Null
    if(-not $strap_ci)
    {
        Write-Host "Installing updates... (Computer will reboot when updates are complete and continue the strap process)" -ForegroundColor Red
        Get-WindowsUpdate -AcceptAll -Install -ForceInstall -AutoReboot | Out-Null
        Restart-Computer
    }
    else
    {
        Write-Host "Skipping updates... (Computer will reboot now and continue the strap process)" -ForegroundColor Red
        Restart-Computer
    }
}
else
{
    ###############################################################################
    ### Stage 2                                                                   #
    ###############################################################################
    Write-Host "Continue strapping..." -ForegroundColor "Yellow"

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

    # Fix ownership
    Write-Host "Fixing ownership..." -ForegroundColor "Yellow"
    takeown /r /d Y /f "$HOME" | Out-Null

    # Clear our Powershell history
    if(Test-Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\$($host.Name)_history.txt")
    {
        Remove-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\$($host.Name)_history.txt" -Force | Out-Null
    }
    Clear-History | Out-Null

    # Cleanup our scheduled task
    schtasks /delete /f /tn "StrapStage2" | Out-Null
    if(Test-Path "C:\strap2.ps1")
    {
        Remove-Item "C:\strap2.ps1" -Force | Out-Null
    }
    
    Write-Host "Your system is now Strap'd!" -ForegroundColor "Green"
}
