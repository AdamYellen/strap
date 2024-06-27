# Strap

A script to bootstrap a minimal macOS and Windows development system. Forked from [Mike McQuaid's Strap](https://github.com/MikeMcQuaid/strap). All changes to the macOS strap script have been kept to a minimum. There has been no attempt to modify the web service portion since I execute the strap scripts directly with the necessary arguments.

## New Features

- Added support for Windows 11 which relies on [UnattendedWinstall](https://github.com/memstechtips/UnattendedWinstall) to install a de-bloated blank canvas
- Added support for a mobile phone number on the lock screen message
- Added support for a 1Password signup URI used by my [dotfile](https://github.com/AdamYellen/dotfiles) strap-after-setup script

## Usage

### macOS

```bash
curl -o strap.sh https://raw.githubusercontent.com/AdamYellen/strap/master/bin/strap.sh
STRAP_GIT_NAME="Adam Yellen" STRAP_GIT_EMAIL="<email>" STRAP_GITHUB_USER="AdamYellen" STRAP_GITHUB_TOKEN="<personal access token>" [STRAP_MOBILE="<number>"] [STRAP_OP_URI="<1Password URI>"] bash strap.sh
```

### Windows

Follow the directions in the [UnattendedWinstall README](https://github.com/AdamYellen/UnattendedWinstall/README.md) to install de-bloated Windows 11

Open a PowerShell terminal as Administrator and run:

```powershell
Set-ExecutionPolicy RemoteSigned -Force; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/AdamYellen/strap/master/bin/strap.ps1" -OutFile "C:\strap.ps1"
C:\strap.ps1 -strap_git_name 'Adam Yellen' -strap_git_email '<email>' -strap_github_user 'AdamYellen' [-strap_github_token '<personal access token>'] [-strap_mobile '<number>'] [-strap_op_uri '<1Password URI>']
```

### Notes

- Retrieve your 1Password Signup URI:
  - On macOS by opening 1Password, click on the Accounts menu, click on the account you want, select Set Up Another Device, and clicking Copy Link
  - On Windows by opening 1Password, click on the account drop-down you want, select Set Up Another Device, and clicking Copy Link

### Original README follows

---
---

# Strap

A script to bootstrap a minimal macOS development system. This does not assume you're doing Ruby/Rails/web development but installs the minimal set of software every macOS developer will want.

## Motivation

Replacing [Boxen](https://github.com/boxen/boxen) in [GitHub](https://github.com/) with a better tool. This post outlines the problems with Boxen and requirements for Strap and other tools used by GitHub: <https://mikemcquaid.com/2016/06/15/replacing-boxen/>

## Features

- Enables `sudo` using TouchID
- Disables Java in Safari (for better security)
- Enables the macOS screensaver password immediately (for better security)
- Enables the macOS application firewall (for better security)
- Adds a `Found this computer?` message to the login screen (for machine recovery)
- Enables full-disk encryption and saves the FileVault Recovery Key to the Desktop (for better security)
- Installs the Xcode Command Line Tools (for compilers and Unix tools)
- Agree to the Xcode license (for using compilers without prompts)
- Installs [Homebrew](https://brew.sh) (for installing command-line software)
- Installs [Homebrew Bundle](https://github.com/Homebrew/homebrew-bundle) (for `bundler`-like `Brewfile` support)
- Installs [Homebrew Services](https://github.com/Homebrew/homebrew-services) (for managing Homebrew-installed services)
- Installs [Homebrew Cask](https://github.com/Homebrew/homebrew-cask) (for installing graphical software)
- Installs the latest macOS software updates (for better security)
- Installs dotfiles from a user's `https://github.com/username/dotfiles` repository. If they exist and are executable: runs `script/setup` to configure the dotfiles and `script/strap-after-setup` after setting up everything else.
- Installs software from a user's `Brewfile` in their `https://github.com/username/homebrew-brewfile` repository or `.Brewfile` in their home directory.
- A simple web application to set Git's name, email and GitHub token (needs authorised on any organisations you wish to access)
- Idempotent

## Out of Scope Features

- Enabling any network services by default (instead enable them when needed)
- Installing Homebrew formulae by default for everyone in an organisation (install them with `Brewfile`s in project repositories instead of mandating formulae for the whole organisation)
- Opting-out of any macOS updates (Apple's security updates and macOS updates are there for a reason)
- Disabling security features (these are a minimal set of best practises)
- Add phone number to security screen message (want to avoid prompting users for information on installation)

## Usage

Open <https://strap.mikemcquaid.com/> in your web browser.

Instead, to run Strap locally run:

```bash
git clone https://github.com/MikeMcQuaid/strap
cd strap
bash bin/strap.sh # or bash bin/strap.sh --debug for more debugging output
```

Instead, to run the web application locally run:

```bash
git clone https://github.com/MikeMcQuaid/strap
cd strap
./script/bootstrap
GITHUB_KEY="..." GITHUB_SECRET="..." ./script/server
```

Strap is also available as a Docker image on [Docker Hub (`mikemcquaid/strap`)](https://hub.docker.com/repository/docker/mikemcquaid/strap) and [GitHub Packages (`ghcr.io/mikemcquaid/strap`)](https://github.com/users/MikeMcQuaid/packages/container/package/strap).

## Web Application Configuration Environment Variables

- `GITHUB_KEY`: the GitHub.com Application Client ID.
- `GITHUB_SECRET`: the GitHub.com Application Client Secret.
- `SESSION_SECRET`: the secret used for cookie session storage.
- `WEB_CONCURRENCY`: the number of Unicorn (web server) processes to run (defaults to 3).
- `STRAP_ISSUES_URL`: the URL where users should file issues (defaults to no URL).
- `STRAP_BEFORE_INSTALL`: instructions displayed in the web application for users to follow before installing Strap (wrapped in `<li>` tags).
- `CUSTOM_HOMEBREW_TAP`: an optional Homebrew tap to install with `brew tap`. Specify multiple arguments to brew tap by separating values with spaces.
- `CUSTOM_BREW_COMMAND`: a single `brew` command that is run after all other stages have completed.

## Status

Stable and in active development.

## Contact

[Mike McQuaid](mailto:mike@mikemcquaid.com)

## License

Licensed under the [MIT License](https://en.wikipedia.org/wiki/MIT_License).
The full license text is available in [LICENSE.txt](https://github.com/MikeMcQuaid/strap/blob/master/LICENSE.txt).
