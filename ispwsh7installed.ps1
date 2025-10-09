# PowerShell 7 Checker and Installer Script
# Created: October 7, 2025

param(
    [switch]$Check,
    [switch]$Install,
    [switch]$AsAdmin
)

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

function Restart-AsAdminAndWait {
    param(
        [string]$Operation
    )
    
    if (-not (Test-IsAdmin)) {
        $argList = @(
            "-ExecutionPolicy", "Bypass",
            "-File", "`"$PSCommandPath`"",
            "-$Operation",
            "-AsAdmin"
        )

        # Safe check for Verbose parameter
        if ($PSCmdlet -and $PSCmdlet.MyInvocation.BoundParameters -and $PSCmdlet.MyInvocation.BoundParameters["Verbose"]) {
            $argList += "-Verbose"
        }
        
        Write-Host "Requesting administrator privileges for PowerShell 7 installation..."
        $process = Start-Process powershell.exe -ArgumentList $argList -Verb RunAs -PassThru
        
        # Wait for the elevated process to complete
        $process.WaitForExit()
        
        return $process.ExitCode
    }
    return 0
}

function Test-PowerShell7Installed {
    <#
    .SYNOPSIS
    Checks if PowerShell 7 is installed on the system.
    
    .DESCRIPTION
    This function checks the Windows registry and installed programs to determine
    if PowerShell 7 is installed on the system.
    
    .OUTPUTS
    [bool] Returns $true if PowerShell 7 is installed, $false otherwise.
    #>
    
    try {
        # Get installed programs from both registry locations
        $MyProgs = @()
        $MyProgs += Get-ItemProperty 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
        $MyProgs += Get-ItemProperty 'HKLM:SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
        
        $InstalledProgs = $MyProgs.DisplayName | Where-Object { $_ -ne $null } | Sort-Object -Unique
        
        # Check if PowerShell 7 is in the installed programs list
        $powershell7Installed = $InstalledProgs -like "*PowerShell*7*"
        
        if ($powershell7Installed) {
            Write-Verbose "PowerShell 7 is installed."
            return $true
        } else {
            Write-Verbose "PowerShell 7 is not installed."
            return $false
        }
    }
    catch {
        Write-Error "Error checking PowerShell 7 installation status: $($_.Exception.Message)"
        return $false
    }
}

function Install-PowerShell7 {
    <#
    .SYNOPSIS
    Installs PowerShell 7 on the system.
    
    .DESCRIPTION
    This function downloads and installs the latest LTS version of PowerShell 7
    using the local curl.exe utility.
    
    .OUTPUTS
    [bool] Returns $true if installation was successful, $false otherwise.
    #>
    
    # Check if already running as admin, if not, restart with admin privileges
    if (-not (Test-IsAdmin)) {
        Write-Host "Administrator privileges required for installation."
        $exitCode = Restart-AsAdminAndWait -Operation "Install"
        return ($exitCode -eq 0)
    }
    
    # Enforce TLS 1.2 for secure downloads
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    # Check if PowerShell 7 is already installed
    if (Test-PowerShell7Installed) {
        Write-Host "PowerShell 7 is already installed."
        return $true
    }
    
    try {
        $url = "https://aka.ms/powershell-release?tag=lts"
        $folderName = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $workpath = "$env:TEMP\powershell7-$folderName"
        $currentPath = $PSScriptRoot
        $downloadPath = "$workpath\powershell-7.msi"
        $curlpath = "$currentPath\curl\curl.exe"
        $curldefault = "--connect-timeout 45 --retry 5 --retry-max-time 120 --retry-connrefused -S -s"
        
        # Verify curl.exe exists
        if (-not (Test-Path $curlpath)) {
            Write-Error "Error: curl.exe not found at $curlpath"
            return $false
        }
        
        # Create temporary directory
        if (Test-Path $workpath) {
            Write-Host "Directory $workpath already exists. Deleting..."
            Remove-Item -Path $workpath -Recurse -Force
        }
        New-Item -Path $workpath -ItemType Directory -Force | Out-Null
        
        Write-Host "PowerShell 7 is not installed."
        Write-Host "Installing PowerShell 7..."
        Write-Host "Please wait..."
        
        # Extract URL from aka.ms link
        Write-Verbose "Extracting URL from aka.ms link..."
        $curlOutput = Invoke-Expression -Command "$curlpath $curldefault -v `"$url`" 2>&1"
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to extract URL from aka.ms link."
        }
        
        $locationHeader = $curlOutput | Where-Object { $_ -match "Location:" } | Select-Object -First 1
        if ($locationHeader -match "Location:\s*(https?://[^\s]+)") {
            $redirecturl1 = $matches[1]
        } else {
            throw "Unable to extract Location header from response."
        }
        
        Write-Verbose "Found redirect URL: $redirecturl1"
        
        # Extract final download URL
        Write-Verbose "Extracting final download URL..."
        $curlOutput = Invoke-Expression -Command "$curlpath $curldefault -v `"$redirecturl1`" 2>&1"
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to extract final download URL."
        }
        
        $locationHeader = $curlOutput | Where-Object { $_ -match "Location:" } | Select-Object -First 1
        if ($locationHeader -match "Location:\s*(https?://[^\s]+)") {
            $redirecturl2 = $matches[1]
        } else {
            throw "Unable to extract final Location header from response."
        }
        
        Write-Verbose "Found final Github URL: $redirecturl2"
        
        # Extract version number from URL
        Write-Verbose "Extract version number from URL..."
        $versionv = $redirecturl2 -split "/" | Select-Object -Last 1
        $version = $versionv -replace "v\s*", ""
        Write-Verbose "Found version number: $versionv"
        
        # Download PowerShell 7 installer
        Write-Host "Downloading PowerShell 7 version $version..."
        $downloadUrl = "https://github.com/PowerShell/PowerShell/releases/download/$versionv/PowerShell-$version-win-x64.msi"
        Invoke-Expression -Command "$curlpath $curldefault -L -o `"$downloadPath`" `"$downloadUrl`""
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to download PowerShell 7 installer."
        }
        
        Write-Host "Download complete."
        
        # Install PowerShell 7
        Write-Host "Installing PowerShell 7..."
        $process = Start-Process -FilePath msiexec.exe -ArgumentList "/i `"$downloadPath`" /passive /norestart" -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "PowerShell 7 installation failed with exit code: $($process.ExitCode)"
        }
        
        Write-Host "Installation complete."
        
        # Clean up temporary files
        Write-Host "Cleaning up temporary files..."
        Remove-Item -Path $workpath -Recurse -Force -ErrorAction SilentlyContinue
        
        # Verify installation
        Start-Sleep -Seconds 5
        if (Test-PowerShell7Installed) {
            Write-Host "PowerShell 7 installation verified successfully."
            return $true
        } else {
            Write-Warning "PowerShell 7 installation could not be verified. You may need to restart your system."
            return $true  # Installation likely succeeded but registry not updated yet
        }
    }
    catch {
        Write-Error "Error during PowerShell 7 installation: $($_.Exception.Message)"
        
        # Clean up on error
        if ($workpath -and (Test-Path $workpath)) {
            Remove-Item -Path $workpath -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        return $false
    }
}

# Main script logic
if ($Check) {
    $isInstalled = Test-PowerShell7Installed
    if ($isInstalled) {
        Write-Host "PowerShell 7 is installed." -ForegroundColor Green
        exit 0  # Return true (success)
    } else {
        Write-Host "PowerShell 7 is not installed." -ForegroundColor Red
        exit 1  # Return false (failure)
    }
}
elseif ($Install) {
    $installResult = Install-PowerShell7
    if ($installResult) {
        Write-Host "PowerShell 7 installation completed successfully." -ForegroundColor Green
        exit 0  # Return true (success)
    } else {
        Write-Host "PowerShell 7 installation failed." -ForegroundColor Red
        exit 1  # Return false (failure)
    }
}
else {
    Write-Host @"
PowerShell 7 Checker and Installer Script

Usage:
  .\ispwsh7installed.ps1 -Check     : Check if PowerShell 7 is installed (returns true/false via exit code)
  .\ispwsh7installed.ps1 -Install   : Install PowerShell 7 if not present

Examples:
  # Check installation status
  .\ispwsh7installed.ps1 -Check
  
  # Install PowerShell 7
  .\ispwsh7installed.ps1 -Install
  
  # Use in scripts with exit code check
  .\ispwsh7installed.ps1 -Check
  if (`$LASTEXITCODE -eq 0) {
      Write-Host "PowerShell 7 is installed"
  } else {
      Write-Host "PowerShell 7 is not installed"
  }

Exit Codes:
  0 = Success (PowerShell 7 is installed / installation succeeded)
  1 = Failure (PowerShell 7 is not installed / installation failed)
"@ -ForegroundColor Cyan
}
