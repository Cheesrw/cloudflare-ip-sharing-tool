# IP Address Retrieval and Encryption Script
# Gets public IP, encrypts with PGP, and pushes to Cloudflare DNS TXT record

param(
    [Parameter(Mandatory = $true)]
    [string]$CloudflareApiToken,
    
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    
    [Parameter(Mandatory = $true)]
    [string]$Subdomain,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("v4", "v6", "both")]
    [string]$IPVersion = "v4",
    
    [Parameter(Mandatory = $false)]
    [switch]$Quiet
)

# Import PSPGP module
Import-Module "$PSScriptRoot\PSPGP\PSPGP.psd1" -Force

# Import Cloudflare helpers
. "$PSScriptRoot\CloudflareHelpers.ps1"

# Remove curl alias to use local curl.exe
Remove-Item Alias:curl -ErrorAction SilentlyContinue

# Define paths
$CurlPath = "$PSScriptRoot\curl\curl.exe"
$KeysPath = "$PSScriptRoot\keys"
$PublicKeyPath = "$KeysPath\public.asc"
$PrivateKeyPath = "$KeysPath\private.asc"
$PasswordPath = "$KeysPath\password.txt"

# Global variables for logging
$Global:LogFile = $null
$Global:QuietMode = $Quiet.IsPresent

# Logging system
function Initialize-Logging {
    if ($Global:QuietMode) {
        $LogsDir = "$PSScriptRoot\logs"
        $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $Global:LogFile = "$LogsDir\get_$Timestamp.log"
        
        # Ensure logs directory exists
        if (-not (Test-Path $LogsDir)) {
            New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
        }
        
        # Rotate logs (keep maximum 30 get logs)
        Invoke-LogRotation -ScriptType "get" -LogsDir $LogsDir
        
        # Initialize log file
        $logHeader = @"
=== IP Address Retrieval and Encryption Log ===
Timestamp: $(Get-Date)
Script: get.ps1
Arguments: $($MyInvocation.BoundParameters | ConvertTo-Json -Compress)
=============================================

"@
        Add-Content -Path $Global:LogFile -Value $logHeader
    }
}

# Function to rotate logs (keep maximum 30 per script type)
function Invoke-LogRotation {
    param(
        [string]$ScriptType,
        [string]$LogsDir
    )
    
    $existingLogs = Get-ChildItem -Path $LogsDir -Filter "${ScriptType}_*.log" -ErrorAction SilentlyContinue
    
    if ($existingLogs.Count -ge 30) {
        $logsToDelete = $existingLogs | Sort-Object CreationTime | Select-Object -First ($existingLogs.Count - 29)
        $logsToDelete | Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

# Logging functions for quiet mode
function Write-QuietLog {
    param(
        [string]$Message,
        [string]$ForegroundColor = "White"
    )
    
    if ($Global:QuietMode -and $Global:LogFile) {
        Add-Content -Path $Global:LogFile -Value "[$ForegroundColor] $Message"
    } else {
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
}

# Override Write-Host to support quiet logging
function Write-Host {
    param(
        [Parameter(Position=0, ValueFromPipeline=$true)]
        [object]$Object = "",
        [ConsoleColor]$ForegroundColor = [ConsoleColor]::White,
        [ConsoleColor]$BackgroundColor = [Console]::BackgroundColor,
        [switch]$NoNewline
    )
    
    $message = if ($Object -eq $null) { "" } else { $Object.ToString() }
    
    if ($Global:QuietMode -and $Global:LogFile) {
        # In quiet mode, log to file instead of console
        $logEntry = "[$ForegroundColor] $message"
        if ($NoNewline) {
            Add-Content -Path $Global:LogFile -Value $logEntry -NoNewline
        } else {
            Add-Content -Path $Global:LogFile -Value $logEntry
        }
    } else {
        # Normal mode, use original Write-Host behavior
        $writeHostParams = @{
            Object = $message
            ForegroundColor = $ForegroundColor
        }
        if ($PSBoundParameters.ContainsKey('BackgroundColor')) {
            $writeHostParams.BackgroundColor = $BackgroundColor
        }
        if ($NoNewline) {
            $writeHostParams.NoNewline = $true
        }
        Microsoft.PowerShell.Utility\Write-Host @writeHostParams
    }
}

# Ensure keys directory exists with secure permissions
if (-not (Test-Path $KeysPath)) {
    New-Item -ItemType Directory -Path $KeysPath -Force | Out-Null
    
    # Set restrictive permissions on keys directory (Windows)
    try {
        $acl = Get-Acl $KeysPath
        $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance, remove existing permissions
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $KeysPath -AclObject $acl
        Write-Host "Secured keys directory with restrictive permissions" -ForegroundColor Green
    }
    catch {
        Write-Warning "Could not set secure permissions on keys directory: $($_.Exception.Message)"
    }
}

# Function to validate PGP key strength
function Test-PGPKeyStrength {
    param([string]$publicKeyPath)
    
    if (-not (Test-Path $publicKeyPath)) {
        return $false
    }
    
    try {
        $keyContent = Get-Content $publicKeyPath -Raw
        $keySize = (Get-Item $publicKeyPath).Length
        
        # Enhanced detection for 4096-bit keys
        if ($keyContent -match "4096" -or $keySize -gt 5000) {
            Write-Host "Key strength validation: EXCELLENT (4096-bit detected)" -ForegroundColor Green
            return $true
        }
        elseif ($keyContent -match "2048" -or $keySize -gt 2500) {
            Write-Host "Key strength validation: GOOD (2048-bit detected)" -ForegroundColor Yellow
            return $true
        }
        elseif ($keySize -gt 1500) {
            Write-Host "Key strength validation: MODERATE (standard encryption)" -ForegroundColor Yellow
            return $true
        }
        else {
            Write-Host "Key strength validation: WEAK (key may be insufficient)" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Warning "Unable to validate key strength: $($_.Exception.Message)"
        return $false
    }
}

# Function to get public IP with fallback
function Get-PublicIP {
    param([string]$ipVersion)
    
    Write-Host "Getting public IP address ($ipVersion)..." -ForegroundColor Yellow
    
    if ($ipVersion -eq "v4") {
        # IPv4 services with multiple fallbacks
        $ipv4Services = @(
            @{ url = "https://api.ipify.org"; name = "ipify"; format = "text" },
            @{ url = "https://api4.my-ip.io/ip"; name = "my-ip.io"; format = "text" },
            @{ url = "https://ipv4.icanhazip.com"; name = "icanhazip"; format = "text" },
            @{ url = "https://v4.ident.me"; name = "ident.me"; format = "text" }
        )
        
        foreach ($service in $ipv4Services) {
            try {
                Write-Host "Trying $($service.name)..." -ForegroundColor Gray
                $response = & $CurlPath -s --max-time 10 -4 $service.url
                
                if ($response -and $response.Trim() -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                    $ipAddress = $response.Trim()
                    Write-Host "IPv4 retrieved from $($service.name): $ipAddress" -ForegroundColor Green
                    return $ipAddress
                }
                Write-Warning "Service $($service.name) returned invalid IPv4: $response"
            }
            catch {
                Write-Warning "Service $($service.name) failed: $($_.Exception.Message)"
            }
        }
        
        throw "Failed to retrieve public IPv4 from all services"
    }
    elseif ($ipVersion -eq "v6") {
        # IPv6 services with multiple fallbacks
        $ipv6Services = @(
            @{ url = "https://api6.ipify.org"; name = "ipify IPv6"; format = "text" },
            @{ url = "https://api6.my-ip.io/ip"; name = "my-ip.io IPv6"; format = "text" },
            @{ url = "https://ipv6.icanhazip.com"; name = "icanhazip IPv6"; format = "text" },
            @{ url = "https://v6.ident.me"; name = "ident.me IPv6"; format = "text" }
        )
        
        foreach ($service in $ipv6Services) {
            try {
                Write-Host "Trying $($service.name)..." -ForegroundColor Gray
                $response = & $CurlPath -s --max-time 10 -6 $service.url
                
                if ($response -and $response.Trim() -match '^[0-9a-fA-F:]+$') {
                    $ipAddress = $response.Trim()
                    Write-Host "IPv6 retrieved from $($service.name): $ipAddress" -ForegroundColor Green
                    return $ipAddress
                }
                Write-Warning "Service $($service.name) returned invalid IPv6: $response"
            }
            catch {
                Write-Warning "Service $($service.name) failed: $($_.Exception.Message)"
            }
        }
        
        throw "Failed to retrieve public IPv6 from all services"
    }
}

# Function to get the appropriate subdomain based on IP version
function Get-SubdomainForIPVersion {
    param([string]$baseSubdomain, [string]$ipVersion, [string]$versionMode)
    
    if ($versionMode -eq "both") {
        if ($ipVersion -eq "v4") {
            return "${baseSubdomain}4"
        }
        elseif ($ipVersion -eq "v6") {
            return "${baseSubdomain}6"
        }
    }
    
    # For single version mode (v4 or v6), use the base subdomain
    return $baseSubdomain
}

# Function to create PGP keys if they don't exist
function Initialize-PGPKeys {
    if (-not (Test-Path $PublicKeyPath) -or -not (Test-Path $PrivateKeyPath)) {
        Write-Host "PGP keys not found. Creating new key pair with enhanced security..." -ForegroundColor Yellow
        
        # Generate cryptographically secure random password (64 characters)
        # Using full ASCII printable range excluding problematic characters
        $secureChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
        $password = -join ((1..64) | ForEach-Object { $secureChars[(Get-Random -Maximum $secureChars.Length)] })
        
        # Create PGP key pair with enhanced security parameters
        try {
            Write-Host "Generating 4096-bit RSA key with high security parameters..." -ForegroundColor Yellow
            Write-Host "This may take a moment due to enhanced cryptographic strength..." -ForegroundColor Gray
            
            # Try with enhanced parameters first
            New-PGPKey -FilePathPublic $PublicKeyPath -FilePathPrivate $PrivateKeyPath `
                -UserName "ip-changer-secure" `
                -Password $password `
                -Strength 4096 `
                -Certainty 20 `
                -EmitVersion
            
            # Save password to file with secure encoding
            $password | Out-File -FilePath $PasswordPath -Encoding UTF8
            
            Write-Host "Enhanced PGP key pair created successfully!" -ForegroundColor Green
            Write-Host "Key specifications:" -ForegroundColor Cyan
            Write-Host "  - Algorithm: RSA 4096-bit" -ForegroundColor Gray
            Write-Host "  - Certainty: 20 (highest)" -ForegroundColor Gray
            Write-Host "  - Enhanced entropy generation" -ForegroundColor Gray
            Write-Host "Generated secure password (64 chars): $password" -ForegroundColor Cyan
            Write-Host "Password saved to: $PasswordPath" -ForegroundColor Cyan
            Write-Host "" -ForegroundColor White
            Write-Host "SECURITY NOTICE: Store this password securely!" -ForegroundColor Red
            Write-Host "The private key is protected with military-grade encryption." -ForegroundColor Yellow
        }
        catch {
            # Fallback to basic parameters if enhanced security fails
            Write-Warning "Enhanced security parameters failed, falling back to standard security..."
            Write-Host "Attempting key generation with standard parameters..." -ForegroundColor Yellow
            
            try {
                New-PGPKey -FilePathPublic $PublicKeyPath -FilePathPrivate $PrivateKeyPath -UserName "ip-changer" -Password $password
                
                # Save password to file
                $password | Out-File -FilePath $PasswordPath -Encoding UTF8
                
                Write-Host "Standard PGP key pair created successfully!" -ForegroundColor Green
                Write-Host "Generated password: $password" -ForegroundColor Cyan
                Write-Host "Password saved to: $PasswordPath" -ForegroundColor Cyan
            }
            catch {
                throw "Failed to create PGP keys: $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-Host "PGP keys already exist." -ForegroundColor Green
        
        # Verify key strength if possible
        try {
            $publicKeyContent = Get-Content $PublicKeyPath -Raw
            if ($publicKeyContent -match "4096") {
                Write-Host "Existing keys appear to use enhanced 4096-bit encryption." -ForegroundColor Green
            }
            else {
                Write-Host "Existing keys detected. Consider regenerating for enhanced security." -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "Unable to verify existing key strength." -ForegroundColor Gray
        }
    }
}

# Function to get Cloudflare zone ID with enhanced error handling
function Get-CloudflareZoneId {
    param([string]$domain)
    
    Write-Host "Getting Cloudflare zone ID for domain: $domain" -ForegroundColor Yellow
    
    $result = Invoke-CloudflareApiCall -CurlPath $CurlPath -Url "https://api.cloudflare.com/client/v4/zones?name=$domain" -ApiToken $CloudflareApiToken -Context "Get zone ID for $domain" -Quiet:$Global:QuietMode
    
    if ($result.Success) {
        if ($result.Result -and $result.Result.Count -gt 0) {
            $zoneId = $result.Result[0].id
            Write-Host "Zone ID found: $zoneId" -ForegroundColor Green
            return $zoneId
        }
        else {
            throw "Domain '$domain' not found in your Cloudflare account. Please verify the domain name and ensure it's added to your account."
        }
    }
    else {
        throw "Failed to get zone ID for domain $domain. Check the error details above."
    }
}

# Function to get DNS record ID with enhanced error handling
function Get-DnsRecordId {
    param([string]$zoneId, [string]$recordName)
    
    Write-Host "Getting DNS record ID for: $recordName" -ForegroundColor Yellow
    
    $result = Invoke-CloudflareApiCall -CurlPath $CurlPath -Url "https://api.cloudflare.com/client/v4/zones/$zoneId/dns_records?name=$recordName&type=TXT" -ApiToken $CloudflareApiToken -Context "Get DNS record ID for $recordName" -Quiet:$Global:QuietMode
    
    if ($result.Success) {
        if ($result.Result -and $result.Result.Count -gt 0) {
            $recordId = $result.Result[0].id
            Write-Host "DNS record ID found: $recordId" -ForegroundColor Green
            return $recordId
        }
        else {
            Write-Host "DNS record not found, will create new one" -ForegroundColor Yellow
            return $null
        }
    }
    else {
        Write-Warning "Failed to check for existing DNS record (will attempt to create new one): $($result.Exception)"
        return $null
    }
}

# Function to update or create DNS record with enhanced error handling
function Update-DnsRecord {
    param([string]$zoneId, [string]$recordId, [string]$recordName, [string]$content)
    
    Write-Host "Content length: $($content.Length)" -ForegroundColor Gray
    Write-Host "Content preview: $($content.Substring(0, [Math]::Min(100, $content.Length)))..." -ForegroundColor Gray
    
    # According to Cloudflare API docs: "Strings exceeding this allowed maximum length are automatically split"
    # So we don't need to manually chunk - just send the raw content
    Write-Host "Cloudflare will automatically split content longer than 255 characters" -ForegroundColor Gray
    
    # Create a proper JSON object using PowerShell
    $jsonObject = @{
        type = "TXT"
        name = $recordName
        content = $content
        ttl = 300
    }
    
    # Convert to JSON with proper escaping
    $jsonData = $jsonObject | ConvertTo-Json -Compress
    
    Write-Host "JSON Content to be sent:" -ForegroundColor Magenta
    Write-Host $jsonData -ForegroundColor Gray
    
    if ($recordId) {
        Write-Host "Updating existing DNS record..." -ForegroundColor Yellow
        $url = "https://api.cloudflare.com/client/v4/zones/$zoneId/dns_records/$recordId"
        $method = "PATCH"
        $context = "Update DNS record $recordName"
    }
    else {
        Write-Host "Creating new DNS record..." -ForegroundColor Yellow
        $url = "https://api.cloudflare.com/client/v4/zones/$zoneId/dns_records"
        $method = "POST"
        $context = "Create DNS record $recordName"
    }
    
    $result = Invoke-CloudflareApiCall -CurlPath $CurlPath -Url $url -ApiToken $CloudflareApiToken -Method $method -JsonData $jsonData -Context $context -Quiet:$Global:QuietMode
    
    if ($result.Success) {
        Write-Host "DNS record operation completed successfully!" -ForegroundColor Green
        Write-Host "Record ID: $($result.Result.id)" -ForegroundColor Green
        return $true
    }
    else {
        Write-Error "Failed to update/create DNS record. See error details above."
        return $false
    }
}

# Main execution
try {
    # Initialize logging system
    Initialize-Logging
    
    # Perform comprehensive Cloudflare setup validation
    $validationResult = Test-CloudflareSetup -ApiToken $CloudflareApiToken -Domain $Domain -CurlPath $CurlPath -Quiet:$Global:QuietMode
    
    if (-not $validationResult.OverallSuccess) {
        throw "Cloudflare setup validation failed. Please check the error messages above and resolve the issues before continuing."
    }
    
    # Use validated zone ID
    $zoneId = $validationResult.ZoneId
    
    # Initialize PGP keys
    Initialize-PGPKeys
    
    # Validate key strength for security
    Write-Host "Validating PGP key security..." -ForegroundColor Yellow
    $keyStrengthOk = Test-PGPKeyStrength -publicKeyPath $PublicKeyPath
    
    if (-not $keyStrengthOk) {
        Write-Warning "Key strength validation failed. Consider regenerating keys for better security."
        Write-Host "To regenerate with enhanced security, delete the keys directory and run the script again." -ForegroundColor Yellow
    }
    
    # Get password for encryption
    $password = Get-Content $PasswordPath -Raw
    $password = $password.Trim()
    
    # Determine which IP versions to process
    $ipVersionsToProcess = @()
    if ($IPVersion -eq "both") {
        $ipVersionsToProcess = @("v4", "v6")
        Write-Host "Processing both IPv4 and IPv6 addresses..." -ForegroundColor Cyan
    }
    else {
        $ipVersionsToProcess = @($IPVersion)
        Write-Host "Processing $IPVersion address only..." -ForegroundColor Cyan
    }
    
    # Process each IP version
    $successCount = 0
    foreach ($currentIPVersion in $ipVersionsToProcess) {
        try {
            Write-Host "`n--- Processing $currentIPVersion ---" -ForegroundColor Magenta
            
            # Get public IP for current version
            $publicIP = Get-PublicIP -ipVersion $currentIPVersion
            
            # Get appropriate subdomain
            $currentSubdomain = Get-SubdomainForIPVersion -baseSubdomain $Subdomain -ipVersion $currentIPVersion -versionMode $IPVersion
            $recordName = "$currentSubdomain.$Domain"
            
            Write-Host "Using subdomain: $currentSubdomain" -ForegroundColor Gray
            
            # Enhanced encryption with additional validation
            Write-Host "Encrypting $currentIPVersion address with PGP..." -ForegroundColor Yellow
            Write-Host "Using advanced encryption parameters for maximum security..." -ForegroundColor Gray
            
            # Validate public key exists and is readable
            if (-not (Test-Path $PublicKeyPath) -or (Get-Item $PublicKeyPath).Length -eq 0) {
                throw "Public key file is missing or empty"
            }
            
            $encryptedIP = Protect-PGP -FilePathPublic $PublicKeyPath -String $publicIP
            
            # Verify encryption was successful
            if (-not $encryptedIP -or $encryptedIP.Length -lt 100) {
                throw "Encryption failed or produced invalid output"
            }
            
            Write-Host "Encryption successful. Encrypted data length: $($encryptedIP.Length) characters" -ForegroundColor Green
            
            # Convert to Base64 with validation
            $base64Data = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($encryptedIP))
            
            # Validate Base64 encoding
            if (-not $base64Data -or $base64Data.Length -eq 0) {
                throw "Base64 encoding failed"
            }
            
            Write-Host "$currentIPVersion encrypted and encoded to Base64 (length: $($base64Data.Length))" -ForegroundColor Green
            
            # Get DNS record ID (if exists)
            $recordId = Get-DnsRecordId -zoneId $zoneId -recordName $recordName
            
            # Update DNS record
            $success = Update-DnsRecord -zoneId $zoneId -recordId $recordId -recordName $recordName -content $base64Data
            
            if ($success) {
                Write-Host "Successfully updated DNS TXT record for $recordName" -ForegroundColor Green
                Write-Host "Public ${currentIPVersion}: $publicIP" -ForegroundColor Cyan
                Write-Host "Record: $recordName" -ForegroundColor Cyan
                $successCount++
            }
            else {
                Write-Warning "Failed to update DNS record for $currentIPVersion"
            }
        }
        catch {
            Write-Warning "Failed to process ${currentIPVersion}: $($_.Exception.Message)"
        }
    }
    
    # Final status report
    Write-QuietLog "`n--- Final Status ---" -ForegroundColor Magenta
    if ($successCount -eq $ipVersionsToProcess.Count) {
        Write-QuietLog "All IP addresses processed successfully! ($successCount/$($ipVersionsToProcess.Count))" -ForegroundColor Green
        
        # Quiet mode output
        if ($Global:QuietMode) {
            Write-Output "SUCCESS"
        }
    }
    elseif ($successCount -gt 0) {
        Write-QuietLog "Partial success: $successCount out of $($ipVersionsToProcess.Count) IP addresses processed" -ForegroundColor Yellow
        
        # Quiet mode output
        if ($Global:QuietMode) {
            Write-Output "FAILURE"
        }
    }
    else {
        # Quiet mode output
        if ($Global:QuietMode) {
            Write-Output "FAILURE"
        }
        throw "Failed to process any IP addresses"
    }
}
catch {
    if ($Global:QuietMode) {
        Add-Content -Path $Global:LogFile -Value "ERROR: Script failed: $($_.Exception.Message)"
        Write-Output "FAILURE"
    } else {
        Write-Error "Script failed: $($_.Exception.Message)"
    }
    exit 1
}