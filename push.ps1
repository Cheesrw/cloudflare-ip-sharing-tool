# IP Address Retrieval and Decryption Script
# Gets encrypted IP from Cloudflare DNS TXT record and decrypts it

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
        $Global:LogFile = "$LogsDir\push_$Timestamp.log"
        
        # Ensure logs directory exists
        if (-not (Test-Path $LogsDir)) {
            New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
        }
        
        # Rotate logs (keep maximum 30 push logs)
        Invoke-LogRotation -ScriptType "push" -LogsDir $LogsDir
        
        # Initialize log file
        $logHeader = @"
=== IP Address Retrieval and Decryption Log ===
Timestamp: $(Get-Date)
Script: push.ps1
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

# Function to get DNS TXT record content with enhanced error handling
function Get-DnsRecordContent {
    param([string]$zoneId, [string]$recordName)
    
    Write-Host "Getting DNS TXT record for: $recordName" -ForegroundColor Yellow
    
    $result = Invoke-CloudflareApiCall -CurlPath $CurlPath -Url "https://api.cloudflare.com/client/v4/zones/$zoneId/dns_records?name=$recordName&type=TXT" -ApiToken $CloudflareApiToken -Context "Get DNS TXT record for $recordName" -Quiet:$Global:QuietMode
    
    if ($result.Success) {
        if ($result.Result -and $result.Result.Count -gt 0) {
            $content = $result.Result[0].content
            Write-Host "DNS TXT record found" -ForegroundColor Green
            Write-Host "Raw content: $($content.Substring(0, [Math]::Min(100, $content.Length)))..." -ForegroundColor Gray
            
            # Cloudflare automatically handles chunking, so the content should be the complete Base64 string
            # However, if it's chunked manually with quotes, we need to handle that
            if ($content -match '^".*".*".*"') {
                # Multiple quoted chunks - remove quotes and join
                Write-Host "Detected manually chunked content, reassembling..." -ForegroundColor Gray
                $chunks = $content -split '"' | Where-Object { $_ -and $_ -ne ' ' -and $_.Trim() -ne '' }
                $content = $chunks -join ''
                Write-Host "Reassembled $($chunks.Count) chunks" -ForegroundColor Gray
            }
            
            return $content
        }
        else {
            throw "DNS TXT record not found for $recordName. Please run get.ps1 first to create the record."
        }
    }
    else {
        throw "Failed to retrieve DNS TXT record for $recordName. Check the error details above."
    }
}

# Function to validate PGP keys exist and are secure
function Test-PGPKeys {
    if (-not (Test-Path $PrivateKeyPath)) {
        throw "Private key not found at: $PrivateKeyPath. Please run the get.ps1 script first to create keys."
    }
    
    if (-not (Test-Path $PasswordPath)) {
        throw "Password file not found at: $PasswordPath. Please run the get.ps1 script first to create keys."
    }
    
    # Validate key file sizes (basic security check)
    $privateKeySize = (Get-Item $PrivateKeyPath).Length
    $passwordSize = (Get-Item $PasswordPath).Length
    
    if ($privateKeySize -lt 1000) {
        throw "Private key file appears to be too small or corrupted"
    }
    
    if ($passwordSize -lt 10) {
        throw "Password file appears to be too small or corrupted"
    }
    
    # Check for enhanced security indicators
    try {
        $privateKeyContent = Get-Content $PrivateKeyPath -Raw
        if ($privateKeyContent -match "4096" -or $privateKeyContent.Length -gt 5000) {
            Write-Host "Enhanced 4096-bit PGP keys detected" -ForegroundColor Green
        }
        elseif ($privateKeyContent -match "2048") {
            Write-Host "Standard 2048-bit PGP keys detected" -ForegroundColor Yellow
        }
        else {
            Write-Host "PGP keys detected (strength unknown)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "PGP keys found (unable to verify strength)" -ForegroundColor Gray
    }
    
    Write-Host "PGP key validation: PASSED" -ForegroundColor Green
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

# Function to validate IP address format
function Test-IPFormat {
    param([string]$ipAddress, [string]$expectedVersion)
    
    if ($expectedVersion -eq "v4") {
        # IPv4 validation
        if ($ipAddress -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            Write-Host "IPv4 address format validation: PASSED" -ForegroundColor Green
            return $true
        }
        else {
            Write-Warning "Decrypted data doesn't appear to be a valid IPv4 address: $ipAddress"
            return $false
        }
    }
    elseif ($expectedVersion -eq "v6") {
        # IPv6 validation (basic check for colons and hex characters)
        if ($ipAddress -match '^[0-9a-fA-F:]+$' -and $ipAddress.Contains(':')) {
            Write-Host "IPv6 address format validation: PASSED" -ForegroundColor Green
            return $true
        }
        else {
            Write-Warning "Decrypted data doesn't appear to be a valid IPv6 address: $ipAddress"
            return $false
        }
    }
    
    return $false
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
    
    # Validate PGP keys exist
    Test-PGPKeys
    
    # Get password for decryption
    $password = Get-Content $PasswordPath -Raw
    $password = $password.Trim()
    
    # Determine which IP versions to process
    $ipVersionsToProcess = @()
    if ($IPVersion -eq "both") {
        $ipVersionsToProcess = @("v4", "v6")
        Write-Host "Retrieving both IPv4 and IPv6 addresses..." -ForegroundColor Cyan
    }
    else {
        $ipVersionsToProcess = @($IPVersion)
        Write-Host "Retrieving $IPVersion address only..." -ForegroundColor Cyan
    }
    
    # Store results
    $results = @{}
    $successCount = 0
    
    # Process each IP version
    foreach ($currentIPVersion in $ipVersionsToProcess) {
        try {
            Write-Host "`n--- Processing $currentIPVersion ---" -ForegroundColor Magenta
            
            # Get appropriate subdomain
            $currentSubdomain = Get-SubdomainForIPVersion -baseSubdomain $Subdomain -ipVersion $currentIPVersion -versionMode $IPVersion
            $recordName = "$currentSubdomain.$Domain"
            
            Write-Host "Using subdomain: $currentSubdomain" -ForegroundColor Gray
            
            # Get DNS TXT record content
            $base64Data = Get-DnsRecordContent -zoneId $zoneId -recordName $recordName
            
            # Decode from Base64 with validation
            Write-Host "Decoding Base64 data for $currentIPVersion..." -ForegroundColor Yellow
            
            # Validate Base64 format
            if (-not $base64Data -or $base64Data.Length -eq 0) {
                throw "Retrieved data is empty or invalid"
            }
            
            if ($base64Data -notmatch '^[A-Za-z0-9+/]*={0,2}$') {
                throw "Retrieved data is not valid Base64 format"
            }
            
            try {
                $encryptedIP = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64Data))
            }
            catch {
                throw "Failed to decode Base64 data: $($_.Exception.Message)"
            }
            
            # Validate encrypted content
            if (-not $encryptedIP -or $encryptedIP.Length -lt 100) {
                throw "Decoded encrypted data appears to be invalid or corrupted"
            }
            
            Write-Host "Base64 decoded successfully. Encrypted data length: $($encryptedIP.Length)" -ForegroundColor Green
            
            # Decrypt IP address with enhanced validation
            Write-Host "Decrypting $currentIPVersion address with PGP..." -ForegroundColor Yellow
            Write-Host "Using secure decryption parameters..." -ForegroundColor Gray
            
            try {
                $decryptedIP = Unprotect-PGP -FilePathPrivate $PrivateKeyPath -Password $password -String $encryptedIP
            }
            catch {
                throw "PGP decryption failed: $($_.Exception.Message). Check password and key integrity."
            }
            
            # Validate decrypted IP format
            if (-not $decryptedIP) {
                throw "Decryption produced empty result"
            }
            
            # Validate IP format based on expected version
            $ipFormatValid = Test-IPFormat -ipAddress $decryptedIP -expectedVersion $currentIPVersion
            if (-not $ipFormatValid) {
                Write-Host "This might be normal if using a different IP version or if the data was corrupted" -ForegroundColor Gray
            }
            
            Write-Host "Successfully retrieved and decrypted $currentIPVersion address!" -ForegroundColor Green
            Write-Host "Decrypted ${currentIPVersion}: $decryptedIP" -ForegroundColor Cyan
            Write-Host "Retrieved from: $recordName" -ForegroundColor Cyan
            
            # Store result
            $results[$currentIPVersion] = @{
                IP = $decryptedIP
                Subdomain = $currentSubdomain
                RecordName = $recordName
            }
            $successCount++
        }
        catch {
            Write-Warning "Failed to process ${currentIPVersion}: $($_.Exception.Message)"
            $results[$currentIPVersion] = $null
        }
    }
    
    # Final status report
    Write-QuietLog "`n--- Final Status ---" -ForegroundColor Magenta
    if ($successCount -eq $ipVersionsToProcess.Count) {
        Write-QuietLog "All IP addresses retrieved successfully! ($successCount/$($ipVersionsToProcess.Count))" -ForegroundColor Green
    }
    elseif ($successCount -gt 0) {
        Write-QuietLog "Partial success: $successCount out of $($ipVersionsToProcess.Count) IP addresses retrieved" -ForegroundColor Yellow
    }
    else {
        throw "Failed to retrieve any IP addresses"
    }
    
    # Display summary or quiet output
    if ($Global:QuietMode) {
        # Quiet mode: only output IP addresses
        foreach ($version in $ipVersionsToProcess) {
            if ($results[$version]) {
                Write-Output $results[$version].IP
            }
        }
    } else {
        # Normal mode: display full summary
        Write-Host "`n--- Summary ---" -ForegroundColor Magenta
        foreach ($version in $ipVersionsToProcess) {
            if ($results[$version]) {
                Write-Host "${version} Address: $($results[$version].IP)" -ForegroundColor Cyan
                Write-Host "${version} Record: $($results[$version].RecordName)" -ForegroundColor Gray
            }
            else {
                Write-Host "${version} Address: FAILED" -ForegroundColor Red
            }
        }
        
        # Return the results (for single version, return just the IP; for both, return the results object)
        if ($IPVersion -eq "both") {
            return $results
        }
        else {
            if ($results[$IPVersion]) {
                return $results[$IPVersion].IP
            }
            else {
                throw "Failed to retrieve $IPVersion address"
            }
        }
    }
}
catch {
    if ($Global:QuietMode) {
        Add-Content -Path $Global:LogFile -Value "ERROR: Script failed: $($_.Exception.Message)"
        # No output on failure in quiet mode for push
    } else {
        Write-Error "Script failed: $($_.Exception.Message)"
    }
    exit 1
}