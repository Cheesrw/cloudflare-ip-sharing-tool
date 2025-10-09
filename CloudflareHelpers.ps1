# Cloudflare API Helper Library
# Provides token verification, permission checking, and advanced error handling

# Function to verify Cloudflare API token
function Test-CloudflareToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiToken,
        
        [Parameter(Mandatory = $true)]
        [string]$CurlPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    
    if (-not $Quiet) {
        Write-Host "Verifying Cloudflare API token..." -ForegroundColor Yellow
    }
    
    try {
        $response = & $CurlPath -s --request GET `
            --url "https://api.cloudflare.com/client/v4/user/tokens/verify" `
            --header "Authorization: Bearer $ApiToken" `
            --header "Content-Type: application/json"
        
        $tokenData = $response | ConvertFrom-Json
        
        if ($tokenData.success -and $tokenData.result) {
            $status = $tokenData.result.status
            $tokenId = $tokenData.result.id
            $expiresOn = $tokenData.result.expires_on
            $notBefore = $tokenData.result.not_before
            
            if (-not $Quiet) {
                Write-Host "Token verification: SUCCESS" -ForegroundColor Green
                Write-Host "Token ID: $tokenId" -ForegroundColor Gray
                Write-Host "Status: $status" -ForegroundColor Gray
            }
            
            if ($expiresOn) {
                $expiryDate = [DateTime]::Parse($expiresOn)
                if ($expiryDate -lt (Get-Date)) {
                    throw "Token has expired on $expiresOn"
                }
                if (-not $Quiet) {
                    Write-Host "Expires: $expiresOn" -ForegroundColor Gray
                }
            }
            
            if ($notBefore) {
                $notBeforeDate = [DateTime]::Parse($notBefore)
                if ($notBeforeDate -gt (Get-Date)) {
                    throw "Token is not yet valid (not before: $notBefore)"
                }
            }
            
            if ($status -ne "active") {
                throw "Token status is '$status' (expected 'active')"
            }
            
            return $true
        }
        else {
            $errorMsg = "Token verification failed"
            if ($tokenData.errors -and $tokenData.errors.Count -gt 0) {
                $errorDetails = ($tokenData.errors | ForEach-Object { "Code $($_.code): $($_.message)" }) -join "; "
                $errorMsg += " - $errorDetails"
            }
            throw $errorMsg
        }
    }
    catch {
        if ($_.Exception.Message -like "*Token*") {
            throw $_.Exception.Message
        }
        else {
            throw "Failed to verify token: $($_.Exception.Message). Check your internet connection and token format."
        }
    }
}

# Function to get token permission groups
function Get-CloudflareTokenPermissions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiToken,
        
        [Parameter(Mandatory = $true)]
        [string]$CurlPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    
    if (-not $Quiet) {
        Write-Host "Checking token permissions..." -ForegroundColor Yellow
    }
    
    try {
        $response = & $CurlPath -s --request GET `
            --url "https://api.cloudflare.com/client/v4/user/tokens/permission_groups" `
            --header "Authorization: Bearer $ApiToken" `
            --header "Content-Type: application/json"
        
        $permissionData = $response | ConvertFrom-Json
        
        if ($permissionData.success -and $permissionData.result) {
            if (-not $Quiet) {
                Write-Host "Permission groups retrieved successfully" -ForegroundColor Green
            }
            
            # Look for DNS Write permission
            $dnsWritePermission = $permissionData.result | Where-Object { 
                $_.name -like "*DNS*Write*" -or 
                $_.name -like "*Zone*Write*" -or 
                $_.scopes -contains "com.cloudflare.api.account.zone" 
            }
            
            if ($dnsWritePermission) {
                if (-not $Quiet) {
                    Write-Host "DNS Write permissions found:" -ForegroundColor Green
                    foreach ($perm in $dnsWritePermission) {
                        Write-Host "  - $($perm.name) (ID: $($perm.id))" -ForegroundColor Gray
                        Write-Host "    Scopes: $($perm.scopes -join ', ')" -ForegroundColor Gray
                    }
                }
                return $true
            }
            else {
                if (-not $Quiet) {
                    Write-Warning "No DNS Write permissions found in available permission groups"
                    Write-Host "Available permission groups:" -ForegroundColor Yellow
                    foreach ($perm in $permissionData.result | Select-Object -First 10) {
                        Write-Host "  - $($perm.name)" -ForegroundColor Gray
                    }
                    if ($permissionData.result.Count -gt 10) {
                        Write-Host "  ... and $($permissionData.result.Count - 10) more" -ForegroundColor Gray
                    }
                }
                return $false
            }
        }
        else {
            if (-not $Quiet) {
                Write-Warning "Failed to retrieve permission groups"
                $permissionIssues = $permissionData['errors']
                if ($permissionIssues) {
                    foreach ($permIssue in $permissionIssues) {
                        Write-Host "Error $($permIssue.code): $($permIssue.message)" -ForegroundColor Red
                    }
                }
            }
            return $false
        }
    }
    catch {
        if (-not $Quiet) {
            Write-Warning "Could not check token permissions: $($_.Exception.Message)"
        }
        return $false
    }
}

# Function to validate zone access
function Test-CloudflareZoneAccess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiToken,
        
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $true)]
        [string]$CurlPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    
    if (-not $Quiet) {
        Write-Host "Validating zone access for domain: $Domain" -ForegroundColor Yellow
    }
    
    try {
        $response = & $CurlPath -s --request GET `
            --url "https://api.cloudflare.com/client/v4/zones?name=$Domain" `
            --header "Authorization: Bearer $ApiToken" `
            --header "Content-Type: application/json"
        
        $zoneData = $response | ConvertFrom-Json
        
        if ($zoneData.success) {
            if ($zoneData.result -and $zoneData.result.Count -gt 0) {
                $zone = $zoneData.result[0]
                if (-not $Quiet) {
                    Write-Host "Zone access validation: SUCCESS" -ForegroundColor Green
                    Write-Host "Zone ID: $($zone.id)" -ForegroundColor Gray
                    Write-Host "Zone Name: $($zone.name)" -ForegroundColor Gray
                    Write-Host "Zone Status: $($zone.status)" -ForegroundColor Gray
                    
                    if ($zone.status -ne "active") {
                        Write-Warning "Zone status is '$($zone.status)' - this may cause issues"
                    }
                }
                
                return @{
                    Success = $true
                    ZoneId = $zone.id
                    ZoneName = $zone.name
                    ZoneStatus = $zone.status
                }
            }
            else {
                throw "Domain '$Domain' not found in your Cloudflare account. Please check the domain name and ensure it's added to your account."
            }
        }
        else {
            $errorMsg = "Zone access validation failed"
            if ($zoneData.errors -and $zoneData.errors.Count -gt 0) {
                $errorDetails = ($zoneData.errors | ForEach-Object { 
                    $msg = "Code $($_.code): $($_.message)"
                    if ($_.code -eq 10000) {
                        $msg += " (Authentication error - check your API token)"
                    }
                    elseif ($_.code -eq 6003) {
                        $msg += " (Invalid or forbidden request - check token permissions)"
                    }
                    elseif ($_.code -eq 1001) {
                        $msg += " (DNS resolution error)"
                    }
                    return $msg
                }) -join "; "
                $errorMsg += " - $errorDetails"
            }
            throw $errorMsg
        }
    }
    catch {
        if ($_.Exception.Message -like "*Domain*not found*" -or $_.Exception.Message -like "*Zone*") {
            throw $_.Exception.Message
        }
        else {
            throw "Failed to validate zone access: $($_.Exception.Message)"
        }
    }
}

# Function to parse and categorize Cloudflare API errors
function Get-CloudflareErrorDetails {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResponseJson,
        
        [Parameter(Mandatory = $false)]
        [string]$Context = "API call"
    )
    
    try {
        $errorData = $ResponseJson | ConvertFrom-Json
        $apiErrors = $errorData['errors']
        
        if ($apiErrors -and $apiErrors.Count -gt 0) {
            $errorCategories = @{
                Authentication = @(10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009)
                Permission = @(6003, 6004, 6005, 6006, 6007, 6008, 6009, 6010, 6011, 6012)
                RateLimit = @(10014, 10015, 10016, 10017, 10018, 10019)
                DNSRecord = @(1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016, 1018, 1019, 1020, 1023, 1025)
                Zone = @(1001, 1002, 1000, 1034, 1035, 1036, 1037, 1040, 1041)
                General = @(1101, 1102, 1104, 1200)
            }
            
            $detailedIssues = @()
            
            foreach ($issue in $apiErrors) {
                $category = "Unknown"
                foreach ($cat in $errorCategories.Keys) {
                    if ($errorCategories[$cat] -contains $issue.code) {
                        $category = $cat
                        break
                    }
                }
                
                $suggestion = ""
                switch ($issue.code) {
                    10000 { $suggestion = "Check your API token format and validity" }
                    10001 { $suggestion = "Token does not have sufficient permissions" }
                    6003 { $suggestion = "Token lacks required permissions for this operation" }
                    1001 { $suggestion = "DNS resolution error - check domain name" }
                    1004 { $suggestion = "Host not configured to serve web traffic" }
                    1015 { $suggestion = "Rate limit exceeded - wait before retrying" }
                    1020 { $suggestion = "Access denied - check firewall rules or security settings" }
                    default { $suggestion = "See Cloudflare documentation for error code $($issue.code)" }
                }
                
                $detailedIssues += @{
                    Code = $issue.code
                    Message = $issue.message
                    Category = $category
                    Suggestion = $suggestion
                    DocumentationUrl = $issue.documentation_url
                }
            }
            
            return @{
                HasErrors = $true
                Errors = $detailedIssues
                Context = $Context
            }
        }
        else {
            return @{
                HasErrors = $false
                Context = $Context
            }
        }
    }
    catch {
        return @{
            HasErrors = $true
            ParseError = $true
            RawResponse = $ResponseJson
            Context = $Context
            Message = "Failed to parse error response: $($_.Exception.Message)"
        }
    }
}

# Function to display formatted error information
function Show-CloudflareError {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ErrorDetails,
        
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    
    if ($ErrorDetails.HasErrors -and -not $Quiet) {
        Write-Host "`n--- Cloudflare API Error Details ---" -ForegroundColor Red
        Write-Host "Context: $($ErrorDetails.Context)" -ForegroundColor Yellow
        
        if ($ErrorDetails.ParseError) {
            Write-Host "Error: $($ErrorDetails.Message)" -ForegroundColor Red
            Write-Host "Raw Response: $($ErrorDetails.RawResponse)" -ForegroundColor Gray
            return
        }
        
        $detailIssues = $ErrorDetails['Errors']
        if ($detailIssues) {
            foreach ($issueInfo in $detailIssues) {
                Write-Host "`nError Code: $($issueInfo.Code) (Category: $($issueInfo.Category))" -ForegroundColor Red
                Write-Host "Message: $($issueInfo.Message)" -ForegroundColor Red
                if ($issueInfo.Suggestion) {
                    Write-Host "Suggestion: $($issueInfo.Suggestion)" -ForegroundColor Yellow
                }
                if ($issueInfo.DocumentationUrl) {
                    Write-Host "Documentation: $($issueInfo.DocumentationUrl)" -ForegroundColor Cyan
                }
            }
            
            Write-Host "`n--- End Error Details ---`n" -ForegroundColor Red
        }
    }
}

# Function to make Cloudflare API calls with enhanced error handling
function Invoke-CloudflareApiCall {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CurlPath,
        
        [Parameter(Mandatory = $true)]
        [string]$Url,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiToken,
        
        [Parameter(Mandatory = $false)]
        [string]$Method = "GET",
        
        [Parameter(Mandatory = $false)]
        [string]$JsonData = $null,
        
        [Parameter(Mandatory = $false)]
        [string]$Context = "API call",
        
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    
    try {
        $curlArgs = @(
            "-s"
            "--request", $Method
            "--url", $Url
            "--header", "Authorization: Bearer $ApiToken"
            "--header", "Content-Type: application/json"
        )
        
        if ($JsonData -and ($Method -eq "POST" -or $Method -eq "PATCH" -or $Method -eq "PUT")) {
            # Create temporary file for JSON data
            $tempFile = [System.IO.Path]::GetTempFileName()
            try {
                [System.IO.File]::WriteAllText($tempFile, $JsonData, [System.Text.UTF8Encoding]::new($false))
                $curlArgs += @("--data-binary", "@$tempFile")
                
                $response = & $CurlPath @curlArgs
            }
            finally {
                if (Test-Path $tempFile) {
                    Remove-Item $tempFile -Force
                }
            }
        }
        else {
            $response = & $CurlPath @curlArgs
        }
        
        if (-not $response) {
            throw "No response received from Cloudflare API"
        }
        
        $responseData = $response | ConvertFrom-Json
        
        if ($responseData.success) {
            return @{
                Success = $true
                Result = $responseData.result
                Messages = $responseData.messages
            }
        }
        else {
            $errorDetails = Get-CloudflareErrorDetails -ResponseJson $response -Context $Context
            Show-CloudflareError -ErrorDetails $errorDetails -Quiet:$Quiet
            
            return @{
                Success = $false
                ErrorDetails = $errorDetails
                RawResponse = $response
            }
        }
    }
    catch {
        if (-not $Quiet) {
            Write-Error "Failed to make Cloudflare API call ($Context): $($_.Exception.Message)"
        }
        return @{
            Success = $false
            Exception = $_.Exception.Message
            Context = $Context
        }
    }
}

# Function to test network connectivity
function Test-NetworkConnectivity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CurlPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    
    if (-not $Quiet) {
        Write-Host "`n=== Network Connectivity Check ===" -ForegroundColor Cyan
    }
    
    $connectivityResults = @{
        IPv4Connectivity = $false
        IPv6Connectivity = $false
        CloudflareAPIConnectivity = $false
        OverallConnectivity = $false
    }
    
    try {
        # Test IPv4 connectivity
        if (-not $Quiet) {
            Write-Host "Testing IPv4 connectivity..." -ForegroundColor Yellow
        }
        try {
            $ipv4Response = & $CurlPath -s --max-time 5 -4 "https://api.ipify.org" 2>$null
            if ($ipv4Response -and $ipv4Response.Trim() -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                if (-not $Quiet) {
                    Write-Host "IPv4 connectivity: WORKING" -ForegroundColor Green
                }
                $connectivityResults.IPv4Connectivity = $true
            } else {
                if (-not $Quiet) {
                    Write-Host "IPv4 connectivity: FAILED" -ForegroundColor Red
                }
            }
        }
        catch {
            if (-not $Quiet) {
                Write-Host "IPv4 connectivity: FAILED ($($_.Exception.Message))" -ForegroundColor Red
            }
        }
        
        # Test IPv6 connectivity
        if (-not $Quiet) {
            Write-Host "Testing IPv6 connectivity..." -ForegroundColor Yellow
        }
        try {
            $ipv6Response = & $CurlPath -s --max-time 5 -6 "https://api6.ipify.org" 2>$null
            if ($ipv6Response -and $ipv6Response.Trim() -match '^[0-9a-fA-F:]+$') {
                if (-not $Quiet) {
                    Write-Host "IPv6 connectivity: WORKING" -ForegroundColor Green
                }
                $connectivityResults.IPv6Connectivity = $true
            } else {
                if (-not $Quiet) {
                    Write-Host "IPv6 connectivity: FAILED (this is normal if IPv6 is not available)" -ForegroundColor Yellow
                }
            }
        }
        catch {
            if (-not $Quiet) {
                Write-Host "IPv6 connectivity: FAILED (this is normal if IPv6 is not available)" -ForegroundColor Yellow
            }
        }
        
        # Test Cloudflare API connectivity
        if (-not $Quiet) {
            Write-Host "Testing Cloudflare API connectivity..." -ForegroundColor Yellow
        }
        try {
            $cfResponse = & $CurlPath -s --max-time 5 "https://api.cloudflare.com/client/v4/zones" 2>$null
            if ($cfResponse -and $cfResponse -like "*success*") {
                if (-not $Quiet) {
                    Write-Host "Cloudflare API connectivity: WORKING" -ForegroundColor Green
                }
                $connectivityResults.CloudflareAPIConnectivity = $true
            } else {
                if (-not $Quiet) {
                    Write-Host "Cloudflare API connectivity: FAILED" -ForegroundColor Red
                }
            }
        }
        catch {
            if (-not $Quiet) {
                Write-Host "Cloudflare API connectivity: FAILED ($($_.Exception.Message))" -ForegroundColor Red
            }
        }
        
        # Overall connectivity assessment
        $connectivityResults.OverallConnectivity = $connectivityResults.IPv4Connectivity -or $connectivityResults.IPv6Connectivity
        
        if (-not $Quiet) {
            if ($connectivityResults.OverallConnectivity) {
                Write-Host "`nOverall network connectivity: WORKING" -ForegroundColor Green
            } else {
                Write-Host "`nOverall network connectivity: FAILED" -ForegroundColor Red
            }
        }
        
        return $connectivityResults
    }
    catch {
        if (-not $Quiet) {
            Write-Warning "Network connectivity test failed: $($_.Exception.Message)"
        }
        return $connectivityResults
    }
}

# Function to perform comprehensive Cloudflare setup validation
function Test-CloudflareSetup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiToken,
        
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $true)]
        [string]$CurlPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeNetworkTest,
        
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    
    if (-not $Quiet) {
        Write-Host "`n=== Cloudflare Setup Validation ===" -ForegroundColor Cyan
    }
    
    $validationResults = @{
        TokenValid = $false
        PermissionsValid = $false
        ZoneAccessValid = $false
        ZoneId = $null
        OverallSuccess = $false
        NetworkConnectivity = $null
    }
    
    try {
        # Optional network connectivity test
        if ($IncludeNetworkTest) {
            $validationResults.NetworkConnectivity = Test-NetworkConnectivity -CurlPath $CurlPath -Quiet:$Quiet
        }
        
        # 1. Verify token
        $validationResults.TokenValid = Test-CloudflareToken -ApiToken $ApiToken -CurlPath $CurlPath -Quiet:$Quiet
        
        # 2. Check permissions
        $validationResults.PermissionsValid = Get-CloudflareTokenPermissions -ApiToken $ApiToken -CurlPath $CurlPath -Quiet:$Quiet
        
        # 3. Test zone access
        $zoneResult = Test-CloudflareZoneAccess -ApiToken $ApiToken -Domain $Domain -CurlPath $CurlPath -Quiet:$Quiet
        $validationResults.ZoneAccessValid = $zoneResult.Success
        $validationResults.ZoneId = $zoneResult.ZoneId
        
        # Overall success
        $validationResults.OverallSuccess = $validationResults.TokenValid -and 
                                          $validationResults.ZoneAccessValid
        
        if ($validationResults.OverallSuccess) {
            if (-not $Quiet) {
                Write-Host "`n=== Validation Complete: SUCCESS ===" -ForegroundColor Green
                Write-Host "✓ Token is valid and active" -ForegroundColor Green
                Write-Host "✓ Zone access confirmed" -ForegroundColor Green
                if ($validationResults.PermissionsValid) {
                    Write-Host "✓ DNS Write permissions detected" -ForegroundColor Green
                }
                else {
                    Write-Host "⚠ Could not verify DNS Write permissions (but zone access works)" -ForegroundColor Yellow
                }
            }
        }
        else {
            if (-not $Quiet) {
                Write-Host "`n=== Validation Complete: FAILED ===" -ForegroundColor Red
                if (-not $validationResults.TokenValid) {
                    Write-Host "✗ Token validation failed" -ForegroundColor Red
                }
                if (-not $validationResults.ZoneAccessValid) {
                    Write-Host "✗ Zone access failed" -ForegroundColor Red
                }
            }
        }
        
        return $validationResults
    }
    catch {
        if (-not $Quiet) {
            Write-Host "`n=== Validation Complete: ERROR ===" -ForegroundColor Red
            Write-Error "Setup validation failed: $($_.Exception.Message)"
        }
        return $validationResults
    }
}

# Functions are automatically available when dot-sourcing this script
# To use: . .\CloudflareHelpers.ps1