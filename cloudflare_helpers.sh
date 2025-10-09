#!/bin/bash
# Cloudflare API Helper Library for Linux
# Provides token verification, permission checking, and advanced error handling
# Requires: curl, jq

# Color codes for output (only define if not already set)
if [[ -z "${COLOR_RED:-}" ]]; then
    readonly COLOR_RED='\033[0;31m'
    readonly COLOR_GREEN='\033[0;32m'
    readonly COLOR_YELLOW='\033[1;33m'
    readonly COLOR_BLUE='\033[0;34m'
    readonly COLOR_CYAN='\033[0;36m'
    readonly COLOR_RESET='\033[0m'
fi

# Print colored output
print_status() {
    local color="$1"
    local message="$2"
    echo -e "${color}${message}${COLOR_RESET}"
}

print_error() {
    print_status "$COLOR_RED" "ERROR: $1" >&2
}

print_warning() {
    print_status "$COLOR_YELLOW" "WARNING: $1" >&2
}

print_success() {
    print_status "$COLOR_GREEN" "SUCCESS: $1"
}

print_info() {
    print_status "$COLOR_CYAN" "$1"
}

# Function to verify Cloudflare API token
test_cloudflare_token() {
    local api_token="$1"
    
    if [[ -z "$api_token" ]]; then
        print_error "API token is required"
        return 1
    fi
    
    print_status "$COLOR_YELLOW" "Verifying Cloudflare API token..." >&2
    
    local response
    response=$(curl -s --request GET \
        --url "https://api.cloudflare.com/client/v4/user/tokens/verify" \
        --header "Authorization: Bearer $api_token" \
        --header "Content-Type: application/json" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        print_error "Failed to connect to Cloudflare API"
        return 1
    fi
    
    # Check if response is valid JSON
    if ! echo "$response" | jq empty 2>/dev/null; then
        print_error "Invalid response from Cloudflare API"
        return 1
    fi
    
    local success
    success=$(echo "$response" | jq -r '.success // false')
    
    if [[ "$success" == "true" ]]; then
        local token_id
        local status
        local expires_on
        
        token_id=$(echo "$response" | jq -r '.result.id // "unknown"')
        status=$(echo "$response" | jq -r '.result.status // "unknown"')
        expires_on=$(echo "$response" | jq -r '.result.expires_on // "never"')
        
        print_success "API token is valid" >&2
        print_info "Token ID: $token_id" >&2
        print_info "Status: $status" >&2
        print_info "Expires: $expires_on" >&2
        
        if [[ "$status" != "active" ]]; then
            print_warning "Token status is not active: $status"
            return 1
        fi
        
        # Check expiration
        if [[ "$expires_on" != "never" && "$expires_on" != "null" ]]; then
            local current_time
            local expire_time
            current_time=$(date +%s)
            expire_time=$(date -d "$expires_on" +%s 2>/dev/null)
            
            if [[ $? -eq 0 && $expire_time -lt $current_time ]]; then
                print_error "Token has expired on $expires_on"
                return 1
            fi
        fi
        
        return 0
    else
        local errors
        errors=$(echo "$response" | jq -r '.errors[]?.message // "Unknown error"' 2>/dev/null)
        if [[ -n "$errors" ]]; then
            print_error "Token verification failed:"
            echo "$errors" | while read -r error; do
                print_error "  $error"
            done
        else
            print_error "Token verification failed with unknown error"
        fi
        return 1
    fi
}

# Function to get token permission groups
get_cloudflare_token_permissions() {
    local api_token="$1"
    
    if [[ -z "$api_token" ]]; then
        print_error "API token is required"
        return 1
    fi
    
    print_status "$COLOR_YELLOW" "Checking token permissions..." >&2
    
    local response
    response=$(curl -s --request GET \
        --url "https://api.cloudflare.com/client/v4/user/tokens/verify" \
        --header "Authorization: Bearer $api_token" \
        --header "Content-Type: application/json" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        print_error "Failed to connect to Cloudflare API"
        return 1
    fi
    
    local success
    success=$(echo "$response" | jq -r '.success // false')
    
    if [[ "$success" == "true" ]]; then
        local policies
        policies=$(echo "$response" | jq -r '.result.policies[]?' 2>/dev/null)
        
        if [[ -n "$policies" ]]; then
            print_success "Token permissions found:" >&2
            echo "$response" | jq -r '.result.policies[] | "  Resource: \(.resources // "all") | Permission: \(.permission_groups[]? // "none")"' 2>/dev/null >&2
            
            # Check for DNS write permissions
            local has_dns_write
            has_dns_write=$(echo "$response" | jq -r '.result.policies[] | select(.permission_groups[]? == "c8fed203ed3043cba015a93ad1616681") | .permission_groups[]?' 2>/dev/null)
            
            if [[ -n "$has_dns_write" ]]; then
                print_success "DNS Write permission: FOUND" >&2
                return 0
            else
                print_warning "DNS Write permission: NOT FOUND"
                print_warning "Token may not have sufficient permissions for DNS operations"
                return 1
            fi
        else
            print_warning "No permission details available"
            return 0
        fi
    else
        print_error "Could not check token permissions"
        return 1
    fi
}

# Function to validate zone access
test_cloudflare_zone_access() {
    local api_token="$1"
    local domain="$2"
    
    if [[ -z "$api_token" || -z "$domain" ]]; then
        print_error "API token and domain are required"
        return 1
    fi
    
    print_status "$COLOR_YELLOW" "Validating zone access for domain: $domain" >&2
    
    local response
    response=$(curl -s --request GET \
        --url "https://api.cloudflare.com/client/v4/zones?name=$domain" \
        --header "Authorization: Bearer $api_token" \
        --header "Content-Type: application/json" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        print_error "Failed to connect to Cloudflare API"
        return 1
    fi
    
    local success
    success=$(echo "$response" | jq -r '.success // false')
    
    if [[ "$success" == "true" ]]; then
        local zone_count
        zone_count=$(echo "$response" | jq -r '.result | length')
        
        if [[ "$zone_count" -gt 0 ]]; then
            local zone_id
            local zone_name
            local zone_status
            
            zone_id=$(echo "$response" | jq -r '.result[0].id')
            zone_name=$(echo "$response" | jq -r '.result[0].name')
            zone_status=$(echo "$response" | jq -r '.result[0].status')
            
            print_success "Zone access validated" >&2
            print_info "Zone ID: $zone_id" >&2
            print_info "Zone Name: $zone_name" >&2
            print_info "Zone Status: $zone_status" >&2
            
            if [[ "$zone_status" != "active" ]]; then
                print_warning "Zone status is not active: $zone_status"
            fi
            
            # Return zone ID for use by calling functions
            echo "$zone_id"
            return 0
        else
            print_error "Domain '$domain' not found in your Cloudflare account"
            print_info "Please ensure:" >&2
            print_info "  1. The domain is added to your Cloudflare account" >&2
            print_info "  2. Your API token has access to this zone" >&2
            print_info "  3. The domain name is spelled correctly" >&2
            return 1
        fi
    else
        get_cloudflare_error_details "$response" "zone access validation"
        return 1
    fi
}

# Function to categorize error codes
categorize_cloudflare_error() {
    local error_code="$1"
    
    case "$error_code" in
        # Authentication errors
        10000|10001|10002|10003|10004|10005|10006|10007|10008|10009)
            echo "Authentication"
            ;;
        # Permission errors
        6003|6004|6005|6006|6007|6008|6009|6010|6011|6012)
            echo "Permission"
            ;;
        # Rate limit errors
        10014|10015|10016|10017|10018|10019)
            echo "RateLimit"
            ;;
        # DNS record errors
        1003|1004|1005|1006|1007|1008|1009|1010|1011|1012|1013|1014|1015|1016|1018|1019|1020|1023|1025)
            echo "DNSRecord"
            ;;
        # Zone errors
        1001|1002|1000|1034|1035|1036|1037|1040|1041)
            echo "Zone"
            ;;
        # General errors
        1101|1102|1104|1200)
            echo "General"
            ;;
        *)
            echo "Unknown"
            ;;
    esac
}

# Function to get suggestions for specific error codes
get_error_suggestion() {
    local error_code="$1"
    
    case "$error_code" in
        10000) echo "Check your API token format and validity" ;;
        10001) echo "Token does not have sufficient permissions" ;;
        6003) echo "Token lacks required permissions for this operation" ;;
        1001) echo "DNS resolution error - check domain name" ;;
        1004) echo "Host not configured to serve web traffic" ;;
        1015) echo "Rate limit exceeded - wait before retrying" ;;
        1020) echo "Access denied - check firewall rules or security settings" ;;
        1003) echo "Invalid or missing zone ID - verify domain access" ;;
        1002) echo "Invalid DNS record data format" ;;
        1005) echo "DNS record type not supported" ;;
        1006) echo "DNS record name validation failed" ;;
        1007) echo "DNS record content validation failed" ;;
        1008) echo "DNS record TTL out of range" ;;
        1009) echo "DNS record proxied status conflict" ;;
        1010) echo "DNS record priority required for MX records" ;;
        1011) echo "DNS record service/protocol required for SRV records" ;;
        1012) echo "DNS record port required for SRV records" ;;
        1013) echo "DNS record weight required for SRV records" ;;
        1014) echo "DNS record target required" ;;
        1016) echo "DNS record name conflicts with existing record" ;;
        1018) echo "DNS record content conflicts with existing record" ;;
        1019) echo "DNS record name invalid for record type" ;;
        1023) echo "DNS record name already exists" ;;
        1025) echo "DNS record not allowed for this zone" ;;
        10014) echo "Rate limit exceeded - retry with exponential backoff" ;;
        10015) echo "Daily rate limit exceeded - try again tomorrow" ;;
        10016) echo "Hourly rate limit exceeded - try again in an hour" ;;
        6004) echo "Account not authorized for this action" ;;
        6005) echo "Zone not authorized for this account" ;;
        6006) echo "User not authorized for this zone" ;;
        9103) echo "Zone not found or access denied" ;;
        *) echo "See Cloudflare documentation for error code $error_code" ;;
    esac
}

# Function to parse and categorize Cloudflare API errors
get_cloudflare_error_details() {
    local response_json="$1"
    local context="${2:-API call}"
    
    if ! echo "$response_json" | jq empty 2>/dev/null; then
        print_error "Invalid JSON response during $context"
        return 1
    fi
    
    local errors
    errors=$(echo "$response_json" | jq -r '.errors[]?' 2>/dev/null)
    
    if [[ -n "$errors" ]]; then
        print_error "Cloudflare API errors during $context:"
        print_info ""
        
        echo "$response_json" | jq -r '.errors[] | "\(.code // "unknown")|\(.message // "unknown")"' 2>/dev/null | while IFS='|' read -r error_code error_message; do
            local category
            local suggestion
            
            category=$(categorize_cloudflare_error "$error_code")
            suggestion=$(get_error_suggestion "$error_code")
            
            print_error "  Error Code: $error_code (Category: $category)"
            print_error "  Message: $error_message"
            print_warning "  Suggestion: $suggestion"
            print_info ""
        done
        return 1
    else
        local success
        success=$(echo "$response_json" | jq -r '.success // false')
        if [[ "$success" != "true" ]]; then
            print_error "API call failed during $context (no specific error details)"
            return 1
        fi
    fi
    
    return 0
}

# Function to make Cloudflare API calls with enhanced error handling
invoke_cloudflare_api_call() {
    local url="$1"
    local api_token="$2"
    local method="${3:-GET}"
    local data="$4"
    local context="${5:-API call}"
    local quiet="${6:-false}"
    
    if [[ -z "$url" || -z "$api_token" ]]; then
        print_error "URL and API token are required for $context"
        return 1
    fi
    
    local curl_args=(
        -s
        --request "$method"
        --url "$url"
        --header "Authorization: Bearer $api_token"
        --header "Content-Type: application/json"
        --max-time 30
        --retry 3
        --retry-delay 1
    )
    
    if [[ -n "$data" ]]; then
        curl_args+=(--data "$data")
    fi
    
    local response
    response=$(curl "${curl_args[@]}" 2>/dev/null)
    local curl_exit_code=$?
    
    if [[ $curl_exit_code -ne 0 ]]; then
        local curl_error_msg=""
        case "$curl_exit_code" in
            6) curl_error_msg="Couldn't resolve host" ;;
            7) curl_error_msg="Failed to connect to host" ;;
            28) curl_error_msg="Operation timeout" ;;
            35) curl_error_msg="SSL connect error" ;;
            56) curl_error_msg="Failure in receiving network data" ;;
            *) curl_error_msg="Network error (curl exit code: $curl_exit_code)" ;;
        esac
        
        if [[ "$quiet" != "true" ]]; then
            print_error "Network error during $context: $curl_error_msg"
        fi
        return 1
    fi
    
    if [[ -z "$response" ]]; then
        if [[ "$quiet" != "true" ]]; then
            print_error "Empty response received during $context"
        fi
        return 1
    fi
    
    if ! echo "$response" | jq empty 2>/dev/null; then
        if [[ "$quiet" != "true" ]]; then
            print_error "Invalid JSON response during $context"
            print_info "Response: $response"
        fi
        return 1
    fi
    
    local success
    success=$(echo "$response" | jq -r '.success // false')
    
    if [[ "$success" == "true" ]]; then
        echo "$response"
        return 0
    else
        if [[ "$quiet" != "true" ]]; then
            get_cloudflare_error_details "$response" "$context"
        fi
        return 1
    fi
}

# Function to test network connectivity
test_network_connectivity() {
    local quiet="${1:-false}"
    
    if [[ "$quiet" != "true" ]]; then
        print_info ""
        print_info "=== Network Connectivity Check ==="
    fi
    
    local ipv4_working=false
    local ipv6_working=false
    local cf_api_working=false
    
    # Test IPv4 connectivity
    if [[ "$quiet" != "true" ]]; then
        print_status "$COLOR_YELLOW" "Testing IPv4 connectivity..."
    fi
    
    local ipv4_response
    ipv4_response=$(curl -s --max-time 5 -4 "https://api.ipify.org" 2>/dev/null)
    
    if [[ $? -eq 0 && "$ipv4_response" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        ipv4_working=true
        if [[ "$quiet" != "true" ]]; then
            print_success "IPv4 connectivity: WORKING (IP: $ipv4_response)"
        fi
    else
        if [[ "$quiet" != "true" ]]; then
            print_error "IPv4 connectivity: FAILED"
        fi
    fi
    
    # Test IPv6 connectivity
    if [[ "$quiet" != "true" ]]; then
        print_status "$COLOR_YELLOW" "Testing IPv6 connectivity..."
    fi
    
    local ipv6_response
    ipv6_response=$(curl -s --max-time 5 -6 "https://api6.ipify.org" 2>/dev/null)
    
    if [[ $? -eq 0 && "$ipv6_response" =~ ^[0-9a-fA-F:]+$ ]]; then
        ipv6_working=true
        if [[ "$quiet" != "true" ]]; then
            print_success "IPv6 connectivity: WORKING (IP: $ipv6_response)"
        fi
    else
        if [[ "$quiet" != "true" ]]; then
            print_warning "IPv6 connectivity: FAILED (this is normal if IPv6 is not available)"
        fi
    fi
    
    # Test Cloudflare API connectivity
    if [[ "$quiet" != "true" ]]; then
        print_status "$COLOR_YELLOW" "Testing Cloudflare API connectivity..."
    fi
    
    local cf_response
    cf_response=$(curl -s --max-time 5 "https://api.cloudflare.com/client/v4/zones" 2>/dev/null)
    
    if [[ $? -eq 0 && "$cf_response" == *"success"* ]]; then
        cf_api_working=true
        if [[ "$quiet" != "true" ]]; then
            print_success "Cloudflare API connectivity: WORKING"
        fi
    else
        if [[ "$quiet" != "true" ]]; then
            print_error "Cloudflare API connectivity: FAILED"
        fi
    fi
    
    # Overall connectivity assessment
    local overall_working=false
    if [[ "$ipv4_working" == "true" || "$ipv6_working" == "true" ]]; then
        overall_working=true
    fi
    
    if [[ "$quiet" != "true" ]]; then
        print_info ""
        if [[ "$overall_working" == "true" ]]; then
            print_success "Overall network connectivity: WORKING"
        else
            print_error "Overall network connectivity: FAILED"
        fi
    fi
    
    # Return connectivity status (0 = working, 1 = failed)
    if [[ "$overall_working" == "true" && "$cf_api_working" == "true" ]]; then
        return 0
    else
        return 1
    fi
}

# Function to perform comprehensive Cloudflare setup validation
test_cloudflare_setup() {
    local api_token="$1"
    local domain="$2"
    local include_network_test="${3:-false}"
    
    if [[ -z "$api_token" || -z "$domain" ]]; then
        print_error "API token and domain are required"
        return 1
    fi
    
    print_info "" >&2
    print_info "=== Cloudflare Setup Validation ===" >&2
    
    local validation_success=true
    local zone_id=""
    
    # Optional network connectivity test
    if [[ "$include_network_test" == "true" ]]; then
        print_info "" >&2
        print_info "0. Testing network connectivity..." >&2
        if ! test_network_connectivity; then
            print_warning "Network connectivity issues detected - continuing anyway" >&2
        fi
    fi
    
    # Test 1: Token verification
    print_info "" >&2
    print_info "1. Testing API token validity..." >&2
    if ! test_cloudflare_token "$api_token"; then
        validation_success=false
    fi
    
    # Test 2: Permission verification
    print_info "" >&2
    print_info "2. Checking token permissions..." >&2
    if ! get_cloudflare_token_permissions "$api_token"; then
        print_warning "Permission check completed with warnings"
    fi
    
    # Test 3: Zone access validation
    print_info "" >&2
    print_info "3. Validating zone access..." >&2
    zone_id=$(test_cloudflare_zone_access "$api_token" "$domain")
    if [[ $? -ne 0 ]]; then
        validation_success=false
    fi
    
    print_info "" >&2
    if [[ "$validation_success" == "true" ]]; then
        print_success "=== All Cloudflare validations PASSED ===" >&2
        print_success "✓ Token is valid and active" >&2
        print_success "✓ Zone access confirmed" >&2
        print_success "✓ Ready for DNS operations" >&2
        echo "$zone_id"  # Return zone ID for use by calling scripts
        return 0
    else
        print_error "=== Cloudflare validation FAILED ===" >&2
        print_info "Please address the issues above before proceeding" >&2
        print_info "" >&2
        print_info "Common solutions:" >&2
        print_info "  • Verify your API token is valid and active" >&2
        print_info "  • Ensure the domain is added to your Cloudflare account" >&2
        print_info "  • Check that your token has DNS write permissions" >&2
        print_info "  • Confirm the domain name is spelled correctly" >&2
        return 1
    fi
}

# Export functions for use in other scripts
# These functions are available when sourcing this script with: source cloudflare_helpers.sh