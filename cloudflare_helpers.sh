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
        
        echo "$response_json" | jq -r '.errors[] | "Code: \(.code // "unknown") | Message: \(.message // "unknown")"' 2>/dev/null | while read -r error_line; do
            local error_code
            error_code=$(echo "$error_line" | grep -o 'Code: [0-9]*' | cut -d' ' -f2)
            
            case "$error_code" in
                1000) print_error "  $error_line (Invalid request)" ;;
                1001) print_error "  $error_line (DNS record not found)" ;;
                1003) print_error "  $error_line (Invalid or missing zone ID)" ;;
                1004) print_error "  $error_line (DNS record already exists)" ;;
                6003) print_error "  $error_line (Invalid request - authentication)" ;;
                9103) print_error "  $error_line (Unknown zone)" ;;
                10000) print_error "  $error_line (Authentication error)" ;;
                *) print_error "  $error_line" ;;
            esac
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
    )
    
    if [[ -n "$data" ]]; then
        curl_args+=(--data "$data")
    fi
    
    local response
    response=$(curl "${curl_args[@]}" 2>/dev/null)
    local curl_exit_code=$?
    
    if [[ $curl_exit_code -ne 0 ]]; then
        print_error "Network error during $context (curl exit code: $curl_exit_code)"
        return 1
    fi
    
    if ! echo "$response" | jq empty 2>/dev/null; then
        print_error "Invalid JSON response during $context"
        return 1
    fi
    
    local success
    success=$(echo "$response" | jq -r '.success // false')
    
    if [[ "$success" == "true" ]]; then
        echo "$response"
        return 0
    else
        get_cloudflare_error_details "$response" "$context"
        return 1
    fi
}

# Function to perform comprehensive Cloudflare setup validation
test_cloudflare_setup() {
    local api_token="$1"
    local domain="$2"
    
    if [[ -z "$api_token" || -z "$domain" ]]; then
        print_error "API token and domain are required"
        return 1
    fi
    
    print_info "" >&2
    print_info "=== Cloudflare Setup Validation ===" >&2
    
    local validation_success=true
    local zone_id=""
    
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
        echo "$zone_id"  # Return zone ID for use by calling scripts
        return 0
    else
        print_error "=== Cloudflare validation FAILED ===" >&2
        print_info "Please address the issues above before proceeding" >&2
        return 1
    fi
}

# Export functions for use in other scripts
# These functions are available when sourcing this script with: source cloudflare_helpers.sh