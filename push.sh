#!/bin/bash
# IP Address Retrieval and Decryption Script for Linux
# Gets encrypted IP from Cloudflare DNS TXT record and decrypts it
# Requires: curl, jq, gpg, base64

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source Cloudflare helpers
source "$SCRIPT_DIR/cloudflare_helpers.sh"

# Default values
IP_VERSION="v4"
QUIET_MODE=false

# Usage function
usage() {
    cat << EOF
Usage: $0 -t <token> -d <domain> -s <subdomain> [-v <version>] [-q]

Options:
    -t, --token      Cloudflare API token (required)
    -d, --domain     Domain name (required)
    -s, --subdomain  Subdomain for DNS record (required)
    -v, --version    IP version: v4, v6, or both (default: v4)
    -q, --quiet      Quiet mode: only return IP address(es), log to file
    -h, --help       Show this help message

Examples:
    $0 -t "your_token" -d "example.com" -s "myip"
    $0 -t "your_token" -d "example.com" -s "myip" -v "v6"
    $0 -t "your_token" -d "example.com" -s "myip" -v "both"
    $0 -t "your_token" -d "example.com" -s "myip" -q

Quiet Mode:
    When -q/--quiet is used, the script will:
    - Only output the retrieved IP address(es)
    - Log all details to logs/push_YYYYMMDD_HHMMSS.log
    - Maintain maximum of 30 push logs (auto-delete oldest)
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--token)
                CLOUDFLARE_API_TOKEN="$2"
                shift 2
                ;;
            -d|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            -s|--subdomain)
                SUBDOMAIN="$2"
                shift 2
                ;;
            -v|--version)
                IP_VERSION="$2"
                shift 2
                ;;
            -q|--quiet)
                QUIET_MODE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Validate required parameters
    if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
        print_error "Cloudflare API token is required"
        usage
        exit 1
    fi
    
    if [[ -z "${DOMAIN:-}" ]]; then
        print_error "Domain is required"
        usage
        exit 1
    fi
    
    if [[ -z "${SUBDOMAIN:-}" ]]; then
        print_error "Subdomain is required"
        usage
        exit 1
    fi
    
    # Validate IP version
    if [[ "$IP_VERSION" != "v4" && "$IP_VERSION" != "v6" && "$IP_VERSION" != "both" ]]; then
        print_error "Invalid IP version: $IP_VERSION. Must be v4, v6, or both"
        exit 1
    fi
}

# Define paths
setup_paths() {
    KEYS_PATH="$SCRIPT_DIR/keys"
    PRIVATE_KEY_PATH="$KEYS_PATH/private.asc"
    PASSWORD_PATH="$KEYS_PATH/password.txt"
}

# Logging system
setup_logging() {
    if [[ "$QUIET_MODE" == "true" ]]; then
        LOGS_DIR="$SCRIPT_DIR/logs"
        TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
        LOG_FILE="$LOGS_DIR/push_${TIMESTAMP}.log"
        
        # Ensure logs directory exists
        if [[ ! -d "$LOGS_DIR" ]]; then
            mkdir -p "$LOGS_DIR"
            chmod 755 "$LOGS_DIR"
        fi
        
        # Rotate logs (keep maximum 30 push logs)
        rotate_logs "push"
        
        # Redirect all output to log file in quiet mode
        exec 1> >(tee -a "$LOG_FILE")
        exec 2> >(tee -a "$LOG_FILE" >&2)
        
        echo "=== IP Address Retrieval and Decryption Log ===" >> "$LOG_FILE"
        echo "Timestamp: $(date)" >> "$LOG_FILE"
        echo "Script: push.sh" >> "$LOG_FILE"
        echo "Arguments: $*" >> "$LOG_FILE"
        echo "=============================================" >> "$LOG_FILE"
    fi
}

# Function to rotate logs (keep maximum 30 per script type)
rotate_logs() {
    local script_type="$1"
    local logs_pattern="${LOGS_DIR}/${script_type}_*.log"
    
    # Count existing logs
    local log_count
    log_count=$(find "$LOGS_DIR" -name "${script_type}_*.log" 2>/dev/null | wc -l)
    
    # If we have 30 or more logs, delete the oldest ones
    if [[ $log_count -ge 30 ]]; then
        local logs_to_delete=$((log_count - 29))
        find "$LOGS_DIR" -name "${script_type}_*.log" -type f -printf '%T@ %p\n' 2>/dev/null | \
            sort -n | head -n "$logs_to_delete" | cut -d' ' -f2- | \
            xargs rm -f 2>/dev/null || true
    fi
}

# Override print functions for quiet mode
setup_quiet_output() {
    if [[ "$QUIET_MODE" == "true" ]]; then
        # Store original functions
        _original_print_info() { echo -e "\033[0;36m$1\033[0m"; }
        _original_print_success() { echo -e "\033[0;32mSUCCESS: $1\033[0m"; }
        _original_print_error() { echo -e "\033[0;31mERROR: $1\033[0m" >&2; }
        _original_print_warning() { echo -e "\033[1;33mWARNING: $1\033[0m" >&2; }
        _original_print_status() { echo -e "$1$2\033[0m"; }
        
        # In quiet mode, suppress console output but keep logging
        print_info() { _original_print_info "$1" >> "$LOG_FILE" 2>&1; }
        print_success() { _original_print_success "$1" >> "$LOG_FILE" 2>&1; }
        print_error() { _original_print_error "$1" >> "$LOG_FILE" 2>&1; }
        print_warning() { _original_print_warning "$1" >> "$LOG_FILE" 2>&1; }
        print_status() { _original_print_status "$1" "$2" >> "$LOG_FILE" 2>&1; }
    fi
}

# Function to get Cloudflare zone ID
get_cloudflare_zone_id() {
    local domain="$1"
    
    print_status "$COLOR_YELLOW" "Getting Cloudflare zone ID for domain: $domain"
    
    local response
    response=$(invoke_cloudflare_api_call \
        "https://api.cloudflare.com/client/v4/zones?name=$domain" \
        "$CLOUDFLARE_API_TOKEN" \
        "GET" \
        "" \
        "Get zone ID for $domain")
    
    if [[ $? -eq 0 ]]; then
        local zone_id
        zone_id=$(echo "$response" | jq -r '.result[0].id // empty')
        
        if [[ -n "$zone_id" ]]; then
            echo "$zone_id"
            return 0
        else
            print_error "No zone found for domain: $domain"
            return 1
        fi
    else
        return 1
    fi
}

# Function to get DNS TXT record content
get_dns_record_content() {
    local zone_id="$1"
    local record_name="$2"
    
    print_status "$COLOR_YELLOW" "Getting DNS TXT record for: $record_name" >&2
    
    local response
    response=$(invoke_cloudflare_api_call \
        "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?name=$record_name&type=TXT" \
        "$CLOUDFLARE_API_TOKEN" \
        "GET" \
        "" \
        "Get DNS TXT record for $record_name")
    
    if [[ $? -eq 0 ]]; then
        local record_count
        record_count=$(echo "$response" | jq -r '.result | length')
        
        if [[ "$record_count" -gt 0 ]]; then
            local content
            content=$(echo "$response" | jq -r '.result[0].content // empty')
            
            if [[ -n "$content" ]]; then
                print_success "DNS TXT record found" >&2
                echo "$content"
                return 0
            else
                print_error "DNS TXT record is empty"
                return 1
            fi
        else
            print_error "DNS TXT record not found for: $record_name"
            print_info "Please ensure you have stored an IP address first using get.sh" >&2
            return 1
        fi
    else
        return 1
    fi
}

# Function to validate GPG keys exist and are secure
test_gpg_keys() {
    if [[ ! -f "$PRIVATE_KEY_PATH" ]]; then
        print_error "Private key file not found: $PRIVATE_KEY_PATH"
        print_info "Please run get.sh first to generate GPG keys"
        return 1
    fi
    
    if [[ ! -f "$PASSWORD_PATH" ]]; then
        print_error "Password file not found: $PASSWORD_PATH"
        print_info "Please run get.sh first to generate GPG keys"
        return 1
    fi
    
    # Validate key file sizes (basic security check)
    local private_key_size
    private_key_size=$(stat -c%s "$PRIVATE_KEY_PATH" 2>/dev/null || wc -c < "$PRIVATE_KEY_PATH" 2>/dev/null || echo "0")
    local password_size
    password_size=$(stat -c%s "$PASSWORD_PATH" 2>/dev/null || wc -c < "$PASSWORD_PATH" 2>/dev/null || echo "0")
    
    if [[ "$private_key_size" -lt 1000 ]]; then
        print_error "Private key file appears to be corrupted or too small"
        return 1
    fi
    
    if [[ "$password_size" -lt 10 ]]; then
        print_error "Password file appears to be corrupted or too small"
        return 1
    fi
    
    # Check for enhanced security indicators
    if grep -q "4096" "$PRIVATE_KEY_PATH" 2>/dev/null; then
        print_success "Private key appears to use 4096-bit encryption"
    elif grep -q "2048" "$PRIVATE_KEY_PATH" 2>/dev/null; then
        print_info "Private key appears to use 2048-bit encryption"
    else
        print_warning "Could not determine private key strength"
    fi
    
    print_success "GPG key validation: PASSED"
    return 0
}

# Function to get the appropriate subdomain based on IP version
get_subdomain_for_ip_version() {
    local base_subdomain="$1"
    local ip_version="$2"
    local version_mode="$3"
    
    # Always append IP version suffix to distinguish between IPv4 and IPv6 records
    if [[ "$ip_version" == "v4" ]]; then
        echo "${base_subdomain}4"
    elif [[ "$ip_version" == "v6" ]]; then
        echo "${base_subdomain}6"
    else
        # Fallback to base subdomain if version is unknown
        echo "$base_subdomain"
    fi
}

# Function to validate IP address format
test_ip_format() {
    local ip_address="$1"
    local expected_version="$2"
    
    if [[ "$expected_version" == "v4" ]]; then
        if [[ "$ip_address" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            # Additional validation for valid IPv4 ranges
            local IFS='.'
            local -a octets=($ip_address)
            for octet in "${octets[@]}"; do
                if [[ "$octet" -gt 255 ]]; then
                    return 1
                fi
            done
            return 0
        fi
    elif [[ "$expected_version" == "v6" ]]; then
        # Basic IPv6 format check
        if [[ "$ip_address" =~ ^[0-9a-fA-F:]+$ ]]; then
            return 0
        fi
    fi
    
    return 1
}

# Main execution function
main() {
    parse_args "$@"
    setup_paths
    setup_logging "$@"
    setup_quiet_output
    
    print_info ""
    print_info "=== IP Address Retrieval and Decryption ==="
    print_info "Domain: $DOMAIN"
    print_info "Subdomain: $SUBDOMAIN"
    print_info "IP Version: $IP_VERSION"
    print_info ""
    
    # Perform comprehensive Cloudflare setup validation
    local zone_id
    zone_id=$(test_cloudflare_setup "$CLOUDFLARE_API_TOKEN" "$DOMAIN")
    if [[ $? -ne 0 ]]; then
        print_error "Cloudflare validation failed"
        exit 1
    fi
    
    # Validate GPG keys exist
    if ! test_gpg_keys; then
        print_error "GPG key validation failed"
        exit 1
    fi
    
    # Get password for decryption
    local password
    password=$(cat "$PASSWORD_PATH")
    password=${password%$'\n'}  # Remove trailing newline
    
    # Determine which IP versions to process
    local ip_versions_to_process=()
    if [[ "$IP_VERSION" == "both" ]]; then
        ip_versions_to_process=("v4" "v6")
    else
        ip_versions_to_process=("$IP_VERSION")
    fi
    
    # Store results
    local -A results
    local success_count=0
    local total_count=${#ip_versions_to_process[@]}
    
    for version in "${ip_versions_to_process[@]}"; do
        print_info ""
        print_info "=== Processing $version ==="
        
        # Get appropriate subdomain
        local full_subdomain
        full_subdomain=$(get_subdomain_for_ip_version "$SUBDOMAIN" "$version" "$IP_VERSION")
        local record_name="${full_subdomain}.${DOMAIN}"
        
        print_info "Record name: $record_name"
        
        # Get DNS record content
        local encrypted_content
        if encrypted_content=$(get_dns_record_content "$zone_id" "$record_name"); then
            print_success "Encrypted content retrieved from DNS"
            
            # Decode from base64
            print_status "$COLOR_YELLOW" "Decoding base64 content..."
            local decoded_content
            if decoded_content=$(echo "$encrypted_content" | base64 -d 2>/dev/null); then
                print_success "Base64 decoding successful"
                
                # Decrypt IP address
                print_status "$COLOR_YELLOW" "Decrypting IP address..."
                local decrypted_ip
                if decrypted_ip=$(echo "$decoded_content" | gpg --decrypt --quiet --batch --passphrase "$password" 2>/dev/null); then
                    # Remove any trailing whitespace
                    decrypted_ip=${decrypted_ip%$'\n'}
                    
                    # Validate IP format
                    if test_ip_format "$decrypted_ip" "$version"; then
                        print_success "Successfully decrypted $version IP: $decrypted_ip"
                        results["$version"]="$decrypted_ip"
                        success_count=$((success_count + 1))
                    else
                        print_error "Decrypted content is not a valid $version IP address: $decrypted_ip"
                        results["$version"]="ERROR: Invalid IP format"
                    fi
                else
                    print_error "Failed to decrypt IP address (wrong password or corrupted data)"
                    results["$version"]="ERROR: Decryption failed"
                fi
            else
                print_error "Failed to decode base64 content"
                results["$version"]="ERROR: Base64 decode failed"
            fi
        else
            print_error "Failed to retrieve DNS record for $version"
            results["$version"]="ERROR: DNS record not found"
        fi
    done
    
    print_info ""
    print_info "=== Results Summary ==="
    
    for version in "${ip_versions_to_process[@]}"; do
        local result="${results[$version]:-ERROR: Unknown}"
        if [[ "$result" == ERROR:* ]]; then
            print_error "$version: $result"
        else
            print_success "$version: $result"
        fi
    done
    
    print_info ""
    print_info "Processed: $total_count IP version(s)"
    print_info "Successful: $success_count"
    print_info "Failed: $((total_count - success_count))"
    
    if [[ $success_count -eq $total_count ]]; then
        print_success "All operations completed successfully"
        
        # Quiet mode output - only return IP addresses
        if [[ "$QUIET_MODE" == "true" ]]; then
            for version in "${ip_versions_to_process[@]}"; do
                local result="${results[$version]:-}"
                if [[ "$result" != ERROR:* && -n "$result" ]]; then
                    echo "$result"
                fi
            done
        else
            # Normal mode output for single IP
            if [[ $total_count -eq 1 ]]; then
                local single_result="${results[${ip_versions_to_process[0]}]}"
                if [[ "$single_result" != ERROR:* ]]; then
                    echo ""
                    echo "IP Address: $single_result"
                fi
            fi
        fi
        
        exit 0
    else
        print_error "Some operations failed"
        
        # Quiet mode output for failures
        if [[ "$QUIET_MODE" == "true" ]]; then
            # Return nothing on failure in quiet mode
            exit 1
        fi
        
        exit 1
    fi
}

# Run main function with all arguments
main "$@"