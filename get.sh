#!/bin/bash
# IP Address Retrieval and Encryption Script for Linux
# Gets public IP, encrypts with GPG, and pushes to Cloudflare DNS TXT record
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
    -q, --quiet      Quiet mode: only return success/failure, log to file
    -h, --help       Show this help message

Examples:
    $0 -t "your_token" -d "example.com" -s "myip"
    $0 -t "your_token" -d "example.com" -s "myip" -v "v6"
    $0 -t "your_token" -d "example.com" -s "myip" -v "both"
    $0 -t "your_token" -d "example.com" -s "myip" -q

Quiet Mode:
    When -q/--quiet is used, the script will:
    - Only output "SUCCESS" or "FAILURE"
    - Log all details to logs/get_YYYYMMDD_HHMMSS.log
    - Maintain maximum of 30 get logs (auto-delete oldest)
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
    PUBLIC_KEY_PATH="$KEYS_PATH/public.asc"
    PRIVATE_KEY_PATH="$KEYS_PATH/private.asc"
    PASSWORD_PATH="$KEYS_PATH/password.txt"
    
    # Ensure keys directory exists with secure permissions
    if [[ ! -d "$KEYS_PATH" ]]; then
        mkdir -p "$KEYS_PATH"
        chmod 700 "$KEYS_PATH"
        print_info "Created keys directory with secure permissions"
    fi
}

# Logging system
setup_logging() {
    if [[ "$QUIET_MODE" == "true" ]]; then
        LOGS_DIR="$SCRIPT_DIR/logs"
        TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
        LOG_FILE="$LOGS_DIR/get_${TIMESTAMP}.log"
        
        # Ensure logs directory exists
        if [[ ! -d "$LOGS_DIR" ]]; then
            mkdir -p "$LOGS_DIR"
            chmod 755 "$LOGS_DIR"
        fi
        
        # Rotate logs (keep maximum 30 get logs)
        rotate_logs "get"
        
        # Redirect all output to log file in quiet mode
        exec 1> >(tee -a "$LOG_FILE")
        exec 2> >(tee -a "$LOG_FILE" >&2)
        
        echo "=== IP Address Retrieval and Encryption Log ===" >> "$LOG_FILE"
        echo "Timestamp: $(date)" >> "$LOG_FILE"
        echo "Script: get.sh" >> "$LOG_FILE"
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

# Function to validate GPG key strength
test_gpg_key_strength() {
    local public_key_path="$1"
    
    if [[ ! -f "$public_key_path" ]]; then
        print_error "Public key file not found: $public_key_path"
        return 1
    fi
    
    print_status "$COLOR_YELLOW" "Validating GPG key strength..."
    
    # Import the public key temporarily to check its properties
    local temp_keyring
    temp_keyring=$(mktemp -d)
    
    local key_info
    if key_info=$(gpg --homedir "$temp_keyring" --import "$public_key_path" 2>&1 && \
                  gpg --homedir "$temp_keyring" --list-keys --with-colons 2>/dev/null); then
        
        # Extract key length from the output
        local key_length
        key_length=$(echo "$key_info" | grep "^pub:" | cut -d: -f3)
        
        if [[ -n "$key_length" ]]; then
            print_info "GPG key length: $key_length bits"
            
            if [[ "$key_length" -ge 4096 ]]; then
                print_success "GPG key strength: EXCELLENT (≥4096 bits)"
            elif [[ "$key_length" -ge 2048 ]]; then
                print_success "GPG key strength: GOOD (≥2048 bits)"
            else
                print_warning "GPG key strength: WEAK (<2048 bits)"
            fi
        else
            print_warning "Could not determine key length"
        fi
    else
        print_warning "Could not validate key strength"
    fi
    
    # Clean up temporary keyring
    rm -rf "$temp_keyring"
    return 0
}

# Function to get public IP with fallback
get_public_ip() {
    local ip_version="$1"
    
    print_status "$COLOR_YELLOW" "Getting public IP address ($ip_version)..." >&2
    
    local ip_address=""
    
    if [[ "$ip_version" == "v4" ]]; then
        # IPv4 services
        local ipv4_services=(
            "https://api.ipify.org"
            "https://api4.my-ip.io/ip"
            "https://ipv4.icanhazip.com"
            "https://v4.ident.me"
        )
        
        for service in "${ipv4_services[@]}"; do
            print_info "Trying $service..." >&2
            if ip_address=$(curl -s --max-time 10 -4 "$service" 2>/dev/null); then
                # Validate IPv4 format
                if [[ "$ip_address" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                    print_success "IPv4 address retrieved: $ip_address" >&2
                    echo "$ip_address"
                    return 0
                fi
            fi
            print_warning "Service $service failed or returned invalid IPv4" >&2
        done
        
    elif [[ "$ip_version" == "v6" ]]; then
        # IPv6 services
        local ipv6_services=(
            "https://api6.ipify.org"
            "https://api6.my-ip.io/ip"
            "https://ipv6.icanhazip.com"
            "https://v6.ident.me"
        )
        
        for service in "${ipv6_services[@]}"; do
            print_info "Trying $service..." >&2
            if ip_address=$(curl -s --max-time 10 -6 "$service" 2>/dev/null); then
                # Validate IPv6 format (basic check)
                if [[ "$ip_address" =~ ^[0-9a-fA-F:]+$ ]]; then
                    print_success "IPv6 address retrieved: $ip_address" >&2
                    echo "$ip_address"
                    return 0
                fi
            fi
            print_warning "Service $service failed or returned invalid IPv6" >&2
        done
    fi
    
    print_error "Failed to retrieve $ip_version address from all services"
    return 1
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

# Function to check entropy availability
check_entropy() {
    print_info "Checking system entropy for GPG key generation..."
    
    # Check if /dev/urandom exists
    if [[ ! -c /dev/urandom ]]; then
        print_error "/dev/urandom not available"
        return 1
    fi
    
    # Check available entropy (if /proc/sys/kernel/random/entropy_avail exists)
    if [[ -r /proc/sys/kernel/random/entropy_avail ]]; then
        local entropy
        entropy=$(cat /proc/sys/kernel/random/entropy_avail)
        print_info "Available entropy: $entropy bits"
        
        if [[ "$entropy" -lt 200 ]]; then
            print_warning "Low entropy detected ($entropy bits). Key generation may be slow."
            print_info "Consider installing 'haveged' or 'rng-tools' to improve entropy generation"
            print_info "You can also move the mouse or type randomly to generate entropy"
        else
            print_success "Entropy level is adequate for key generation"
        fi
    else
        print_info "Cannot check entropy level (proceeding anyway)"
    fi
    
    return 0
}

# Function to create GPG keys if they don't exist
initialize_gpg_keys() {
    if [[ ! -f "$PUBLIC_KEY_PATH" || ! -f "$PRIVATE_KEY_PATH" ]]; then
        print_info "GPG keys not found. Generating new PGP key pair..."
        
        # Check entropy availability
        check_entropy
        
        # Generate a strong password
        local password
        if command -v openssl >/dev/null 2>&1; then
            # Use OpenSSL if available for better randomness
            password=$(openssl rand -base64 48 | tr -d "=+/" | cut -c1-64)
        else
            # Fallback to /dev/urandom
            password=$(head -c 64 /dev/urandom | base64 | tr -d "=+/" | cut -c1-64)
        fi
        
        echo "$password" > "$PASSWORD_PATH"
        chmod 600 "$PASSWORD_PATH"
        
        # Create GPG batch configuration
        local gpg_config
        gpg_config=$(mktemp)
        cat > "$gpg_config" << EOF
%echo Generating PGP key pair for IP changer
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: ip-changer-secure
Name-Email: noreply@local
Expire-Date: 0
Passphrase: $password
%no-protection
%commit
%echo Key generation complete
EOF
        
        print_info "Generating 4096-bit RSA key pair (this may take a few minutes)..."
        print_info "If this seems to hang, try generating some entropy by:"
        print_info "  - Moving the mouse cursor"
        print_info "  - Typing random characters"
        print_info "  - Running: sudo apt-get install haveged && sudo systemctl start haveged"
        
        # Set GPG to use a temporary home directory to avoid conflicts
        local temp_gpg_home
        temp_gpg_home=$(mktemp -d)
        export GNUPGHOME="$temp_gpg_home"
        
        # Generate the key pair with verbose error output
        local gpg_output
        if gpg_output=$(gpg --batch --generate-key "$gpg_config" 2>&1); then
            print_success "GPG key pair generated successfully"
            
            # Export public key
            if gpg --armor --export "ip-changer-secure" > "$PUBLIC_KEY_PATH" 2>/dev/null; then
                print_success "Public key exported"
            else
                print_error "Failed to export public key"
                cleanup_temp_gpg_home "$temp_gpg_home"
                rm -f "$gpg_config"
                return 1
            fi
            
            # Export private key
            if gpg --armor --export-secret-keys "ip-changer-secure" > "$PRIVATE_KEY_PATH" 2>/dev/null; then
                print_success "Private key exported"
            else
                print_error "Failed to export private key"
                cleanup_temp_gpg_home "$temp_gpg_home"
                rm -f "$gpg_config"
                return 1
            fi
            
            # Set secure permissions
            chmod 600 "$PRIVATE_KEY_PATH"
            chmod 644 "$PUBLIC_KEY_PATH"
            
            print_success "Keys exported and secured"
            print_success "Password saved to: $PASSWORD_PATH"
        else
            print_error "Failed to generate GPG key pair"
            print_error "GPG output: $gpg_output"
            
            # Provide helpful error messages
            if echo "$gpg_output" | grep -qi "not enough random bytes"; then
                print_error "Insufficient entropy for key generation"
                print_info "Solutions:"
                print_info "1. Install entropy daemon: sudo apt-get install haveged && sudo systemctl start haveged"
                print_info "2. Install rng-tools: sudo apt-get install rng-tools"
                print_info "3. Generate activity: move mouse, type, or run 'find / -type f -exec cat {} \\; > /dev/null 2>&1 &'"
            elif echo "$gpg_output" | grep -qi "permission denied"; then
                print_error "Permission denied - check file permissions and ownership"
            elif echo "$gpg_output" | grep -qi "no such file"; then
                print_error "GPG binary not found or corrupted"
                print_info "Install GPG: sudo apt-get install gnupg"
            else
                print_error "Unknown GPG error occurred"
                print_info "Try running with debug: export GNUPGHOME=\$(mktemp -d) && gpg --batch --generate-key /path/to/config"
            fi
            
            cleanup_temp_gpg_home "$temp_gpg_home"
            rm -f "$gpg_config"
            return 1
        fi
        
        cleanup_temp_gpg_home "$temp_gpg_home"
        rm -f "$gpg_config"
    else
        print_info "Using existing GPG keys"
        test_gpg_key_strength "$PUBLIC_KEY_PATH"
    fi
}

# Function to clean up temporary GPG home directory
cleanup_temp_gpg_home() {
    local temp_home="$1"
    if [[ -n "$temp_home" && -d "$temp_home" ]]; then
        rm -rf "$temp_home"
        unset GNUPGHOME
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

# Function to get DNS record ID
get_dns_record_id() {
    local zone_id="$1"
    local record_name="$2"
    
    print_status "$COLOR_YELLOW" "Getting DNS record ID for: $record_name" >&2
    
    local response
    response=$(invoke_cloudflare_api_call \
        "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?name=$record_name&type=TXT" \
        "$CLOUDFLARE_API_TOKEN" \
        "GET" \
        "" \
        "Get DNS record ID for $record_name")
    
    if [[ $? -eq 0 ]]; then
        local record_id
        record_id=$(echo "$response" | jq -r '.result[0].id // empty')
        
        if [[ -n "$record_id" ]]; then
            echo "$record_id"
            return 0
        else
            print_info "DNS record not found, will create new one" >&2
            return 1
        fi
    else
        return 1
    fi
}

# Function to update or create DNS record
update_dns_record() {
    local zone_id="$1"
    local record_id="$2"
    local record_name="$3"
    local content="$4"
    
    print_info "Content length: ${#content}"
    print_info "Content preview: ${content:0:100}..."
    
    local method="POST"
    local url="https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records"
    local data
    
    if [[ -n "$record_id" ]]; then
        method="PUT"
        url="$url/$record_id"
        print_status "$COLOR_YELLOW" "Updating existing DNS record: $record_name"
    else
        print_status "$COLOR_YELLOW" "Creating new DNS record: $record_name"
    fi
    
    # Prepare JSON data with proper escaping
    data=$(jq -n \
        --arg type "TXT" \
        --arg name "$record_name" \
        --arg content "$content" \
        --arg ttl "300" \
        '{type: $type, name: $name, content: $content, ttl: ($ttl | tonumber)}')
    
    local response
    response=$(invoke_cloudflare_api_call \
        "$url" \
        "$CLOUDFLARE_API_TOKEN" \
        "$method" \
        "$data" \
        "Update DNS record $record_name")
    
    if [[ $? -eq 0 ]]; then
        local result_id
        result_id=$(echo "$response" | jq -r '.result.id // empty')
        
        if [[ -n "$result_id" ]]; then
            print_success "DNS record updated successfully"
            print_info "Record ID: $result_id"
            return 0
        else
            print_error "DNS record operation failed"
            return 1
        fi
    else
        return 1
    fi
}

# Main execution function
main() {
    parse_args "$@"
    setup_paths
    setup_logging "$@"
    setup_quiet_output
    
    print_info ""
    print_info "=== IP Address Retrieval and Encryption ==="
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
    
    # Initialize GPG keys
    if ! initialize_gpg_keys; then
        print_error "Failed to initialize GPG keys"
        exit 1
    fi
    
    # Get password for encryption
    local password
    password=$(cat "$PASSWORD_PATH")
    
    # Determine which IP versions to process
    local ip_versions_to_process=()
    if [[ "$IP_VERSION" == "both" ]]; then
        ip_versions_to_process=("v4" "v6")
    else
        ip_versions_to_process=("$IP_VERSION")
    fi
    
    # Process each IP version
    local success_count=0
    local total_count=${#ip_versions_to_process[@]}
    
    for version in "${ip_versions_to_process[@]}"; do
        print_info ""
        print_info "=== Processing $version ==="
        
        # Get public IP
        local ip_address
        if ip_address=$(get_public_ip "$version"); then
            print_success "IP address retrieved: $ip_address"
            
            # Get appropriate subdomain
            local full_subdomain
            full_subdomain=$(get_subdomain_for_ip_version "$SUBDOMAIN" "$version" "$IP_VERSION")
            local record_name="${full_subdomain}.${DOMAIN}"
            
            print_info "Record name: $record_name"
            
            # Encrypt IP address
            print_status "$COLOR_YELLOW" "Encrypting IP address..."
            local encrypted_content
            if encrypted_content=$(echo "$ip_address" | gpg --symmetric --cipher-algo AES256 --compress-algo 1 --s2k-mode 3 --s2k-digest-algo SHA256 --s2k-count 65536 --quiet --batch --passphrase "$password" --armor 2>/dev/null); then
                print_success "IP address encrypted successfully"
                
                # Encode to base64 for DNS storage
                local base64_content
                base64_content=$(echo "$encrypted_content" | base64 -w 0)
                
                # Get existing record ID (if any)
                local record_id
                record_id=$(get_dns_record_id "$zone_id" "$record_name")
                
                # Update or create DNS record
                if update_dns_record "$zone_id" "$record_id" "$record_name" "$base64_content"; then
                    print_success "Successfully stored encrypted $version IP in DNS record"
                    success_count=$((success_count + 1))
                else
                    print_error "Failed to store encrypted $version IP in DNS record"
                fi
            else
                print_error "Failed to encrypt IP address"
            fi
        else
            print_error "Failed to retrieve $version IP address"
        fi
    done
    
    print_info ""
    print_info "=== Summary ==="
    print_info "Processed: $total_count IP version(s)"
    print_info "Successful: $success_count"
    print_info "Failed: $((total_count - success_count))"
    
    if [[ $success_count -eq $total_count ]]; then
        print_success "All operations completed successfully"
        
        # Quiet mode output
        if [[ "$QUIET_MODE" == "true" ]]; then
            echo "SUCCESS"
        fi
        exit 0
    else
        print_error "Some operations failed"
        
        # Quiet mode output
        if [[ "$QUIET_MODE" == "true" ]]; then
            echo "FAILURE"
        fi
        exit 1
    fi
}

# Run main function with all arguments
main "$@"