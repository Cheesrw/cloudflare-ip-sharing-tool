#!/bin/bash
# IP Changer Script Runner for Linux
# Interactive menu interface for IP changer scripts

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration - Edit these values
CLOUDFLARE_TOKEN="example"
DOMAIN="example.org"
SUBDOMAIN="example"

# Color codes
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_RESET='\033[0m'

# Print colored output
print_status() {
    local color="$1"
    local message="$2"
    echo -e "${color}${message}${COLOR_RESET}"
}

print_error() {
    print_status "$COLOR_RED" "ERROR: $1" >&2
}

print_success() {
    print_status "$COLOR_GREEN" "SUCCESS: $1"
}

print_warning() {
    print_status "$COLOR_YELLOW" "WARNING: $1" >&2
}

print_info() {
    print_status "$COLOR_CYAN" "$1"
}

print_header() {
    print_status "$COLOR_BLUE" "$1"
}

# Function to check if script files exist
check_script_files() {
    local missing_files=()
    
    if [[ ! -f "$SCRIPT_DIR/check_requirements.sh" ]]; then
        missing_files+=("check_requirements.sh")
    fi
    
    if [[ ! -f "$SCRIPT_DIR/cloudflare_helpers.sh" ]]; then
        missing_files+=("cloudflare_helpers.sh")
    fi
    
    if [[ ! -f "$SCRIPT_DIR/get.sh" ]]; then
        missing_files+=("get.sh")
    fi
    
    if [[ ! -f "$SCRIPT_DIR/push.sh" ]]; then
        missing_files+=("push.sh")
    fi
    
    if [[ ${#missing_files[@]} -gt 0 ]]; then
        print_error "Missing required script files:"
        for file in "${missing_files[@]}"; do
            print_error "  $file"
        done
        print_info "Please ensure all IP changer script files are in the same directory as this runner."
        return 1
    fi
    
    return 0
}

# Function to make scripts executable
make_scripts_executable() {
    local scripts=("check_requirements.sh" "cloudflare_helpers.sh" "get.sh" "push.sh")
    
    for script in "${scripts[@]}"; do
        if [[ -f "$SCRIPT_DIR/$script" ]]; then
            chmod +x "$SCRIPT_DIR/$script" 2>/dev/null || {
                print_warning "Could not make $script executable (permission denied)"
            }
        fi
    done
}

# Function to check configuration for example values
check_configuration() {
    local config_errors=()
    
    # Check if any configuration values contain "example"
    if [[ "$CLOUDFLARE_TOKEN" == *"example"* ]]; then
        config_errors+=("CLOUDFLARE_TOKEN contains 'example' - please update with your real API token")
    fi
    
    if [[ "$DOMAIN" == *"example"* ]]; then
        config_errors+=("DOMAIN contains 'example' - please update with your real domain")
    fi
    
    if [[ "$SUBDOMAIN" == *"example"* ]]; then
        config_errors+=("SUBDOMAIN contains 'example' - please update with your real subdomain")
    fi
    
    # Check for completely empty values
    if [[ -z "$CLOUDFLARE_TOKEN" ]]; then
        config_errors+=("CLOUDFLARE_TOKEN is empty - please set your API token")
    fi
    
    if [[ -z "$DOMAIN" ]]; then
        config_errors+=("DOMAIN is empty - please set your domain")
    fi
    
    if [[ -z "$SUBDOMAIN" ]]; then
        config_errors+=("SUBDOMAIN is empty - please set your subdomain")
    fi
    
    # Check for short/invalid values
    if [[ ${#CLOUDFLARE_TOKEN} -lt 10 ]]; then
        config_errors+=("CLOUDFLARE_TOKEN appears too short - please verify your API token")
    fi
    
    if [[ ${#DOMAIN} -lt 3 ]]; then
        config_errors+=("DOMAIN appears too short - please verify your domain")
    fi
    
    if [[ ${#SUBDOMAIN} -lt 1 ]]; then
        config_errors+=("SUBDOMAIN appears too short - please verify your subdomain")
    fi
    
    if [[ ${#config_errors[@]} -gt 0 ]]; then
        print_error "Configuration validation failed:"
        for error in "${config_errors[@]}"; do
            print_error "  $error"
        done
        print_info ""
        print_info "Please edit this script ($0) and update the configuration values at the top:"
        print_info "  CLOUDFLARE_TOKEN - Your Cloudflare API token"
        print_info "  DOMAIN - Your domain name (e.g., example.com)"
        print_info "  SUBDOMAIN - Your subdomain prefix (e.g., myip)"
        return 1
    fi
    
    print_success "Configuration validation: PASSED"
    return 0
}

# Function to check requirements
check_requirements() {
    print_info "Checking system requirements..."
    
    if [[ -f "$SCRIPT_DIR/check_requirements.sh" ]]; then
        if bash "$SCRIPT_DIR/check_requirements.sh" >/dev/null 2>&1; then
            print_success "Requirements check: PASSED"
            return 0
        else
            print_error "Requirements check: FAILED"
            print_info ""
            print_info "Running detailed requirements check..."
            bash "$SCRIPT_DIR/check_requirements.sh" --install-commands
            return 1
        fi
    else
        print_warning "Requirements checker not found, skipping requirements check"
        return 0
    fi
}

# Function to pause and wait for user input
pause_for_input() {
    echo ""
    read -p "Press Enter to continue..."
    echo ""
}

# Function to run a script with error handling
run_script() {
    local script="$1"
    local description="$2"
    shift 2
    local args=("$@")
    
    print_info ""
    print_info "$description"
    
    if [[ -f "$SCRIPT_DIR/$script" ]]; then
        if bash "$SCRIPT_DIR/$script" "${args[@]}"; then
            print_success "Operation completed successfully"
        else
            local exit_code=$?
            print_error "Operation failed (exit code: $exit_code)"
            
            # Provide specific help for common issues
            if [[ "$script" == "get.sh" ]]; then
                print_info ""
                print_warning "If you're seeing GPG key generation failures:"
                print_info "1. Try the 'Fix GPG/entropy issues' option (menu item 9)"
                print_info "2. Install entropy daemon: sudo apt-get install haveged"
                print_info "3. Check system requirements with menu item 7"
                print_info "4. For more help, run: ./fix_gpg_entropy.sh --help"
            fi
        fi
    else
        print_error "Script not found: $script"
    fi
}

# Function to show the main menu
show_menu() {
    clear
    print_header "==============================="
    print_header "   IP Changer Script Runner"
    print_header "==============================="
    echo ""
    print_info "Configuration:"
    print_info "  Domain: $DOMAIN"
    print_info "  Subdomain: $SUBDOMAIN"
    print_info "  Token: ${CLOUDFLARE_TOKEN:0:8}...${CLOUDFLARE_TOKEN: -8}"
    echo ""
    print_info "Select an option:"
    echo "  1. Store current IP address (IPv4 only)"
    echo "  2. Store current IP address (IPv6 only)"
    echo "  3. Store current IP address (Both IPv4 and IPv6)"
    echo "  4. Retrieve stored IP address (IPv4 only)"
    echo "  5. Retrieve stored IP address (IPv6 only)"
    echo "  6. Retrieve stored IP address (Both IPv4 and IPv6)"
    echo "  7. Check system requirements"
    echo "  8. Test Cloudflare connectivity"
    echo "  9. Fix GPG/entropy issues"
    echo " 10. Exit"
    echo ""
}

# Function to test Cloudflare connectivity
test_cloudflare() {
    print_info "Testing Cloudflare API connectivity..."
    
    # Source the helpers to use test functions
    if [[ -f "$SCRIPT_DIR/cloudflare_helpers.sh" ]]; then
        source "$SCRIPT_DIR/cloudflare_helpers.sh"
        
        print_info ""
        if test_cloudflare_setup "$CLOUDFLARE_TOKEN" "$DOMAIN" >/dev/null; then
            print_success "Cloudflare connectivity test: PASSED"
        else
            print_error "Cloudflare connectivity test: FAILED"
            print_info ""
            print_info "Running detailed Cloudflare test..."
            test_cloudflare_setup "$CLOUDFLARE_TOKEN" "$DOMAIN"
        fi
    else
        print_error "Cloudflare helpers not found"
    fi
}

# Main script execution
main() {
    # Initial setup
    print_header "IP Changer Script Runner for Linux"
    echo ""
    
    # Check if script files exist
    if ! check_script_files; then
        exit 1
    fi
    
    # Make scripts executable
    make_scripts_executable
    
    # Check configuration
    print_info "Validating configuration..."
    if ! check_configuration; then
        exit 1
    fi
    echo ""
    
    # Check requirements
    if ! check_requirements; then
        print_info ""
        print_error "Please install the missing requirements before continuing."
        exit 1
    fi
    echo ""
    
    print_success "Initialization complete!"
    pause_for_input
    
    # Main menu loop
    while true; do
        show_menu
        
        read -p "Enter your choice (1-10): " choice
        
        case "$choice" in
            1)
                run_script "get.sh" "Storing current IPv4 address..." \
                    -t "$CLOUDFLARE_TOKEN" -d "$DOMAIN" -s "$SUBDOMAIN" -v "v4"
                pause_for_input
                ;;
            2)
                run_script "get.sh" "Storing current IPv6 address..." \
                    -t "$CLOUDFLARE_TOKEN" -d "$DOMAIN" -s "$SUBDOMAIN" -v "v6"
                pause_for_input
                ;;
            3)
                run_script "get.sh" "Storing both IPv4 and IPv6 addresses..." \
                    -t "$CLOUDFLARE_TOKEN" -d "$DOMAIN" -s "$SUBDOMAIN" -v "both"
                pause_for_input
                ;;
            4)
                run_script "push.sh" "Retrieving stored IPv4 address..." \
                    -t "$CLOUDFLARE_TOKEN" -d "$DOMAIN" -s "$SUBDOMAIN" -v "v4"
                pause_for_input
                ;;
            5)
                run_script "push.sh" "Retrieving stored IPv6 address..." \
                    -t "$CLOUDFLARE_TOKEN" -d "$DOMAIN" -s "$SUBDOMAIN" -v "v6"
                pause_for_input
                ;;
            6)
                run_script "push.sh" "Retrieving both stored addresses..." \
                    -t "$CLOUDFLARE_TOKEN" -d "$DOMAIN" -s "$SUBDOMAIN" -v "both"
                pause_for_input
                ;;
            7)
                print_info ""
                bash "$SCRIPT_DIR/check_requirements.sh" --install-commands --check-network
                pause_for_input
                ;;
            8)
                print_info ""
                test_cloudflare
                pause_for_input
                ;;
            9)
                print_info ""
                print_info "Running GPG/entropy diagnostics and fixes..."
                if [[ -f "$SCRIPT_DIR/fix_gpg_entropy.sh" ]]; then
                    bash "$SCRIPT_DIR/fix_gpg_entropy.sh" --auto
                else
                    print_error "GPG entropy fix script not found"
                    print_info "Manual fix suggestions:"
                    print_info "1. Install entropy daemon: sudo apt-get install haveged"
                    print_info "2. Start service: sudo systemctl start haveged"
                    print_info "3. Enable on boot: sudo systemctl enable haveged"
                fi
                pause_for_input
                ;;
            10)
                print_info "Goodbye!"
                exit 0
                ;;
            *)
                print_error "Invalid choice. Please try again."
                pause_for_input
                ;;
        esac
    done
}

# Handle script interruption
trap 'print_info "\nScript interrupted by user"; exit 1' INT TERM

# Run main function
main "$@"