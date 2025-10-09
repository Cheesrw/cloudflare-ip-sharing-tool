#!/bin/bash
# Linux Requirements Checker for IP Changer Scripts
# Checks for required packages without installing them

set -euo pipefail

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
    print_status "$COLOR_RED" "✗ $1"
}

print_success() {
    print_status "$COLOR_GREEN" "✓ $1"
}

print_warning() {
    print_status "$COLOR_YELLOW" "⚠ $1"
}

print_info() {
    print_status "$COLOR_CYAN" "$1"
}

print_header() {
    print_status "$COLOR_BLUE" "=== $1 ==="
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check GPG entropy requirements
check_gpg_entropy() {
    print_info "Checking entropy for GPG key generation..."
    
    if [[ -r /proc/sys/kernel/random/entropy_avail ]]; then
        local entropy
        entropy=$(cat /proc/sys/kernel/random/entropy_avail)
        print_info "Available entropy: $entropy bits"
        
        if [[ "$entropy" -lt 200 ]]; then
            print_warning "Low entropy ($entropy bits) - GPG key generation may fail or be very slow"
            print_info "Consider installing: sudo apt-get install haveged"
            print_info "Or run: ./fix_gpg_entropy.sh --install"
        elif [[ "$entropy" -lt 1000 ]]; then
            print_warning "Moderate entropy ($entropy bits) - key generation may be slow"
            print_info "Consider installing entropy daemon for better performance"
        else
            print_success "Good entropy level ($entropy bits)"
        fi
        
        # Check for entropy daemons
        if command_exists "haveged" || systemctl is-active haveged >/dev/null 2>&1; then
            print_success "haveged entropy daemon detected"
        elif command_exists "rngd" || systemctl is-active rng-tools >/dev/null 2>&1; then
            print_success "rng-tools entropy daemon detected"
        else
            print_warning "No entropy daemon detected - consider installing haveged or rng-tools"
        fi
    else
        print_warning "Cannot check entropy level (older kernel?)"
    fi
}

# Function to get command version
get_version() {
    local cmd="$1"
    local version_flag="${2:---version}"
    
    if command_exists "$cmd"; then
        $cmd $version_flag 2>/dev/null | head -n 1 || echo "Version unknown"
    else
        echo "Not installed"
    fi
}

# Function to check package manager availability
check_package_managers() {
    print_header "Package Manager Detection"
    
    local managers_found=()
    
    if command_exists "apt" || command_exists "apt-get"; then
        print_success "APT (Debian/Ubuntu) detected"
        managers_found+=("apt")
    fi
    
    if command_exists "yum"; then
        print_success "YUM (RHEL/CentOS) detected"
        managers_found+=("yum")
    fi
    
    if command_exists "dnf"; then
        print_success "DNF (Fedora) detected"
        managers_found+=("dnf")
    fi
    
    if command_exists "pacman"; then
        print_success "Pacman (Arch Linux) detected"
        managers_found+=("pacman")
    fi
    
    if command_exists "zypper"; then
        print_success "Zypper (openSUSE) detected"
        managers_found+=("zypper")
    fi
    
    if command_exists "apk"; then
        print_success "APK (Alpine Linux) detected"
        managers_found+=("apk")
    fi
    
    if command_exists "brew"; then
        print_success "Homebrew (macOS/Linux) detected"
        managers_found+=("brew")
    fi
    
    if [[ ${#managers_found[@]} -eq 0 ]]; then
        print_error "No supported package manager found"
        return 1
    fi
    
    echo "DETECTED_MANAGERS=(${managers_found[*]})"
    return 0
}

# Function to check core requirements
check_core_requirements() {
    print_header "Core Requirements Check"
    
    local missing_core=()
    
    # Check bash version
    if [[ "${BASH_VERSION%%.*}" -ge 4 ]]; then
        print_success "Bash ${BASH_VERSION} (minimum 4.0 required)"
    else
        print_error "Bash ${BASH_VERSION} (minimum 4.0 required)"
        missing_core+=("bash>=4.0")
    fi
    
    # Check curl
    if command_exists "curl"; then
        local curl_version
        curl_version=$(get_version "curl" "--version")
        print_success "curl: $curl_version"
        
        # Check for HTTPS support
        if curl --version 2>/dev/null | grep -q "https"; then
            print_success "curl: HTTPS support detected"
        else
            print_warning "curl: HTTPS support not detected"
        fi
    else
        print_error "curl: Not installed"
        missing_core+=("curl")
    fi
    
    # Check jq
    if command_exists "jq"; then
        local jq_version
        jq_version=$(get_version "jq" "--version")
        print_success "jq: $jq_version"
    else
        print_error "jq: Not installed"
        missing_core+=("jq")
    fi
    
    # Check gpg
    if command_exists "gpg"; then
        local gpg_version
        gpg_version=$(get_version "gpg" "--version")
        print_success "gpg: $gpg_version"
        
        # Check for specific algorithms
        if gpg --version 2>/dev/null | grep -q "AES256"; then
            print_success "gpg: AES256 support detected"
        else
            print_warning "gpg: AES256 support not confirmed"
        fi
        
        # Check entropy for GPG key generation
        check_gpg_entropy
    else
        print_error "gpg: Not installed"
        missing_core+=("gnupg")
    fi
    
    # Check base64
    if command_exists "base64"; then
        print_success "base64: Available"
    else
        print_error "base64: Not installed"
        missing_core+=("coreutils")
    fi
    
    # Check basic shell utilities
    local shell_utils=("grep" "sed" "awk" "cut" "head" "tail" "cat" "echo" "mktemp" "chmod" "stat")
    local missing_utils=()
    
    for util in "${shell_utils[@]}"; do
        if command_exists "$util"; then
            print_success "$util: Available"
        else
            print_error "$util: Not installed"
            missing_utils+=("$util")
        fi
    done
    
    if [[ ${#missing_utils[@]} -gt 0 ]]; then
        missing_core+=("coreutils")
    fi
    
    echo "MISSING_CORE=(${missing_core[*]})"
    return ${#missing_core[@]}
}

# Function to check optional but recommended tools
check_optional_requirements() {
    print_header "Optional Tools Check"
    
    local missing_optional=()
    
    # Check for better random number generation
    if [[ -e "/dev/urandom" ]]; then
        print_success "/dev/urandom: Available (for secure random generation)"
    else
        print_warning "/dev/urandom: Not available"
        missing_optional+=("urandom-support")
    fi
    
    # Check for IPv6 support
    if [[ -e "/proc/net/if_inet6" ]]; then
        print_success "IPv6: Kernel support detected"
    else
        print_warning "IPv6: Kernel support not detected"
    fi
    
    # Check for specific curl features
    if command_exists "curl"; then
        if curl --help 2>/dev/null | grep -q "ipv6"; then
            print_success "curl: IPv6 support detected"
        else
            print_warning "curl: IPv6 support not confirmed"
        fi
        
        if curl --help 2>/dev/null | grep -q "max-time"; then
            print_success "curl: Timeout support detected"
        else
            print_warning "curl: Timeout support not confirmed"
        fi
    fi
    
    # Check for process management tools
    if command_exists "ps"; then
        print_success "ps: Available (for process monitoring)"
    else
        print_warning "ps: Not available"
        missing_optional+=("procps")
    fi
    
    if command_exists "pgrep"; then
        print_success "pgrep: Available (for process searching)"
    else
        print_warning "pgrep: Not available"
        missing_optional+=("procps")
    fi
    
    # Check for file permissions tools
    if command_exists "chown"; then
        print_success "chown: Available (for file ownership)"
    else
        print_warning "chown: Not available"
        missing_optional+=("coreutils")
    fi
    
    echo "MISSING_OPTIONAL=(${missing_optional[*]})"
    return 0
}

# Function to detect Linux distribution
detect_distribution() {
    print_header "Linux Distribution Detection"
    
    local distro="Unknown"
    local version="Unknown"
    
    if [[ -f "/etc/os-release" ]]; then
        source /etc/os-release
        distro="${NAME:-Unknown}"
        version="${VERSION:-${VERSION_ID:-Unknown}}"
    elif [[ -f "/etc/redhat-release" ]]; then
        distro=$(cat /etc/redhat-release)
    elif [[ -f "/etc/debian_version" ]]; then
        distro="Debian $(cat /etc/debian_version)"
    elif command_exists "lsb_release"; then
        distro=$(lsb_release -d | cut -f2-)
    fi
    
    print_info "Distribution: $distro"
    print_info "Version: $version"
    
    echo "DISTRO=\"$distro\""
    echo "DISTRO_VERSION=\"$version\""
}

# Function to generate installation commands
generate_install_commands() {
    local missing_core_str="$1"
    local detected_managers_str="$2"
    
    # Convert string back to array
    read -ra missing_core <<< "$missing_core_str"
    read -ra detected_managers <<< "$detected_managers_str"
    
    if [[ ${#missing_core[@]} -eq 0 ]]; then
        return 0
    fi
    
    print_header "Installation Commands"
    print_info "The following commands can be used to install missing packages:"
    echo ""
    
    for manager in "${detected_managers[@]}"; do
        case "$manager" in
            "apt")
                print_info "For Debian/Ubuntu systems:"
                echo "sudo apt update"
                echo -n "sudo apt install"
                for pkg in "${missing_core[@]}"; do
                    case "$pkg" in
                        "curl") echo -n " curl" ;;
                        "jq") echo -n " jq" ;;
                        "gnupg") echo -n " gnupg" ;;
                        "coreutils") echo -n " coreutils" ;;
                        "bash>=4.0") echo -n " bash" ;;
                    esac
                done
                echo ""
                echo ""
                ;;
            "yum")
                print_info "For RHEL/CentOS systems:"
                echo -n "sudo yum install"
                for pkg in "${missing_core[@]}"; do
                    case "$pkg" in
                        "curl") echo -n " curl" ;;
                        "jq") echo -n " jq" ;;
                        "gnupg") echo -n " gnupg2" ;;
                        "coreutils") echo -n " coreutils" ;;
                        "bash>=4.0") echo -n " bash" ;;
                    esac
                done
                echo ""
                echo ""
                ;;
            "dnf")
                print_info "For Fedora systems:"
                echo -n "sudo dnf install"
                for pkg in "${missing_core[@]}"; do
                    case "$pkg" in
                        "curl") echo -n " curl" ;;
                        "jq") echo -n " jq" ;;
                        "gnupg") echo -n " gnupg2" ;;
                        "coreutils") echo -n " coreutils" ;;
                        "bash>=4.0") echo -n " bash" ;;
                    esac
                done
                echo ""
                echo ""
                ;;
            "pacman")
                print_info "For Arch Linux systems:"
                echo -n "sudo pacman -S"
                for pkg in "${missing_core[@]}"; do
                    case "$pkg" in
                        "curl") echo -n " curl" ;;
                        "jq") echo -n " jq" ;;
                        "gnupg") echo -n " gnupg" ;;
                        "coreutils") echo -n " coreutils" ;;
                        "bash>=4.0") echo -n " bash" ;;
                    esac
                done
                echo ""
                echo ""
                ;;
            "zypper")
                print_info "For openSUSE systems:"
                echo -n "sudo zypper install"
                for pkg in "${missing_core[@]}"; do
                    case "$pkg" in
                        "curl") echo -n " curl" ;;
                        "jq") echo -n " jq" ;;
                        "gnupg") echo -n " gpg2" ;;
                        "coreutils") echo -n " coreutils" ;;
                        "bash>=4.0") echo -n " bash" ;;
                    esac
                done
                echo ""
                echo ""
                ;;
            "apk")
                print_info "For Alpine Linux systems:"
                echo -n "sudo apk add"
                for pkg in "${missing_core[@]}"; do
                    case "$pkg" in
                        "curl") echo -n " curl" ;;
                        "jq") echo -n " jq" ;;
                        "gnupg") echo -n " gnupg" ;;
                        "coreutils") echo -n " coreutils" ;;
                        "bash>=4.0") echo -n " bash" ;;
                    esac
                done
                echo ""
                echo ""
                ;;
            "brew")
                print_info "For Homebrew (macOS/Linux):"
                echo -n "brew install"
                for pkg in "${missing_core[@]}"; do
                    case "$pkg" in
                        "curl") echo -n " curl" ;;
                        "jq") echo -n " jq" ;;
                        "gnupg") echo -n " gnupg" ;;
                        "coreutils") echo -n " coreutils" ;;
                        "bash>=4.0") echo -n " bash" ;;
                    esac
                done
                echo ""
                echo ""
                ;;
        esac
    done
}

# Function to check network connectivity
check_network() {
    print_header "Network Connectivity Check"
    
    # Test basic connectivity
    if command_exists "curl"; then
        print_info "Testing network connectivity..."
        
        # Test IPv4 connectivity
        if curl -4 -s --max-time 5 "https://api.ipify.org" >/dev/null 2>&1; then
            print_success "IPv4 connectivity: Working"
        else
            print_warning "IPv4 connectivity: Failed"
        fi
        
        # Test IPv6 connectivity
        if curl -6 -s --max-time 5 "https://api6.ipify.org" >/dev/null 2>&1; then
            print_success "IPv6 connectivity: Working"
        else
            print_warning "IPv6 connectivity: Failed (this is normal if IPv6 is not available)"
        fi
        
        # Test Cloudflare API connectivity
        if curl -s --max-time 5 "https://api.cloudflare.com/client/v4/zones" >/dev/null 2>&1; then
            print_success "Cloudflare API connectivity: Working"
        else
            print_warning "Cloudflare API connectivity: Failed"
        fi
    else
        print_warning "Cannot test network connectivity (curl not available)"
    fi
}

# Main function
main() {
    local show_install_commands=false
    local check_network_connectivity=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --install-commands)
                show_install_commands=true
                shift
                ;;
            --check-network)
                check_network_connectivity=true
                shift
                ;;
            -h|--help)
                cat << EOF
Linux Requirements Checker for IP Changer Scripts

Usage: $0 [OPTIONS]

Options:
    --install-commands    Show package installation commands for missing dependencies
    --check-network      Test network connectivity to required services
    -h, --help           Show this help message

This script checks for all required tools and packages needed to run the
IP changer scripts on Linux systems. It does NOT install anything automatically.
EOF
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    print_info "Linux Requirements Checker for IP Changer Scripts"
    print_info "This script will check for required dependencies without installing them."
    echo ""
    
    # Detect distribution
    detect_distribution
    echo ""
    
    # Check package managers
    local managers_output
    managers_output=$(check_package_managers)
    local managers_status=$?
    echo ""
    
    # Check core requirements
    local core_output
    core_output=$(check_core_requirements)
    local core_status=$?
    echo ""
    
    # Check optional requirements
    check_optional_requirements
    echo ""
    
    # Check network if requested
    if [[ "$check_network_connectivity" == "true" ]]; then
        check_network
        echo ""
    fi
    
    # Extract results
    local detected_managers
    detected_managers=$(echo "$managers_output" | grep "DETECTED_MANAGERS=" | cut -d'=' -f2 | tr -d '()')
    local missing_core
    missing_core=$(echo "$core_output" | grep "MISSING_CORE=" | cut -d'=' -f2 | tr -d '()')
    
    # Show summary
    print_header "Summary"
    
    if [[ $core_status -eq 0 ]]; then
        print_success "All core requirements are satisfied!"
        print_info "The IP changer scripts should work on this system."
    else
        print_error "Missing $core_status core requirement(s)"
        print_info "The IP changer scripts will NOT work until these are installed."
        
        if [[ "$show_install_commands" == "true" ]]; then
            echo ""
            generate_install_commands "$missing_core" "$detected_managers"
        else
            echo ""
            print_info "Run with --install-commands to see installation instructions."
        fi
    fi
    
    echo ""
    print_info "Script locations after installation:"
    print_info "  • get.sh       - Store encrypted IP addresses"
    print_info "  • push.sh      - Retrieve and decrypt IP addresses"  
    print_info "  • run.sh       - Interactive menu runner"
    print_info "  • check_requirements.sh - This requirements checker"
    
    exit $core_status
}

# Run main function
main "$@"