#!/bin/bash
# GPG Entropy Fix Script for Debian/Ubuntu systems
# Helps resolve GPG key generation issues by improving system entropy

set -euo pipefail

# Color codes
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_RESET='\033[0m'

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
    print_status "$COLOR_YELLOW" "WARNING: $1"
}

print_info() {
    print_status "$COLOR_CYAN" "$1"
}

print_header() {
    print_status "$COLOR_BLUE" "=== $1 ==="
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

# Function to check current entropy
check_entropy() {
    print_header "Entropy Status Check"
    
    if [[ -r /proc/sys/kernel/random/entropy_avail ]]; then
        local entropy
        entropy=$(cat /proc/sys/kernel/random/entropy_avail)
        print_info "Current entropy: $entropy bits"
        
        if [[ "$entropy" -lt 200 ]]; then
            print_warning "Low entropy detected ($entropy bits)"
            return 1
        elif [[ "$entropy" -lt 1000 ]]; then
            print_warning "Moderate entropy ($entropy bits)"
            return 2
        else
            print_success "Good entropy level ($entropy bits)"
            return 0
        fi
    else
        print_warning "Cannot read entropy information"
        return 3
    fi
}

# Function to install entropy daemons
install_entropy_tools() {
    print_header "Installing Entropy Generation Tools"
    
    if ! check_root; then
        print_error "Root privileges required to install packages"
        print_info "Please run: sudo $0"
        return 1
    fi
    
    # Detect package manager
    if command -v apt-get >/dev/null 2>&1; then
        print_info "Detected APT package manager (Debian/Ubuntu)"
        
        print_info "Updating package lists..."
        apt-get update -qq
        
        print_info "Installing haveged (entropy daemon)..."
        if apt-get install -y haveged; then
            print_success "haveged installed successfully"
            
            print_info "Starting haveged service..."
            if systemctl start haveged && systemctl enable haveged; then
                print_success "haveged service started and enabled"
            else
                print_warning "Could not start haveged service"
            fi
        else
            print_warning "Failed to install haveged, trying rng-tools..."
            
            if apt-get install -y rng-tools; then
                print_success "rng-tools installed successfully"
                
                print_info "Starting rng-tools service..."
                if systemctl start rng-tools && systemctl enable rng-tools; then
                    print_success "rng-tools service started and enabled"
                else
                    print_warning "Could not start rng-tools service"
                fi
            else
                print_error "Failed to install entropy tools"
                return 1
            fi
        fi
        
    elif command -v yum >/dev/null 2>&1; then
        print_info "Detected YUM package manager (RHEL/CentOS)"
        
        print_info "Installing haveged..."
        if yum install -y epel-release && yum install -y haveged; then
            print_success "haveged installed successfully"
            systemctl start haveged && systemctl enable haveged
        else
            print_error "Failed to install haveged"
            return 1
        fi
        
    elif command -v dnf >/dev/null 2>&1; then
        print_info "Detected DNF package manager (Fedora)"
        
        print_info "Installing haveged..."
        if dnf install -y haveged; then
            print_success "haveged installed successfully"
            systemctl start haveged && systemctl enable haveged
        else
            print_error "Failed to install haveged"
            return 1
        fi
        
    else
        print_error "No supported package manager found"
        print_info "Please install haveged or rng-tools manually"
        return 1
    fi
    
    return 0
}

# Function to generate entropy manually
generate_entropy() {
    print_header "Manual Entropy Generation"
    
    print_info "Starting entropy generation activities..."
    print_info "This will run for 30 seconds to boost entropy"
    
    # Background entropy generation
    {
        # Read random files
        find /var /usr /etc -type f -readable 2>/dev/null | head -1000 | xargs cat > /dev/null 2>&1 &
        
        # Generate some disk activity
        dd if=/dev/urandom of=/tmp/entropy_boost bs=1024 count=1024 2>/dev/null &
        
        # CPU activity
        yes > /dev/null &
        local yes_pid=$!
        
        sleep 30
        
        # Clean up
        kill $yes_pid 2>/dev/null || true
        rm -f /tmp/entropy_boost 2>/dev/null || true
        
    } &
    
    local bg_pid=$!
    
    # Show progress
    for i in {1..30}; do
        printf "\rGenerating entropy... [%2d/30]" "$i"
        sleep 1
    done
    
    wait $bg_pid 2>/dev/null || true
    echo ""
    print_success "Entropy generation completed"
}

# Function to test GPG functionality
test_gpg() {
    print_header "Testing GPG Functionality"
    
    # Check if GPG is installed
    if ! command -v gpg >/dev/null 2>&1; then
        print_error "GPG is not installed"
        print_info "Install with: sudo apt-get install gnupg"
        return 1
    fi
    
    print_success "GPG is installed: $(gpg --version | head -n1)"
    
    # Test GPG with a simple operation
    local temp_dir
    temp_dir=$(mktemp -d)
    export GNUPGHOME="$temp_dir"
    
    print_info "Testing GPG key generation (test key)..."
    
    # Create a minimal test key configuration
    cat > "$temp_dir/test_key.conf" << EOF
%echo Generating test key
Key-Type: RSA
Key-Length: 2048
Name-Real: Test Key
Name-Email: test@local
Expire-Date: 1d
%no-protection
%commit
%echo Test key generation complete
EOF
    
    if timeout 60 gpg --batch --generate-key "$temp_dir/test_key.conf" 2>/dev/null; then
        print_success "GPG test key generation: PASSED"
        rm -rf "$temp_dir"
        unset GNUPGHOME
        return 0
    else
        print_error "GPG test key generation: FAILED"
        print_warning "This indicates GPG may have entropy issues"
        rm -rf "$temp_dir"
        unset GNUPGHOME
        return 1
    fi
}

# Main function
main() {
    print_header "GPG Entropy Fix for IP Changer Scripts"
    echo ""
    
    # Parse command line arguments
    local auto_fix=false
    local install_tools=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --auto|--fix)
                auto_fix=true
                shift
                ;;
            --install)
                install_tools=true
                shift
                ;;
            --help|-h)
                cat << EOF
GPG Entropy Fix Script

Usage: $0 [OPTIONS]

Options:
    --auto, --fix    Automatically attempt to fix entropy issues
    --install        Install entropy generation tools (requires root)
    --help, -h       Show this help message

Examples:
    $0                  # Check entropy status
    $0 --auto          # Check and attempt to fix issues automatically
    sudo $0 --install  # Install entropy tools (requires root)

This script helps diagnose and fix GPG key generation issues by:
1. Checking current entropy levels
2. Installing entropy generation tools (haveged/rng-tools)
3. Manually generating entropy when needed
4. Testing GPG functionality

EOF
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Check entropy status
    local entropy_status
    check_entropy
    entropy_status=$?
    
    # Test GPG functionality
    if ! test_gpg; then
        print_warning "GPG functionality test failed"
        auto_fix=true
    fi
    
    # Auto-fix if requested or if entropy is very low
    if [[ "$auto_fix" == "true" || "$entropy_status" -eq 1 ]]; then
        print_info ""
        print_info "Attempting to improve entropy..."
        
        # Try to install tools if we have permission
        if [[ "$install_tools" == "true" ]] || check_root; then
            if install_entropy_tools; then
                print_info "Waiting 10 seconds for entropy daemon to initialize..."
                sleep 10
                check_entropy
            fi
        else
            print_info "No root privileges - performing manual entropy generation"
            generate_entropy
            check_entropy
        fi
        
        # Test GPG again
        print_info ""
        if test_gpg; then
            print_success "GPG functionality test now passes!"
        else
            print_warning "GPG test still fails - you may need to install entropy tools manually"
        fi
    fi
    
    print_info ""
    print_header "Recommendations"
    
    if [[ "$entropy_status" -eq 1 ]]; then
        print_info "Your system has low entropy. For reliable GPG key generation:"
        print_info "1. Install entropy daemon: sudo apt-get install haveged"
        print_info "2. Start the service: sudo systemctl start haveged"
        print_info "3. Enable on boot: sudo systemctl enable haveged"
        print_info "4. Or run: sudo $0 --install"
    elif [[ "$entropy_status" -eq 2 ]]; then
        print_info "Your system has moderate entropy. Consider installing haveged for better performance."
    else
        print_success "Your system appears ready for GPG key generation!"
    fi
    
    print_info ""
    print_info "To run the IP changer scripts now:"
    print_info "  ./run.sh"
    
    return $entropy_status
}

# Run main function
main "$@"