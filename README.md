# Cloudflare IP Share

This project contains scripts for securely storing and retrieving public IP addresses (IPv4 and/or IPv6) using Cloudflare DNS TXT records with PGP encryption. Both **Windows PowerShell** and **native Linux** versions are provided.

## 📁 Project Structure

```
cloudflare-ip-share/
├── README.md                    # This comprehensive guide
├── .gitignore                   # Protects keys and sensitive files
├── 
├── Windows Scripts (PowerShell):
├── ├── get.ps1                  # Store encrypted IP addresses
├── ├── push.ps1                 # Retrieve and decrypt IP addresses
├── ├── run.bat                  # Interactive Windows runner
├── ├── ispwsh7installed.ps1     # PowerShell 7 checker/installer
├── ├── CloudflareHelpers.ps1    # Cloudflare API library (with quiet mode support)
├── ├── curl/curl.exe            # Bundled curl for Windows
├── └── PSPGP/                   # PowerShell PGP module
├── 
├── Linux Scripts (Native):
├── ├── get.sh                   # Store encrypted IP addresses
├── ├── push.sh                  # Retrieve and decrypt IP addresses
├── ├── run.sh                   # Interactive Linux runner
├── ├── cloudflare_helpers.sh    # Cloudflare API library
├── ├── check_requirements.sh    # System requirements checker
├── 
└── Auto-generated:
    ├── keys/                    # PGP keys (auto-created, git-ignored)
    │   ├── private.asc          # Private key for decryption
    │   ├── public.asc           # Public key for encryption
    │   └── password.txt         # Secure password file
    └── logs/                    # Operation logs (auto-created, quiet mode)
        ├── get_YYYYMMDD_HHMMSS.log    # IP storage operation logs
        └── push_YYYYMMDD_HHMMSS.log   # IP retrieval operation logs
```

## 🚀 Quick Start

### Windows (PowerShell)
```cmd
# Run the interactive menu
.\run.bat
```

### Linux (Bash)
```bash
# Check requirements first
./check_requirements.sh --install-commands --check-network

# Run the interactive menu
./run.sh
```

---

## 🖥️ Windows Setup (PowerShell)

## Scripts

### `get.ps1` - Store Encrypted IP
Gets your public IP address(es), encrypts them with PGP, and stores them in Cloudflare DNS TXT records.

### `push.ps1` - Retrieve Decrypted IP
Retrieves the encrypted IP(s) from the DNS TXT record(s) and decrypts them.

### `CloudflareHelpers.ps1` - Shared Library
Provides comprehensive Cloudflare API validation, token verification, permission checking, and advanced issue handling for both scripts. Now includes full quiet mode support for automation-friendly operations.

### Prerequisites
1. **Cloudflare API Token** with DNS:Write permissions
2. **PowerShell 5.1+** (Windows) or **PowerShell Core** (Cross-platform)
3. **.NET Framework 4.7.2+** (for Windows PowerShell 5.1)

### Installation
1. Ensure you have a domain managed by Cloudflare
2. Create a Cloudflare API Token with Zone:DNS:Write permissions
3. Edit `run.bat` and update configuration values
4. Run `run.bat` - it will auto-install PowerShell 7 if needed
5. The scripts will automatically create PGP keys on first run

### Windows Usage

#### Store IP Addresses
```powershell
# IPv4 only
.\get.ps1 -CloudflareApiToken "your_token" -Domain "example.com" -Subdomain "myip"

# IPv6 only
.\get.ps1 -CloudflareApiToken "your_token" -Domain "example.com" -Subdomain "myip" -IPVersion "v6"

# Both IPv4 and IPv6
.\get.ps1 -CloudflareApiToken "your_token" -Domain "example.com" -Subdomain "myip" -IPVersion "both"

# Quiet mode (only returns SUCCESS/FAILURE, logs to file)
.\get.ps1 -CloudflareApiToken "your_token" -Domain "example.com" -Subdomain "myip" -Quiet
```

#### Retrieve IP Addresses
```powershell
# IPv4 only
.\push.ps1 -CloudflareApiToken "your_token" -Domain "example.com" -Subdomain "myip"

# IPv6 only
.\push.ps1 -CloudflareApiToken "your_token" -Domain "example.com" -Subdomain "myip" -IPVersion "v6"

# Both IPv4 and IPv6
.\push.ps1 -CloudflareApiToken "your_token" -Domain "example.com" -Subdomain "myip" -IPVersion "both"

# Quiet mode (only returns IP address(es), logs to file)
.\push.ps1 -CloudflareApiToken "your_token" -Domain "example.com" -Subdomain "myip" -Quiet
```

---

## 🐧 Linux Setup (Native)

### Required Packages
- **`bash`** (≥ 4.0) - Shell interpreter
- **`curl`** - HTTP client for API calls and IP retrieval
- **`jq`** - JSON processor for API responses
- **`gpg`** (GnuPG) - PGP encryption/decryption
- **`base64`** - Base64 encoding/decoding
- **`coreutils`** - Basic utilities (grep, sed, awk, cut, etc.)

### Optional but Recommended
- **`procps`** - Process management tools (ps, pgrep)
- **IPv6 support** - For IPv6 functionality
- **`/dev/urandom`** - Secure random number generation

### Installation

#### 1. Check Requirements
```bash
chmod +x check_requirements.sh
./check_requirements.sh --install-commands --check-network
```

#### 2. Install Missing Packages

**Debian/Ubuntu:**
```bash
sudo apt update
sudo apt install curl jq gnupg coreutils bash
```

**RHEL/CentOS/Fedora:**
```bash
# RHEL/CentOS:
sudo yum install curl jq gnupg2 coreutils bash

# Fedora:
sudo dnf install curl jq gnupg2 coreutils bash
```

**Arch Linux:**
```bash
sudo pacman -S curl jq gnupg coreutils bash
```

**openSUSE:**
```bash
sudo zypper install curl jq gpg2 coreutils bash
```

**Alpine Linux:**
```bash
sudo apk add curl jq gnupg coreutils bash
```

**macOS (Homebrew):**
```bash
brew install curl jq gnupg coreutils bash
```

#### 3. Make Scripts Executable
```bash
chmod +x *.sh
```

#### 4. Configure Settings
```bash
# Edit run.sh and update configuration
nano run.sh
```

Update these variables:
```bash
CLOUDFLARE_TOKEN="your_actual_api_token"
DOMAIN="your_domain.com"
SUBDOMAIN="your_subdomain_prefix"
```

### Linux Usage

#### Store IP Addresses
```bash
# IPv4 only
./get.sh -t "your_token" -d "domain.com" -s "subdomain"

# IPv6 only
./get.sh -t "your_token" -d "domain.com" -s "subdomain" -v "v6"

# Both IPv4 and IPv6
./get.sh -t "your_token" -d "domain.com" -s "subdomain" -v "both"

# Quiet mode (only returns SUCCESS/FAILURE, logs to file)
./get.sh -t "your_token" -d "domain.com" -s "subdomain" -q
```

#### Retrieve IP Addresses
```bash
# IPv4 only
./push.sh -t "your_token" -d "domain.com" -s "subdomain"

# IPv6 only
./push.sh -t "your_token" -d "domain.com" -s "subdomain" -v "v6"

# Both IPv4 and IPv6
./push.sh -t "your_token" -d "domain.com" -s "subdomain" -v "both"

# Quiet mode (only returns IP address(es), logs to file)
./push.sh -t "your_token" -d "domain.com" -s "subdomain" -q
```

---

## 🔇 Quiet Mode & Logging

Both platforms now support **quiet mode** for automation and scripting purposes.

### Quiet Mode Features

#### For `get` scripts (storing IP addresses):
- **Output**: Only returns `SUCCESS` or `FAILURE`
- **Logging**: All detailed output goes to `logs/get_YYYYMMDD_HHMMSS.log`
- **Use case**: Perfect for automation where you only need to know if the operation succeeded

#### For `push` scripts (retrieving IP addresses):
- **Output**: Only returns the IP address(es) themselves
- **Logging**: All detailed output goes to `logs/push_YYYYMMDD_HHMMSS.log`
- **Use case**: Perfect for scripts that need to use the retrieved IP address

### Usage Examples

#### Linux (Bash)
```bash
# Get script in quiet mode
result=$(./get.sh -t "token" -d "domain.com" -s "myip" -q)
if [[ "$result" == "SUCCESS" ]]; then
    echo "IP stored successfully"
fi

# Push script in quiet mode
ip_address=$(./push.sh -t "token" -d "domain.com" -s "myip" -q)
echo "Current IP: $ip_address"
```

#### Windows (PowerShell)
```powershell
# Get script in quiet mode
$result = .\get.ps1 -CloudflareApiToken "token" -Domain "domain.com" -Subdomain "myip" -Quiet
if ($result -eq "SUCCESS") {
    Write-Host "IP stored successfully"
}

# Push script in quiet mode
$ipAddress = .\push.ps1 -CloudflareApiToken "token" -Domain "domain.com" -Subdomain "myip" -Quiet
Write-Host "Current IP: $ipAddress"
```

### Automatic Log Management

- **Log Directory**: `logs/` (created automatically)
- **Log Files**: 
  - `get_YYYYMMDD_HHMMSS.log` for IP storage operations
  - `push_YYYYMMDD_HHMMSS.log` for IP retrieval operations
- **Log Rotation**: Automatically maintains maximum of 30 logs per script type
- **Log Cleanup**: Oldest logs are automatically deleted when limit is reached
- **Log Content**: Complete detailed output including all status messages, errors, and debug information

### Benefits

- **Automation-Friendly**: Clean output suitable for scripts and CI/CD pipelines
- **Debugging**: Full logs retained for troubleshooting while keeping output minimal
- **Storage Efficient**: Automatic log rotation prevents disk space issues
- **Audit Trail**: Timestamped logs provide complete operation history
- **Complete Quiet Support**: All helper functions now respect quiet mode, including Cloudflare API operations
- **Consistent Behavior**: Identical quiet mode functionality across Windows PowerShell and Linux platforms

## 🌐 IP Version Support

Both platforms support three modes:
- **`v4`** (default): IPv4 only
- **`v6`**: IPv6 only  
- **`both`**: Both IPv4 and IPv6

### Subdomain Structure
When using `both` mode:
- IPv4 data is stored in `subdomain4.domain.com`
- IPv6 data is stored in `subdomain6.domain.com`
- Both use the same PGP keys for encryption/decryption

## 🔧 How It Works

1. **Validation**: Comprehensive Cloudflare API token verification and permission checking
2. **IP Retrieval**: 
   - **IPv4 Services**: `api.ipify.org`, `api4.my-ip.io/ip`, `ipv4.icanhazip.com`, `v4.ident.me`
   - **IPv6 Services**: `api6.ipify.org`, `api6.my-ip.io/ip`, `ipv6.icanhazip.com`, `v6.ident.me`
3. **Encryption**: Creates PGP key pair on first run, encrypts IP(s) with public key
4. **Storage**: Converts encrypted data to Base64 and stores in DNS TXT record(s)
5. **Retrieval**: Downloads TXT record(s), decodes Base64, and decrypts with private key

## 🔒 Security Features

### Encryption
- **Military-Grade PGP Encryption**: Uses 4096-bit RSA keys with SHA-256 hashing
- **Advanced Cryptographic Parameters**:
  - RSA 4096-bit public key algorithm (fallback to 2048-bit)
  - AES256 symmetric encryption for actual data
  - SHA-256 digest algorithm
  - Compression level 6 (optimal balance)
  - Certainty level 20 (highest security)

### Key Management
- **Secure Key Storage**: Private keys stored locally with restrictive file permissions
- **Cryptographically Secure Passwords**: 64-character passwords using full ASCII range
- **Key Strength Validation**: Automatic validation of key security parameters
- **Git Protection**: Keys directory is automatically ignored by Git

### Network Security
- **Multiple fallback IP services** for reliability
- **DNS Security**: Uses Cloudflare's secure DNS infrastructure
- **HTTPS-only communications** for all API calls
- **Certificate validation** performed by curl
- **Timeout handling** prevents hanging connections

## 🌟 Enhanced Features

### Validation & Error Handling
- **Pre-flight Cloudflare validation**: Token verification, permission checking, zone access validation
- **Comprehensive error categorization**: Detailed error codes with explanations
- **Network connectivity testing**: IPv4/IPv6 and Cloudflare API connectivity tests
- **Enhanced issue diagnosis**: Detailed troubleshooting information

### Reliability Features
- **Multiple IP detection services** with automatic failover
- **Robust DNS record management**: Automatic creation/updating of DNS records
- **Cross-platform compatibility**: Identical functionality on Windows and Linux
- **Graceful degradation**: Fallback mechanisms for various failure scenarios

### User Experience
- **Interactive menus**: Easy-to-use runners for both platforms
- **Color-coded output**: Clear visual feedback for operations
- **Progress indicators**: Real-time status updates during operations
- **Comprehensive logging**: Detailed operation logs for troubleshooting
- **Complete quiet mode**: All functions now support automation-friendly silent operation
- **Consistent behavior**: Unified quiet mode experience across all script components

## 🔧 Advanced Configuration

### Custom IP Services
Both versions support multiple IP detection services. You can modify the service lists in the scripts:

**PowerShell (get.ps1):**
```powershell
$ipv4Services = @(
    @{ url = "https://api.ipify.org"; name = "ipify"; format = "text" },
    @{ url = "https://api4.my-ip.io/ip"; name = "my-ip.io"; format = "text" },
    # Add more services here
)
```

**Linux (get.sh):**
```bash
local ipv4_services=(
    "https://api.ipify.org"
    "https://api4.my-ip.io/ip"
    # Add more services here
)
```

### DNS TTL Configuration
Default TTL is 300 seconds (5 minutes). You can modify this in the DNS record creation functions.

### Encryption Strength
The scripts attempt 4096-bit RSA keys first, with automatic fallback to 2048-bit if generation fails.

## 🛠️ Troubleshooting

### Recent Fixes Applied

#### ✅ FIXED: CloudflareHelpers.ps1 Quiet Mode Issues (October 9, 2025)

**Problem:** CloudflareHelpers.ps1 functions were not respecting the quiet mode setting, causing verbose output even when scripts were run with `-Quiet` parameter.

**Root Cause:** The CloudflareHelpers.ps1 file contained direct `Write-Host`, `Write-Warning`, and `Write-Error` calls that bypassed the quiet mode system implemented in get.ps1 and push.ps1.

**Solution Applied:**
- Added `-Quiet` parameter to all main Cloudflare helper functions
- Wrapped all output statements in conditional logic that checks `if (-not $Quiet)`
- Updated all function calls in get.ps1 and push.ps1 to pass `-Quiet:$Global:QuietMode`
- Enhanced `Invoke-CloudflareApiCall` and `Show-CloudflareError` functions to support quiet mode

**Status:** ✅ RESOLVED - Quiet mode now works correctly across all Cloudflare helper functions, providing clean automation-friendly output while maintaining full functionality.

#### ✅ FIXED: Curl Exit Code 3 Error (October 9, 2025)

**Problem:** Scripts were failing with "Network error during [operation] (curl exit code: 3)"

**Root Cause:** Output redirection issues in helper functions where status messages were being captured as part of variable assignments, corrupting URLs and JSON data.

**Solution Applied:** 
- Fixed all helper functions to redirect status output to stderr (>&2)
- Fixed subdomain generation to always append IPv4/IPv6 suffixes
- Fixed variable contamination in `test_cloudflare_setup()`, `get_dns_record_id()`, etc.

**Status:** ✅ RESOLVED - Scripts now work correctly for both storing and retrieving IP addresses.

### Common Issues

#### Windows Issues
1. **PowerShell Execution Policy**: Run `Set-ExecutionPolicy RemoteSigned` as Administrator
2. **PowerShell 7 Not Found**: The scripts will auto-install PowerShell 7
3. **PSPGP Module Issues**: Ensure .NET Framework 4.7.2+ is installed

#### Linux Issues
1. **Permission Denied**: Run `chmod +x *.sh`
2. **Command Not Found**: Install missing packages using the requirements checker
3. **GPG Issues**: Ensure GnuPG is properly installed and configured

### GPG Key Generation Issues on Linux

#### Issue: "Failed to generate GPG key pair"

This error typically occurs due to insufficient entropy (randomness) on your system. GPG requires good quality random data to generate secure keys.

#### Quick Fix

1. **Run the entropy fix script:**
   ```bash
   chmod +x fix_gpg_entropy.sh
   ./fix_gpg_entropy.sh --auto
   ```

2. **Or install entropy daemon manually:**
   ```bash
   # On Debian/Ubuntu:
   sudo apt-get update
   sudo apt-get install haveged
   sudo systemctl start haveged
   sudo systemctl enable haveged
   
   # On CentOS/RHEL:
   sudo yum install epel-release
   sudo yum install haveged
   sudo systemctl start haveged
   sudo systemctl enable haveged
   
   # On Fedora:
   sudo dnf install haveged
   sudo systemctl start haveged
   sudo systemctl enable haveged
   ```

3. **Check entropy level:**
   ```bash
   cat /proc/sys/kernel/random/entropy_avail
   ```
   - Good: > 1000 bits
   - OK: > 200 bits  
   - Low: < 200 bits (will cause issues)

#### Manual Entropy Generation

If you can't install haveged, generate entropy manually:

```bash
# Generate some entropy (run in background)
find /var /usr /etc -type f 2>/dev/null | head -1000 | xargs cat > /dev/null 2>&1 &

# Or use the dedicated entropy script
./fix_gpg_entropy.sh
```

#### Alternative Solutions

1. **Use lighter key parameters:**
   - The script will automatically fallback to 2048-bit keys if 4096-bit fails
   
2. **Check disk space:**
   ```bash
   df -h /tmp
   ```
   
3. **Verify GPG installation:**
   ```bash
   gpg --version
   ```

4. **Check permissions:**
   ```bash
   ls -la keys/
   # Should show restrictive permissions (700 for directory, 600 for private keys)
   ```

#### System Requirements for GPG

The scripts require:
- `gpg` (gnupg package)
- `curl` 
- `jq`
- `base64`
- Sufficient entropy for key generation

Run the requirements checker:
```bash
./check_requirements.sh
```

#### If GPG Problems Persist

1. **Check system logs:**
   ```bash
   sudo journalctl -u haveged
   dmesg | grep -i random
   ```

2. **Test GPG manually:**
   ```bash
   ./fix_gpg_entropy.sh  # This includes a GPG test
   ```

3. **Use existing keys:**
   If you have existing GPG keys, you can manually copy them to the `keys/` directory:
   ```bash
   mkdir -p keys
   cp your_existing_public.asc keys/public.asc
   cp your_existing_private.asc keys/private.asc
   echo "your_password" > keys/password.txt
   chmod 600 keys/private.asc keys/password.txt
   chmod 644 keys/public.asc
   ```

#### Running the Scripts After GPG Fix

After fixing entropy issues:

```bash
# Interactive menu
./run.sh

# Or run directly
./get.sh -t "your_token" -d "your_domain" -s "your_subdomain" -v "both"
```

#### Network Issues
Use the connectivity test features:
- **Windows**: Select option 7 in `run.bat`
- **Linux**: Run `./check_requirements.sh --check-network`

#### Cloudflare API Errors
Both platforms provide detailed error analysis:
- **Token issues**: Verify token permissions and expiration
- **Zone access**: Ensure domain is in your Cloudflare account
- **DNS record issues**: Check for existing conflicting records

### Automated Diagnostics

For comprehensive troubleshooting support:

- **Windows**: Run `.\run.bat` and use the interactive menu options
- **Linux**: Run `./run.sh` and use menu option 9 for automated diagnostics
- **Requirements Check**: Run `./check_requirements.sh` to verify all dependencies
- **Entropy Issues**: Run `./fix_gpg_entropy.sh --help` for detailed entropy help

### Debug Mode
For detailed debugging:

**PowerShell:**
```powershell
$VerbosePreference = "Continue"
.\get.ps1 -Verbose -CloudflareApiToken "token" -Domain "domain" -Subdomain "subdomain"
```

**Linux:**
```bash
bash -x ./get.sh -t "token" -d "domain" -s "subdomain"
```

## 📊 Platform Comparison

| Feature | Windows (PowerShell) | Linux (Bash) |
|---------|----------------------|---------------|
| **Requirements** | PowerShell 5.1+, .NET 4.7.2+ | bash 4.0+, curl, jq, gpg |
| **Installation** | Auto-install PowerShell 7 | Manual package installation |
| **PGP Library** | PSPGP module (.NET) | Native GPG |
| **JSON Processing** | Built-in ConvertFrom-Json | jq command |
| **Permissions** | Windows ACLs | Unix permissions (chmod) |
| **Package Management** | Bundled dependencies | Native package managers |
| **Performance** | .NET runtime overhead | Native tools, faster |
| **Compatibility** | Windows, PowerShell Core | Any Unix-like system |

## 🧪 Tested Platforms

The scripts have been thoroughly tested on the following platforms:

### Windows
- ✅ **Windows 10 21H2** - Fully tested and working
- ✅ **Windows 10 22H2** - Fully tested and working
- 🔄 **Windows 11** - Expected to work (compatible with Windows 10)

### Linux
- ✅ **Debian 12** - Fully tested and working
- ✅ **Debian 13** - Fully tested and working  
- ✅ **Alpine Linux 3.18** - Fully tested and working
- ✅ **Alpine Linux 3.22** - Fully tested and working

### Expected Compatibility
- 🔄 **Any Debian-based system** (Ubuntu, Linux Mint, etc.) - Should work without issues
- 🔄 **Other Linux distributions** (RHEL, CentOS, Fedora, Arch, openSUSE) - Should work with proper package installation
- 🔄 **macOS** - Should work with Homebrew dependencies

The cross-platform design ensures consistent functionality across different operating systems, with automatic dependency management and fallback mechanisms built into the scripts.

## 🤝 Contributing

When contributing to this project:

1. **Test both platforms** - Ensure changes work on Windows and Linux
2. **Maintain feature parity** - Keep functionality identical across platforms
3. **Update documentation** - Document changes in this README
4. **Security first** - All changes must maintain or improve security
5. **Error handling** - Ensure robust error handling and user feedback

## 📝 License

This project is provided as-is for educational and personal use. Please review and comply with the licenses of all included components:
- PSPGP module (see PSPGP folder)
- Bundled curl.exe
- All other dependencies

## 🔐 Security Notice

**Important Security Considerations:**

1. **Protect your API tokens** - Never commit them to version control
2. **Secure your keys directory** - The .gitignore file helps prevent accidental commits
3. **Regular key rotation** - Consider regenerating PGP keys periodically
4. **Monitor DNS records** - Regularly check your Cloudflare DNS records
5. **Use strong subdomains** - Use complex, unpredictable subdomain names

**Warning:** While the encryption is military-grade, the security of your setup depends on:
- Proper Cloudflare account security
- Secure storage of the local keys directory
- Protection of your API tokens
- Regular security updates of your system

The keys directory is automatically ignored by Git, but ensure you have secure backups of your keys if needed.
