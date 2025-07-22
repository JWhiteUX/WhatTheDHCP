#!/bin/bash

# Network Analysis Helper Script
# Companion script for DHCP discovery and network troubleshooting

set -euo pipefail  # Exit on error, undefined variables, and pipe failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "\n${CYAN}=== $1 ===${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to get primary network interface
get_primary_interface() {
    local interface=""
    if command_exists ip; then
        interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    elif command_exists netstat; then
        interface=$(netstat -rn | grep default | awk '{print $NF}' | head -n1)
    else
        # Fallback for macOS
        interface=$(route get default | grep interface | awk '{print $2}')
    fi
    echo "$interface"
}

# Function to get network information
show_network_info() {
    print_header "Current Network Configuration"
    
    local interface
    interface=$(get_primary_interface)
    
    if [[ -z "$interface" ]]; then
        print_error "Could not determine primary network interface"
        return 1
    fi
    
    print_status "Primary interface: $interface"
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        print_status "Interface details:"
        ifconfig "$interface" | grep -E "(inet |ether )"
        
        print_status "DHCP lease info:"
        if [[ -f "/var/db/dhcpclient/leases/$interface" ]]; then
            cat "/var/db/dhcpclient/leases/$interface" 2>/dev/null || print_warning "Could not read DHCP lease file"
        else
            ipconfig getpacket "$interface" 2>/dev/null || print_warning "No DHCP packet info available"
        fi
        
    else
        # Linux
        print_status "Interface details:"
        ip addr show "$interface" | grep -E "(inet |link/ether)"
        
        print_status "DHCP lease info:"
        if [[ -f "/var/lib/dhcp/dhclient.leases" ]]; then
            tail -20 /var/lib/dhcp/dhclient.leases
        elif [[ -f "/var/lib/dhclient/dhclient.leases" ]]; then
            tail -20 /var/lib/dhclient/dhclient.leases
        else
            print_warning "No DHCP lease file found"
        fi
    fi
}

# Function to scan for active hosts
scan_network() {
    print_header "Active Host Discovery"
    
    local network=""
    local interface
    interface=$(get_primary_interface)
    
    if [[ -z "$interface" ]]; then
        print_error "Could not determine primary network interface"
        return 1
    fi
    
    if command_exists ip; then
        network=$(ip route | grep "$interface" | grep "/" | head -n1 | awk '{print $1}')
    else
        # Fallback method - more robust for different platforms
        local ip
        ip=$(ifconfig "$interface" | grep "inet " | head -n1 | awk '{print $2}' | sed 's/addr://')
        # Simple assumption for common networks
        if [[ -n "$ip" ]]; then
            network=$(echo "$ip" | cut -d. -f1-3).0/24
        fi
    fi
    
    if [[ -z "$network" ]]; then
        print_error "Could not determine network range"
        return 1
    fi
    
    print_status "Scanning network: $network"
    
    if command_exists nmap; then
        print_status "Using nmap for host discovery..."
        local scan_results
        scan_results=$(nmap -sn "$network" | grep -E "(Nmap scan report|MAC Address)" || true)
        if [[ -n "$scan_results" ]]; then
            echo "$scan_results"
        else
            print_warning "No hosts found via nmap scan"
        fi
    elif command_exists arp-scan; then
        print_status "Using arp-scan for host discovery..."
        if ! sudo arp-scan "$network"; then
            print_warning "arp-scan failed or found no hosts"
        fi
    else
        print_warning "nmap or arp-scan not found. Using ping sweep..."
        local base_ip
        base_ip=$(echo "$network" | cut -d. -f1-3)
        local pids=()
        
        for i in {1..254}; do
            (ping -c 1 -W 1 "$base_ip.$i" >/dev/null 2>&1 && echo "$base_ip.$i is up") &
            pids+=($!)
            # Limit concurrent processes to avoid overwhelming the system
            if (( ${#pids[@]} >= 20 )); then
                wait "${pids[@]}"
                pids=()
            fi
        done
        wait "${pids[@]}"
    fi
}

# Function to check for multiple DHCP servers using nmap
nmap_dhcp_check() {
    print_header "DHCP Server Detection (nmap method)"
    
    if ! command_exists nmap; then
        print_error "nmap not installed. Install with: brew install nmap (macOS) or apt-get install nmap (Linux)"
        return 1
    fi
    
    print_status "Scanning for DHCP servers..."
    local nmap_output
    if nmap_output=$(sudo nmap --script broadcast-dhcp-discover 2>/dev/null); then
        local dhcp_results
        dhcp_results=$(echo "$nmap_output" | grep -A 20 "broadcast-dhcp-discover" || true)
        
        if [[ -n "$dhcp_results" ]]; then
            echo "$dhcp_results"
        else
            print_warning "No DHCP servers detected via nmap broadcast method"
        fi
    else
        print_error "nmap DHCP discovery failed. This might require sudo privileges or network connectivity."
        return 1
    fi
}

# Function to analyze ARP table
analyze_arp() {
    print_header "ARP Table Analysis"
    
    print_status "Current ARP entries:"
    if command_exists ip; then
        ip neigh show
    else
        arp -a
    fi
    
    print_status "Checking for duplicate MAC addresses (potential DHCP conflicts):"
    if command_exists ip; then
        ip neigh show | awk '{print $5}' | sort | uniq -d | while read -r mac; do
            [[ -n "$mac" ]] && echo "Duplicate MAC: $mac"
        done
    else
        arp -a | awk '{print $4}' | sort | uniq -d | while read -r mac; do
            [[ -n "$mac" ]] && echo "Duplicate MAC: $mac"
        done
    fi
}

# Function to monitor DHCP traffic
monitor_dhcp() {
    print_header "DHCP Traffic Monitoring"
    
    if ! command_exists tcpdump; then
        print_error "tcpdump not available. This is usually installed by default."
        return 1
    fi
    
    local interface
    interface=$(get_primary_interface)
    
    if [[ -z "$interface" ]]; then
        print_error "Could not determine primary network interface"
        return 1
    fi
    print_status "Monitoring DHCP traffic on $interface (Press Ctrl+C to stop)..."
    print_warning "This requires sudo privileges"
    
    sudo tcpdump -i "$interface" -n port 67 or port 68
}

# Function to release and renew DHCP lease
renew_dhcp() {
    print_header "DHCP Lease Renewal"
    
    local interface
    interface=$(get_primary_interface)
    
    if [[ -z "$interface" ]]; then
        print_error "Could not determine primary network interface"
        return 1
    fi
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        print_status "Releasing DHCP lease on $interface..."
        sudo ipconfig set "$interface" NONE
        sleep 2
        print_status "Renewing DHCP lease on $interface..."
        sudo ipconfig set "$interface" DHCP
    else
        print_status "Releasing and renewing DHCP lease on $interface..."
        sudo dhclient -r "$interface"
        sleep 2
        sudo dhclient "$interface"
    fi
    
    print_status "New network configuration:"
    show_network_info
}

# Function to check common DHCP server ports and services
check_dhcp_services() {
    print_header "DHCP Service Detection"
    
    print_status "Checking for DHCP servers on common ports..."
    
    # Get network range
    local network=""
    local interface
    interface=$(get_primary_interface)
    
    if [[ -z "$interface" ]]; then
        print_error "Could not determine primary network interface"
        return 1
    fi
    
    if command_exists ip; then
        network=$(ip route | grep "$interface" | grep "/" | head -n1 | awk '{print $1}')
    else
        local ip
        ip=$(ifconfig "$interface" | grep "inet " | head -n1 | awk '{print $2}' | sed 's/addr://')
        if [[ -n "$ip" ]]; then
            network=$(echo "$ip" | cut -d. -f1-3).0/24
        fi
    fi
    
    if [[ -z "$network" ]]; then
        print_error "Could not determine network range"
        return 1
    fi
    
    if command_exists nmap; then
        print_status "Scanning for DHCP (port 67) and potential rogue servers..."
        local dhcp_scan
        dhcp_scan=$(nmap -sU -p 67 "$network" | grep -B 5 -A 5 "open" || true)
        if [[ -n "$dhcp_scan" ]]; then
            echo "$dhcp_scan"
        else
            print_status "No open DHCP ports (67/UDP) found on network"
        fi
        
        print_status "Checking for common router/AP management interfaces..."
        local web_scan
        web_scan=$(nmap -p 80,443,8080 "$network" | grep -B 2 -A 2 "open" || true)
        if [[ -n "$web_scan" ]]; then
            echo "$web_scan"
        else
            print_status "No common web management interfaces found"
        fi
    else
        print_warning "nmap not available for detailed scanning"
    fi
}

# Function to run Python DHCP discovery tool
run_dhcp_discovery() {
    print_header "Running Python DHCP Discovery Tool"
    
    if [[ -f "dhcp_discovery.py" ]]; then
        print_status "Found dhcp_discovery.py, running discovery..."
        python3 dhcp_discovery.py "$@"
    else
        print_error "dhcp_discovery.py not found in current directory"
        print_status "Please ensure the Python script is in the same directory"
    fi
}

# Function to show help
show_help() {
    echo -e "${CYAN}Network Analysis Helper Script${NC}"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  info          Show current network configuration"
    echo "  scan          Scan for active hosts on network"
    echo "  dhcp-nmap     Use nmap to detect DHCP servers"
    echo "  dhcp-python   Run Python DHCP discovery tool"
    echo "  arp           Analyze ARP table for conflicts"
    echo "  monitor       Monitor DHCP traffic (requires sudo)"
    echo "  renew         Release and renew DHCP lease"
    echo "  services      Check for DHCP services on network"
    echo "  all           Run all non-interactive checks"
    echo "  help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 info                    # Show network info"
    echo "  $0 dhcp-python -t 15       # Run Python tool with 15s timeout"
    echo "  $0 all                     # Run comprehensive analysis"
    echo ""
    echo "Note: Use 'all' (not '-all') for comprehensive analysis"
}

# Function to run all checks
run_all() {
    print_header "Comprehensive Network Analysis"
    
    # Run each function with error handling
    show_network_info || print_error "Network info check failed"
    echo ""
    
    scan_network || print_error "Network scan failed"
    echo ""
    
    analyze_arp || print_error "ARP analysis failed"
    echo ""
    
    check_dhcp_services || print_error "DHCP services check failed"
    echo ""
    
    nmap_dhcp_check || print_error "nmap DHCP check failed"
    echo ""
    
    run_dhcp_discovery || print_error "Python DHCP discovery failed"
    
    print_header "Analysis Complete"
    print_status "If multiple DHCP servers were found, investigate each one"
    print_status "Look for unauthorized devices offering DHCP services"
    print_warning "Consider temporarily disabling suspected rogue DHCP servers for testing"
}

# Main script logic
main() {
    case "${1:-help}" in
        "info")
            show_network_info
            ;;
        "scan")
            scan_network
            ;;
        "dhcp-nmap")
            nmap_dhcp_check
            ;;
        "dhcp-python")
            shift
            run_dhcp_discovery "$@"
            ;;
        "arp")
            analyze_arp
            ;;
        "monitor")
            monitor_dhcp
            ;;
        "renew")
            renew_dhcp
            ;;
        "services")
            check_dhcp_services
            ;;
        "all")
            run_all
            ;;
        "help"|*)
            show_help
            ;;
    esac
}

# Only run main if script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi