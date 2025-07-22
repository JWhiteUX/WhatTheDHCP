#!/usr/bin/env python3
"""
Simple DHCP Detection Tool
Uses practical methods that actually work on real networks
"""

import subprocess
import re
import json
import sys
import time
from typing import Dict, List, Optional

class SimpleDHCPDetector:
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.servers = {}
        
    def debug_print(self, message: str):
        if self.debug:
            print(f"[DEBUG] {message}")
    
    def get_current_dhcp_info(self) -> Dict:
        """Get current DHCP information from the system"""
        print("🔍 Method 1: Current DHCP Configuration Analysis")
        
        info = {}
        
        if sys.platform == "darwin":  # macOS
            try:
                # Get DHCP info for primary interface
                result = subprocess.run(['ipconfig', 'getpacket', 'en0'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    output = result.stdout
                    self.debug_print(f"ipconfig output: {output}")
                    
                    # Parse DHCP server info
                    server_match = re.search(r'server_identifier \(ip\): (.+)', output)
                    if server_match:
                        server_ip = server_match.group(1)
                        info[server_ip] = {'method': 'ipconfig', 'interface': 'en0'}
                        print(f"   ✅ Current DHCP server: {server_ip}")
                        
                        # Get additional info
                        subnet_match = re.search(r'subnet_mask \(ip\): (.+)', output)
                        if subnet_match:
                            info[server_ip]['subnet_mask'] = subnet_match.group(1)
                            
                        router_match = re.search(r'router \(ip_mult\): {(.+)}', output)
                        if router_match:
                            info[server_ip]['router'] = router_match.group(1)
                            
                        lease_match = re.search(r'lease_time \(uint32\): (.+)', output)
                        if lease_match:
                            info[server_ip]['lease_time'] = lease_match.group(1)
                    else:
                        print("   ❌ No DHCP server info found in current config")
                else:
                    print("   ❌ Could not get DHCP packet info")
                    
            except Exception as e:
                self.debug_print(f"Error getting macOS DHCP info: {e}")
                
        else:  # Linux
            try:
                # Check dhclient lease files
                lease_files = [
                    '/var/lib/dhcp/dhclient.leases',
                    '/var/lib/dhclient/dhclient.leases'
                ]
                
                for lease_file in lease_files:
                    try:
                        with open(lease_file, 'r') as f:
                            content = f.read()
                            
                        # Find most recent lease
                        leases = re.findall(r'lease {.*?}', content, re.DOTALL)
                        if leases:
                            latest_lease = leases[-1]  # Get the last lease
                            
                            server_match = re.search(r'option dhcp-server-identifier (.+?);', latest_lease)
                            if server_match:
                                server_ip = server_match.group(1)
                                info[server_ip] = {'method': 'dhclient_lease', 'lease_file': lease_file}
                                print(f"   ✅ DHCP server from lease: {server_ip}")
                                
                                # Get additional lease info
                                subnet_match = re.search(r'option subnet-mask (.+?);', latest_lease)
                                if subnet_match:
                                    info[server_ip]['subnet_mask'] = subnet_match.group(1)
                                    
                                router_match = re.search(r'option routers (.+?);', latest_lease)
                                if router_match:
                                    info[server_ip]['router'] = router_match.group(1)
                        break
                    except FileNotFoundError:
                        continue
                        
            except Exception as e:
                self.debug_print(f"Error getting Linux DHCP info: {e}")
        
        return info
    
    def network_scan_dhcp_ports(self) -> Dict:
        """Scan network for devices with DHCP ports open"""
        print("🔍 Method 2: Network Scan for DHCP Services")
        
        info = {}
        
        try:
            # Get network range
            if sys.platform == "darwin":
                # Get current IP and assume /24 network
                result = subprocess.run(['ifconfig', 'en0'], capture_output=True, text=True)
                if result.returncode == 0:
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                    if ip_match:
                        current_ip = ip_match.group(1)
                        network = '.'.join(current_ip.split('.')[:-1]) + '.0/24'
                        self.debug_print(f"Scanning network: {network}")
                    else:
                        print("   ❌ Could not determine network range")
                        return info
            else:
                # Linux - use ip command
                result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
                network_match = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', result.stdout)
                if network_match:
                    network = network_match.group(1)
                else:
                    print("   ❌ Could not determine network range")
                    return info
            
            # Use nmap to scan for DHCP servers
            print(f"   Scanning {network} for DHCP services...")
            result = subprocess.run([
                'nmap', '-sU', '-p', '67', '--open', network
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Parse nmap output for open ports
                current_host = None
                for line in result.stdout.split('\n'):
                    host_match = re.search(r'Nmap scan report for (.+)', line)
                    if host_match:
                        current_host = host_match.group(1)
                        # Extract IP if hostname is given
                        ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', current_host)
                        if ip_match:
                            current_host = ip_match.group(1)
                        elif not re.match(r'\d+\.\d+\.\d+\.\d+', current_host):
                            # If it's a hostname, try to resolve
                            continue
                    elif current_host and '67/udp' in line and 'open' in line:
                        info[current_host] = {'method': 'nmap_scan', 'port_67_open': True}
                        print(f"   ✅ Found device with DHCP port open: {current_host}")
                        
            else:
                print("   ❌ Nmap scan failed")
                
        except subprocess.TimeoutExpired:
            print("   ⏱️ Network scan timed out")
        except FileNotFoundError:
            print("   ❌ Nmap not installed - skipping network scan")
        except Exception as e:
            self.debug_print(f"Network scan error: {e}")
            
        return info
    
    def arp_table_analysis(self) -> Dict:
        """Analyze ARP table for potential DHCP servers"""
        print("🔍 Method 3: ARP Table Analysis")
        
        info = {}
        
        try:
            # Get ARP table
            if sys.platform == "darwin":
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            else:
                result = subprocess.run(['ip', 'neigh', 'show'], capture_output=True, text=True)
            
            if result.returncode == 0:
                arp_entries = result.stdout.split('\n')
                self.debug_print(f"Found {len(arp_entries)} ARP entries")
                
                # Look for common router/DHCP server patterns
                dhcp_candidates = []
                
                for entry in arp_entries:
                    # Extract IP addresses
                    ip_matches = re.findall(r'(\d+\.\d+\.\d+\.\d+)', entry)
                    for ip in ip_matches:
                        # Common DHCP server IPs (usually router IPs)
                        if (ip.endswith('.1') or ip.endswith('.254') or 
                            ip.endswith('.10') or ip.endswith('.100')):
                            dhcp_candidates.append(ip)
                
                # Remove duplicates and check each candidate
                for candidate in set(dhcp_candidates):
                    info[candidate] = {'method': 'arp_analysis', 'likely_router': True}
                    print(f"   🤔 Potential DHCP server (common router IP): {candidate}")
                    
            else:
                print("   ❌ Could not get ARP table")
                
        except Exception as e:
            self.debug_print(f"ARP analysis error: {e}")
            
        return info
    
    def dhcp_renewal_test(self) -> Dict:
        """Test DHCP by forcing renewal and capturing server info"""
        print("🔍 Method 4: DHCP Renewal Test")
        
        info = {}
        
        try:
            if sys.platform == "darwin":
                print("   Forcing DHCP renewal on en0...")
                
                # Release current lease
                result1 = subprocess.run(['sudo', 'ipconfig', 'set', 'en0', 'NONE'], 
                                       capture_output=True, text=True)
                time.sleep(2)
                
                # Request new lease
                result2 = subprocess.run(['sudo', 'ipconfig', 'set', 'en0', 'DHCP'], 
                                       capture_output=True, text=True)
                time.sleep(3)
                
                # Check new configuration
                result3 = subprocess.run(['ipconfig', 'getpacket', 'en0'], 
                                       capture_output=True, text=True)
                
                if result3.returncode == 0:
                    output = result3.stdout
                    server_match = re.search(r'server_identifier \(ip\): (.+)', output)
                    if server_match:
                        server_ip = server_match.group(1)
                        info[server_ip] = {'method': 'dhcp_renewal', 'interface': 'en0'}
                        print(f"   ✅ DHCP server responded to renewal: {server_ip}")
                    else:
                        print("   ❌ No DHCP server info after renewal")
                else:
                    print("   ❌ Could not get packet info after renewal")
                    
            else:
                print("   Linux DHCP renewal test not implemented (use dhclient)")
                
        except Exception as e:
            print(f"   ❌ Error during DHCP renewal: {e}")
            self.debug_print(f"Renewal error details: {e}")
            
        return info
    
    def router_web_interface_check(self) -> Dict:
        """Check common router IPs for web interfaces (potential DHCP servers)"""
        print("🔍 Method 5: Router Web Interface Detection")
        
        info = {}
        common_router_ips = [
            '192.168.1.1', '192.168.0.1', '192.168.1.254', '192.168.0.254',
            '10.0.0.1', '10.0.1.1', '172.16.0.1', '192.168.2.1'
        ]
        
        try:
            # Get current network to focus scan
            if sys.platform == "darwin":
                result = subprocess.run(['route', 'get', 'default'], capture_output=True, text=True)
                if result.returncode == 0:
                    gateway_match = re.search(r'gateway: (.+)', result.stdout)
                    if gateway_match:
                        gateway = gateway_match.group(1)
                        if gateway not in common_router_ips:
                            common_router_ips.insert(0, gateway)
                        self.debug_print(f"Current gateway: {gateway}")
            
            for router_ip in common_router_ips[:5]:  # Check first 5
                try:
                    # Quick ping test
                    ping_result = subprocess.run(['ping', '-c', '1', '-W', '1000', router_ip], 
                                               capture_output=True, text=True, timeout=2)
                    
                    if ping_result.returncode == 0:
                        info[router_ip] = {'method': 'router_check', 'responds_to_ping': True}
                        print(f"   🤔 Active router/gateway found: {router_ip}")
                        
                except subprocess.TimeoutExpired:
                    continue
                except Exception as e:
                    self.debug_print(f"Error checking {router_ip}: {e}")
                    
        except Exception as e:
            self.debug_print(f"Router check error: {e}")
            
        return info
    
    def detect_servers(self) -> Dict:
        """Run all detection methods"""
        print("🔍 Starting Practical DHCP Server Detection...")
        print("=" * 60)
        
        all_servers = {}
        
        methods = [
            self.get_current_dhcp_info,
            self.network_scan_dhcp_ports,
            self.arp_table_analysis,
            self.dhcp_renewal_test,
            self.router_web_interface_check
        ]
        
        for method in methods:
            try:
                servers = method()
                for server_ip, info in servers.items():
                    if server_ip not in all_servers:
                        all_servers[server_ip] = info
                    else:
                        # Merge info from multiple methods
                        all_servers[server_ip].update(info)
                        
            except Exception as e:
                self.debug_print(f"Method {method.__name__} failed: {e}")
            
            print()
            
        return all_servers
    
    def print_results(self, servers: Dict):
        """Print detection results"""
        if not servers:
            print("❌ No DHCP servers detected!")
            print("\nThis could mean:")
            print("- Network uses static IP configuration")
            print("- DHCP server is heavily firewalled")
            print("- Detection methods need adjustment for this network")
            return
        
        print(f"✅ Found {len(servers)} potential DHCP server(s):")
        print("=" * 70)
        
        confidence_levels = {
            'ipconfig': '🟢 HIGH',
            'dhclient_lease': '🟢 HIGH', 
            'dhcp_renewal': '🟢 HIGH',
            'nmap_scan': '🟡 MEDIUM',
            'arp_analysis': '🟠 LOW',
            'router_check': '🟠 LOW'
        }
        
        # Sort by confidence level
        sorted_servers = sorted(servers.items(), 
                              key=lambda x: list(confidence_levels.keys()).index(x[1].get('method', 'unknown')))
        
        for i, (server_ip, info) in enumerate(sorted_servers, 1):
            method = info.get('method', 'unknown')
            confidence = confidence_levels.get(method, '🔴 UNKNOWN')
            
            print(f"\n🖥️  Server #{i}: {server_ip}")
            print(f"   Confidence:     {confidence}")
            print(f"   Detection:      {method}")
            
            for key, value in info.items():
                if key not in ['method']:
                    print(f"   {key.replace('_', ' ').title()}: {value}")
            
            print("-" * 50)
        
        # Analysis
        high_confidence = [s for s, info in servers.items() 
                          if info.get('method') in ['ipconfig', 'dhclient_lease', 'dhcp_renewal']]
        
        if len(high_confidence) > 1:
            print("\n🚨 MULTIPLE HIGH-CONFIDENCE DHCP SERVERS!")
            print("   This strongly suggests a rogue DHCP server.")
            print("   High-confidence servers:", ', '.join(high_confidence))
        elif len(high_confidence) == 1:
            print(f"\n✅ Single high-confidence DHCP server: {high_confidence[0]}")
        else:
            print("\n🤔 No high-confidence DHCP servers found.")
            print("   Check medium/low confidence results above.")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Simple DHCP Server Detection Tool')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
    
    args = parser.parse_args()
    
    try:
        detector = SimpleDHCPDetector(debug=args.debug)
        servers = detector.detect_servers()
        detector.print_results(servers)
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Detection stopped by user.")
    except Exception as e:
        print(f"\n❌ Error during detection: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()