"""
Packet Filter - Rule-based packet filtering engine
Implements all filtering rules: app, IP/domain, protocol, port, geo-IP, time-based, etc.
"""

from typing import Optional, Tuple, List
from datetime import datetime, time
import ipaddress

from utils.data_models import NetworkPacket, Protocol, TrafficDirection
from config.config import config


class PacketFilter:
    """
    Rule-based packet filtering engine
    Applies filtering rules before packets reach ML analysis
    """
    
    def __init__(self):
        self.config = config.filter
        
        # Blocked apps (user-configured)
        self.blocked_apps: set = set()
        
        # Blocked IPs and domains
        self.blocked_ips: set = set()
        self.blocked_domains: set = set()
        
        # Allowed apps (whitelist mode)
        self.allowed_apps: set = set()
        self.whitelist_mode = False
        
        # Per-app rules
        self.app_rules: dict = {}  # app -> rules dict
        
        # Time-based rules
        self.night_mode_blocked_apps: set = set()
    
    def should_block(self, packet: NetworkPacket) -> Tuple[bool, Optional[str]]:
        """
        Determine if packet should be blocked based on rules
        
        Returns:
            - should_block: bool
            - reason: Optional[str] - reason for blocking
        """
        # 1. Check app-level blocking
        if packet.app_package_name in self.blocked_apps:
            return True, f"App {packet.app_package_name} is blocked"
        
        # 2. Check whitelist mode
        if self.whitelist_mode and packet.app_package_name not in self.allowed_apps:
            return True, f"App not in whitelist"
        
        # 3. Check destination IP blocking
        if packet.destination_ip in self.blocked_ips:
            return True, f"Destination IP {packet.destination_ip} is blocked"
        
        # 4. Check domain blocking
        if packet.domain and packet.domain in self.blocked_domains:
            return True, f"Domain {packet.domain} is blocked"
        
        # 5. Check protocol blocking
        if packet.protocol == Protocol.ICMP and self.config.block_icmp:
            return True, "ICMP protocol is blocked"
        
        # 6. Check port blocking
        if packet.destination_port in self.config.blocked_ports:
            return True, f"Port {packet.destination_port} is blocked (dangerous port)"
        
        # 7. Check time-based rules
        if self.config.enable_time_based_rules:
            is_night = self._is_night_time()
            if is_night and packet.app_package_name in self.night_mode_blocked_apps:
                return True, f"App blocked during night mode"
        
        # 8. Check per-app custom rules
        if packet.app_package_name in self.app_rules:
            should_block, reason = self._check_app_rules(packet)
            if should_block:
                return True, reason
        
        # 9. Check traffic direction rules (if configured)
        # Could add rules like "block all inbound" for certain apps
        
        return False, None
    
    def _check_app_rules(self, packet: NetworkPacket) -> Tuple[bool, Optional[str]]:
        """Check per-app custom rules"""
        rules = self.app_rules[packet.app_package_name]
        
        # Check allowed protocols
        if 'allowed_protocols' in rules:
            if packet.protocol.value not in rules['allowed_protocols']:
                return True, f"Protocol {packet.protocol.value} not allowed for this app"
        
        # Check allowed ports
        if 'allowed_ports' in rules:
            if packet.destination_port not in rules['allowed_ports']:
                return True, f"Port {packet.destination_port} not allowed for this app"
        
        # Check allowed destinations
        if 'allowed_destinations' in rules:
            if packet.destination_ip not in rules['allowed_destinations']:
                return True, f"Destination not in allowed list"
        
        # Check blocked destinations
        if 'blocked_destinations' in rules:
            if packet.destination_ip in rules['blocked_destinations']:
                return True, f"Destination in blocked list"
        
        # Check data limit
        if 'data_limit_mb' in rules:
            # Would need to track data usage per app
            pass
        
        return False, None
    
    def _is_night_time(self) -> bool:
        """Check if current time is within night mode hours"""
        current_hour = datetime.now().hour
        start = self.config.night_mode_start_hour
        end = self.config.night_mode_end_hour
        
        if start < end:
            return start <= current_hour < end
        else:
            # Night mode crosses midnight
            return current_hour >= start or current_hour < end
    
    # Configuration methods
    
    def block_app(self, app: str):
        """Block all traffic from an app"""
        self.blocked_apps.add(app)
    
    def unblock_app(self, app: str):
        """Unblock an app"""
        self.blocked_apps.discard(app)
    
    def allow_app(self, app: str):
        """Add app to whitelist"""
        self.allowed_apps.add(app)
    
    def block_ip(self, ip: str):
        """Block traffic to an IP address"""
        self.blocked_ips.add(ip)
    
    def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        self.blocked_ips.discard(ip)
    
    def block_domain(self, domain: str):
        """Block traffic to a domain"""
        self.blocked_domains.add(domain)
    
    def unblock_domain(self, domain: str):
        """Unblock a domain"""
        self.blocked_domains.discard(domain)
    
    def add_app_rule(self, app: str, rule_type: str, value):
        """Add custom rule for an app"""
        if app not in self.app_rules:
            self.app_rules[app] = {}
        
        self.app_rules[app][rule_type] = value
    
    def remove_app_rule(self, app: str, rule_type: str):
        """Remove custom rule for an app"""
        if app in self.app_rules and rule_type in self.app_rules[app]:
            del self.app_rules[app][rule_type]
    
    def enable_whitelist_mode(self):
        """Enable whitelist mode (only allowed apps can access network)"""
        self.whitelist_mode = True
    
    def disable_whitelist_mode(self):
        """Disable whitelist mode"""
        self.whitelist_mode = False
    
    def add_night_mode_app(self, app: str):
        """Block app during night hours"""
        self.night_mode_blocked_apps.add(app)
    
    def remove_night_mode_app(self, app: str):
        """Remove app from night mode blocking"""
        self.night_mode_blocked_apps.discard(app)
    
    def get_blocked_apps(self) -> List[str]:
        """Get list of blocked apps"""
        return list(self.blocked_apps)
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IPs"""
        return list(self.blocked_ips)
    
    def get_blocked_domains(self) -> List[str]:
        """Get list of blocked domains"""
        return list(self.blocked_domains)
    
    def export_rules(self) -> dict:
        """Export all filtering rules"""
        return {
            'blocked_apps': list(self.blocked_apps),
            'allowed_apps': list(self.allowed_apps),
            'whitelist_mode': self.whitelist_mode,
            'blocked_ips': list(self.blocked_ips),
            'blocked_domains': list(self.blocked_domains),
            'blocked_ports': self.config.blocked_ports,
            'night_mode_apps': list(self.night_mode_blocked_apps),
            'app_rules': self.app_rules,
            'config': {
                'block_icmp': self.config.block_icmp,
                'enable_time_based_rules': self.config.enable_time_based_rules,
                'night_mode_start_hour': self.config.night_mode_start_hour,
                'night_mode_end_hour': self.config.night_mode_end_hour
            }
        }
    
    def import_rules(self, rules: dict):
        """Import filtering rules"""
        self.blocked_apps = set(rules.get('blocked_apps', []))
        self.allowed_apps = set(rules.get('allowed_apps', []))
        self.whitelist_mode = rules.get('whitelist_mode', False)
        self.blocked_ips = set(rules.get('blocked_ips', []))
        self.blocked_domains = set(rules.get('blocked_domains', []))
        self.night_mode_blocked_apps = set(rules.get('night_mode_apps', []))
        self.app_rules = rules.get('app_rules', {})


class GeoIPFilter:
    """
    Geo-IP based filtering
    Blocks traffic based on country/region
    """
    
    def __init__(self):
        self.config = config.filter
        self.blocked_countries = set(self.config.blocked_countries)
        
        # Would integrate with MaxMind GeoIP2 or similar
        # For now, placeholder
        self.geoip_db = None
    
    def should_block(self, ip: str) -> Tuple[bool, Optional[str]]:
        """Check if IP should be blocked based on geo-location"""
        if not self.config.enable_geo_blocking:
            return False, None
        
        # Get country for IP
        country = self._get_country(ip)
        
        if country and country in self.blocked_countries:
            return True, f"Traffic from {country} is blocked"
        
        return False, None
    
    def _get_country(self, ip: str) -> Optional[str]:
        """Get country code for IP address"""
        # Would use GeoIP2 database here
        # Placeholder implementation
        return None
    
    def block_country(self, country_code: str):
        """Block traffic from a country"""
        self.blocked_countries.add(country_code.upper())
    
    def unblock_country(self, country_code: str):
        """Unblock traffic from a country"""
        self.blocked_countries.discard(country_code.upper())
    
    def get_blocked_countries(self) -> List[str]:
        """Get list of blocked countries"""
        return list(self.blocked_countries)
