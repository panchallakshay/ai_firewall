"""
Multi-source Threat Intelligence Integration
Integrates AbuseIPDB, AlienVault OTX, URLhaus, and local threat databases
"""

import requests
import json
import hashlib
import time
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from pathlib import Path
import sqlite3

from utils.data_models import ThreatIntelligenceResult
from config.config import config


class ThreatIntelligence:
    """
    Multi-source threat intelligence lookup with caching
    """
    
    def __init__(self):
        self.config = config.threat_intel
        
        # Initialize cache
        self.memory_cache: Dict[str, ThreatIntelligenceResult] = {}
        self.cache_timestamps: Dict[str, datetime] = {}
        
        # Initialize disk cache (SQLite)
        if self.config.enable_disk_cache:
            self._init_disk_cache()
        
        # Rate limiting
        self.api_call_counts: Dict[str, List[datetime]] = {
            'abuseipdb': [],
            'virustotal': [],
            'alienvault': [],
            'urlhaus': []
        }
        
        # Load local threat database
        self.local_blocklist = self._load_local_blocklist()
    
    def _init_disk_cache(self):
        """Initialize SQLite cache database"""
        cache_dir = Path(self.config.cache_directory)
        cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.cache_db_path = cache_dir / "threat_cache.db"
        conn = sqlite3.connect(str(self.cache_db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_cache (
                ip_or_domain TEXT PRIMARY KEY,
                is_malicious INTEGER,
                threat_score REAL,
                sources TEXT,
                categories TEXT,
                country TEXT,
                asn TEXT,
                timestamp TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def _load_local_blocklist(self) -> set:
        """Load local blocklist from file"""
        blocklist = set()
        
        # Common blocklist sources (would be downloaded/updated periodically)
        blocklist_files = [
            'data/blocklists/firebog.txt',
            'data/blocklists/steven_black.txt',
            'data/blocklists/abuse_ch.txt'
        ]
        
        for filepath in blocklist_files:
            try:
                with open(filepath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            blocklist.add(line)
            except FileNotFoundError:
                pass  # File doesn't exist yet
        
        return blocklist
    
    def check_threat(self, ip_or_domain: str) -> ThreatIntelligenceResult:
        """
        Check if IP or domain is malicious using multiple sources
        Returns aggregated threat intelligence result
        """
        # Check memory cache first
        if ip_or_domain in self.memory_cache:
            cached_time = self.cache_timestamps.get(ip_or_domain)
            if cached_time and (datetime.now() - cached_time).days < self.config.cache_ttl_days:
                result = self.memory_cache[ip_or_domain]
                result.cached = True
                return result
        
        # Check disk cache
        if self.config.enable_disk_cache:
            cached_result = self._check_disk_cache(ip_or_domain)
            if cached_result:
                cached_result.cached = True
                self.memory_cache[ip_or_domain] = cached_result
                self.cache_timestamps[ip_or_domain] = datetime.now()
                return cached_result
        
        # Check local blocklist (instant, no API call)
        if ip_or_domain in self.local_blocklist:
            result = ThreatIntelligenceResult(
                ip_or_domain=ip_or_domain,
                is_malicious=True,
                threat_score=100.0,
                sources=['local_blocklist'],
                categories=['blocklist'],
                cached=False
            )
            self._cache_result(result)
            return result
        
        # Query multiple threat intelligence sources
        results = []
        
        # 1. AbuseIPDB (primary for IPs)
        if self._is_ip(ip_or_domain) and self.config.abuseipdb_api_key:
            abuseipdb_result = self._query_abuseipdb(ip_or_domain)
            if abuseipdb_result:
                results.append(abuseipdb_result)
        
        # 2. AlienVault OTX
        if self.config.alienvault_api_key:
            otx_result = self._query_alienvault(ip_or_domain)
            if otx_result:
                results.append(otx_result)
        
        # 3. URLhaus (for domains)
        if not self._is_ip(ip_or_domain):
            urlhaus_result = self._query_urlhaus(ip_or_domain)
            if urlhaus_result:
                results.append(urlhaus_result)
        
        # 4. VirusTotal (fallback, rate-limited)
        if self.config.virustotal_api_key and len(results) == 0:
            vt_result = self._query_virustotal(ip_or_domain)
            if vt_result:
                results.append(vt_result)
        
        # Aggregate results
        aggregated = self._aggregate_results(ip_or_domain, results)
        
        # Cache the result
        self._cache_result(aggregated)
        
        return aggregated
    
    def _query_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Query AbuseIPDB API"""
        if not self._check_rate_limit('abuseipdb', self.config.abuseipdb_max_requests_per_day):
            return None
        
        try:
            headers = {
                'Key': self.config.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': True
            }
            
            response = requests.get(
                self.config.abuseipdb_url,
                headers=headers,
                params=params,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()['data']
                
                return {
                    'source': 'abuseipdb',
                    'is_malicious': data['abuseConfidenceScore'] > 50,
                    'threat_score': data['abuseConfidenceScore'],
                    'categories': data.get('usageType', ''),
                    'country': data.get('countryCode', ''),
                    'asn': data.get('isp', '')
                }
        
        except Exception as e:
            print(f"AbuseIPDB query failed: {e}")
        
        return None
    
    def _query_alienvault(self, indicator: str) -> Optional[Dict]:
        """Query AlienVault OTX API"""
        try:
            indicator_type = 'IPv4' if self._is_ip(indicator) else 'domain'
            url = f"{self.config.alienvault_url}/{indicator_type}/{indicator}/general"
            
            headers = {
                'X-OTX-API-KEY': self.config.alienvault_api_key
            }
            
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                # OTX provides pulse count and reputation
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                
                return {
                    'source': 'alienvault_otx',
                    'is_malicious': pulse_count > 0,
                    'threat_score': min(pulse_count * 10, 100),  # Scale to 0-100
                    'categories': 'threat_feed',
                    'country': data.get('country_code', ''),
                    'asn': data.get('asn', '')
                }
        
        except Exception as e:
            print(f"AlienVault OTX query failed: {e}")
        
        return None
    
    def _query_urlhaus(self, domain: str) -> Optional[Dict]:
        """Query URLhaus API"""
        try:
            data = {'url': domain}
            
            response = requests.post(
                self.config.urlhaus_url,
                data=data,
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('query_status') == 'ok':
                    return {
                        'source': 'urlhaus',
                        'is_malicious': True,
                        'threat_score': 90.0,
                        'categories': result.get('threat', 'malware'),
                        'country': '',
                        'asn': ''
                    }
        
        except Exception as e:
            print(f"URLhaus query failed: {e}")
        
        return None
    
    def _query_virustotal(self, indicator: str) -> Optional[Dict]:
        """Query VirusTotal API (rate-limited fallback)"""
        if not self._check_rate_limit('virustotal', self.config.virustotal_max_requests_per_minute, window_minutes=1):
            return None
        
        try:
            headers = {
                'x-apikey': self.config.virustotal_api_key
            }
            
            endpoint = 'ip_addresses' if self._is_ip(indicator) else 'domains'
            url = f"https://www.virustotal.com/api/v3/{endpoint}/{indicator}"
            
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()['data']['attributes']
                stats = data.get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                total = sum(stats.values())
                
                return {
                    'source': 'virustotal',
                    'is_malicious': malicious > 0,
                    'threat_score': (malicious / total * 100) if total > 0 else 0,
                    'categories': 'multiple',
                    'country': data.get('country', ''),
                    'asn': str(data.get('asn', ''))
                }
        
        except Exception as e:
            print(f"VirusTotal query failed: {e}")
        
        return None
    
    def _aggregate_results(self, ip_or_domain: str, results: List[Dict]) -> ThreatIntelligenceResult:
        """Aggregate results from multiple sources"""
        if not results:
            return ThreatIntelligenceResult(
                ip_or_domain=ip_or_domain,
                is_malicious=False,
                threat_score=0.0,
                sources=[],
                categories=[]
            )
        
        # Calculate weighted threat score
        total_score = sum(r['threat_score'] for r in results)
        avg_score = total_score / len(results)
        
        # Determine if malicious (require multiple sources for high confidence)
        malicious_count = sum(1 for r in results if r['is_malicious'])
        is_malicious = malicious_count >= self.config.min_sources_for_block
        
        # Aggregate metadata
        sources = [r['source'] for r in results]
        categories = list(set(r['categories'] for r in results if r['categories']))
        
        # Get country and ASN from first result that has it
        country = next((r['country'] for r in results if r.get('country')), None)
        asn = next((r['asn'] for r in results if r.get('asn')), None)
        
        return ThreatIntelligenceResult(
            ip_or_domain=ip_or_domain,
            is_malicious=is_malicious,
            threat_score=avg_score,
            sources=sources,
            categories=categories,
            country=country,
            asn=asn,
            cached=False
        )
    
    def _check_rate_limit(self, api_name: str, max_requests: int, window_minutes: int = 1440) -> bool:
        """Check if API rate limit allows another request"""
        now = datetime.now()
        cutoff = now - timedelta(minutes=window_minutes)
        
        # Remove old timestamps
        self.api_call_counts[api_name] = [
            ts for ts in self.api_call_counts[api_name]
            if ts > cutoff
        ]
        
        # Check if under limit
        if len(self.api_call_counts[api_name]) >= max_requests:
            return False
        
        # Record this call
        self.api_call_counts[api_name].append(now)
        return True
    
    def _cache_result(self, result: ThreatIntelligenceResult):
        """Cache result in memory and disk"""
        # Memory cache
        self.memory_cache[result.ip_or_domain] = result
        self.cache_timestamps[result.ip_or_domain] = datetime.now()
        
        # Disk cache
        if self.config.enable_disk_cache:
            conn = sqlite3.connect(str(self.cache_db_path))
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO threat_cache 
                (ip_or_domain, is_malicious, threat_score, sources, categories, country, asn, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.ip_or_domain,
                1 if result.is_malicious else 0,
                result.threat_score,
                json.dumps(result.sources),
                json.dumps(result.categories),
                result.country,
                result.asn,
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
    
    def _check_disk_cache(self, ip_or_domain: str) -> Optional[ThreatIntelligenceResult]:
        """Check disk cache for cached result"""
        try:
            conn = sqlite3.connect(str(self.cache_db_path))
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT * FROM threat_cache WHERE ip_or_domain = ?",
                (ip_or_domain,)
            )
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                cached_time = datetime.fromisoformat(row[7])
                if (datetime.now() - cached_time).days < self.config.cache_ttl_days:
                    return ThreatIntelligenceResult(
                        ip_or_domain=row[0],
                        is_malicious=bool(row[1]),
                        threat_score=row[2],
                        sources=json.loads(row[3]),
                        categories=json.loads(row[4]),
                        country=row[5],
                        asn=row[6],
                        cached=True
                    )
        
        except Exception as e:
            print(f"Disk cache check failed: {e}")
        
        return None
    
    @staticmethod
    def _is_ip(value: str) -> bool:
        """Check if value is an IP address"""
        parts = value.split('.')
        if len(parts) != 4:
            return False
        
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
