"""
DNS Feature Extraction for Threat Detection
Extracts 11 features from domain names for AI model training
"""

import re
import math
import tldextract
from collections import Counter
from typing import Dict, Tuple


class DnsFeatureExtractor:
    """Extract features from domain names for threat detection"""
    
    # High-risk TLDs based on abuse prevalence
    HIGH_RISK_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq',  # Free TLDs
        'xyz', 'top', 'work', 'click', 'link',  # Commonly abused
        'ru', 'cn', 'pw', 'cc'  # Geographic/abuse-prone
    }
    
    def __init__(self, tranco_ranks: Dict[str, int] = None):
        """
        Initialize feature extractor
        
        Args:
            tranco_ranks: Optional dict mapping domain -> rank for popularity scoring
        """
        self.tranco_ranks = tranco_ranks or {}
    
    def extract_features(self, domain: str, dns_stats: Dict = None) -> Tuple[list, list]:
        """
        Extract all DNS features from a domain
        
        Args:
            domain: Domain name (e.g., "example.com")
            dns_stats: Optional dict with temporal stats:
                - queries_per_min: DNS queries in last minute
                - unique_domains_per_min: Unique domains queried in last minute
        
        Returns:
            Tuple of (feature_vector, feature_names)
        """
        dns_stats = dns_stats or {}
        
        # Parse domain
        extracted = tldextract.extract(domain)
        full_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        subdomain = extracted.subdomain
        
        features = []
        feature_names = []
        
        # 1. Domain length
        features.append(len(domain))
        feature_names.append('domain_length')
        
        # 2. Number of dots (subdomain depth)
        features.append(domain.count('.'))
        feature_names.append('num_dots')
        
        # 3. Shannon entropy (randomness indicator)
        features.append(self._calculate_entropy(domain))
        feature_names.append('entropy')
        
        # 4. Punycode flag (IDN homograph attacks)
        features.append(1.0 if domain.startswith('xn--') else 0.0)
        feature_names.append('is_punycode')
        
        # 5. Digit ratio
        features.append(self._digit_ratio(domain))
        feature_names.append('digit_ratio')
        
        # 6. Vowel ratio
        features.append(self._vowel_ratio(domain))
        feature_names.append('vowel_ratio')
        
        # 7. TLD risk score
        features.append(self._tld_risk_score(extracted.suffix))
        feature_names.append('tld_risk')
        
        # 8. Consecutive consonants (DGA indicator)
        features.append(self._max_consecutive_consonants(domain))
        feature_names.append('max_consecutive_consonants')
        
        # 9. DNS queries per minute (burst detection)
        features.append(dns_stats.get('queries_per_min', 0.0))
        feature_names.append('queries_per_min')
        
        # 10. Unique domains per minute (scanning behavior)
        features.append(dns_stats.get('unique_domains_per_min', 0.0))
        feature_names.append('unique_domains_per_min')
        
        # 11. Tranco rank bucket (popularity indicator)
        features.append(self._tranco_rank_bucket(full_domain))
        feature_names.append('tranco_rank_bucket')
        
        return features, feature_names
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of string"""
        if not s:
            return 0.0
        
        # Count character frequencies
        counter = Counter(s)
        length = len(s)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _digit_ratio(self, s: str) -> float:
        """Calculate ratio of digits to total characters"""
        if not s:
            return 0.0
        digits = sum(1 for c in s if c.isdigit())
        return digits / len(s)
    
    def _vowel_ratio(self, s: str) -> float:
        """Calculate ratio of vowels to total alphabetic characters"""
        vowels = 'aeiouAEIOU'
        alpha_chars = [c for c in s if c.isalpha()]
        if not alpha_chars:
            return 0.0
        vowel_count = sum(1 for c in alpha_chars if c in vowels)
        return vowel_count / len(alpha_chars)
    
    def _tld_risk_score(self, tld: str) -> float:
        """Score TLD based on abuse prevalence"""
        if not tld:
            return 0.5  # Unknown TLD
        
        tld_lower = tld.lower()
        if tld_lower in self.HIGH_RISK_TLDS:
            return 1.0  # High risk
        elif tld_lower in ['com', 'org', 'net', 'edu', 'gov']:
            return 0.0  # Low risk (established TLDs)
        else:
            return 0.3  # Medium risk (other TLDs)
    
    def _max_consecutive_consonants(self, s: str) -> int:
        """Find maximum consecutive consonants (DGA indicator)"""
        vowels = set('aeiouAEIOU')
        max_count = 0
        current_count = 0
        
        for char in s:
            if char.isalpha() and char not in vowels:
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        
        return max_count
    
    def _tranco_rank_bucket(self, domain: str) -> float:
        """
        Convert Tranco rank to bucket score
        
        Buckets:
        - 0.0: Top 10k (very popular)
        - 0.25: Top 100k
        - 0.5: Top 1M
        - 0.75: Known but not top 1M
        - 1.0: Unknown domain
        """
        if domain not in self.tranco_ranks:
            return 1.0  # Unknown
        
        rank = self.tranco_ranks[domain]
        if rank <= 10000:
            return 0.0
        elif rank <= 100000:
            return 0.25
        elif rank <= 1000000:
            return 0.5
        else:
            return 0.75


def load_tranco_ranks(filepath: str, max_ranks: int = 1000000) -> Dict[str, int]:
    """
    Load Tranco rankings from CSV file
    
    Args:
        filepath: Path to Tranco CSV (format: rank,domain)
        max_ranks: Maximum number of ranks to load
    
    Returns:
        Dict mapping domain -> rank
    """
    ranks = {}
    try:
        with open(filepath, 'r') as f:
            for i, line in enumerate(f):
                if i >= max_ranks:
                    break
                parts = line.strip().split(',')
                if len(parts) == 2:
                    rank, domain = parts
                    ranks[domain] = int(rank)
    except FileNotFoundError:
        print(f"Warning: Tranco file not found at {filepath}")
    
    return ranks


# Example usage
if __name__ == "__main__":
    extractor = DnsFeatureExtractor()
    
    # Test benign domain
    features, names = extractor.extract_features(
        "www.google.com",
        dns_stats={'queries_per_min': 2.0, 'unique_domains_per_min': 1.0}
    )
    print("Benign domain (google.com):")
    for name, value in zip(names, features):
        print(f"  {name}: {value}")
    
    print()
    
    # Test suspicious domain (DGA-like)
    features, names = extractor.extract_features(
        "xj9k2mq7p.tk",
        dns_stats={'queries_per_min': 45.0, 'unique_domains_per_min': 38.0}
    )
    print("Suspicious domain (DGA-like):")
    for name, value in zip(names, features):
        print(f"  {name}: {value}")
