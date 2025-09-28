from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple
import re

@dataclass
class DetectionResult:
    attack_type: str
    detected: bool
    matched_rules: List[str]
    confidence_percent: float
    evidence: Dict[str, Any]
    recommended_actions: List[str]

class AttackDetector:
    def __init__(self):
        self.rules = {
            'ransomware': self.detect_ransomware,
            'brute_force': self.detect_brute_force,
            'phishing': self.detect_phishing,
            'ddos': self.detect_ddos,
            'mitm': self.detect_mitm,
            'sql_injection': self.detect_sql_injection,
            'xss': self.detect_xss,
            'malware': self.detect_malware,
            'insider_threat': self.detect_insider_threat,
            'zero_day': self.detect_zero_day
        }

    def detect_ransomware(self, num_files_modified: int, time_window_seconds: int, 
                         entropy_score: float, ransom_note_found: bool) -> DetectionResult:
        """Detect ransomware based on file modifications and encryption patterns."""
        matched_rules = []
        evidence = {}
        
        # Calculate files per second
        files_per_sec = num_files_modified / max(1, time_window_seconds)
        evidence['files_per_second'] = round(files_per_sec, 2)
        evidence['entropy_score'] = entropy_score
        evidence['ransom_note_found'] = ransom_note_found
        
        # Rule 1: Rapid file modifications
        if files_per_sec > 0.833 or (num_files_modified >= 50 and time_window_seconds <= 60):
            matched_rules.append('rapid_modifications')
        
        # Rule 2: High entropy (suggests encryption)
        if entropy_score > 0.8:
            matched_rules.append('high_entropy')
        
        # Rule 3: Ransom note found (high severity)
        if ransom_note_found:
            matched_rules.append('ransom_note')
        
        # Calculate confidence
        weights = {'ransom_note': 2, 'rapid_modifications': 1, 'high_entropy': 1}
        total_weight = sum(weights.values())
        matched_weight = sum(weights.get(rule, 0) for rule in matched_rules)
        confidence = (matched_weight / total_weight) * 100
        
        # Determine if attack is detected
        detected = len(matched_rules) >= 2 or ransom_note_found
        
        recommended_actions = []
        if detected:
            recommended_actions = [
                "Isolate affected systems from the network",
                "Check for and terminate suspicious processes",
                "Restore from clean backups if available",
                "Report to security team immediately"
            ]
        
        return DetectionResult(
            attack_type="Ransomware",
            detected=detected,
            matched_rules=matched_rules,
            confidence_percent=round(confidence, 2),
            evidence=evidence,
            recommended_actions=recommended_actions
        )

    def detect_brute_force(self, failed_attempts: int, time_window: int, 
                          source_ips: str, account_locked: bool) -> DetectionResult:
        """Detect brute force login attempts."""
        matched_rules = []
        evidence = {}
        
        # Calculate attempts per minute
        attempts_per_min = failed_attempts / max(1, time_window)
        evidence['attempts_per_minute'] = round(attempts_per_min, 2)
        
        # Count unique IPs
        unique_ips = len(set(ip.strip() for ip in source_ips.split(',')) if source_ips else [])
        evidence['unique_ips'] = unique_ips
        evidence['account_locked'] = account_locked
        
        # Rule 1: High attempt rate
        if attempts_per_min > 5:
            matched_rules.append('high_attempt_rate')
        
        # Rule 2: Distributed attempts
        if unique_ips > 5:
            matched_rules.append('distributed_attempts')
        
        # Rule 3: Account lockout
        if account_locked and attempts_per_min > 5:
            matched_rules.append('lockout_confirmed')
        
        # Calculate confidence
        weights = {'high_attempt_rate': 1, 'distributed_attempts': 1, 'lockout_confirmed': 1.5}
        total_weight = sum(weights.values())
        matched_weight = sum(weights.get(rule, 0) for rule in matched_rules)
        confidence = (matched_weight / total_weight) * 100
        
        # Determine if attack is detected
        detected = ('high_attempt_rate' in matched_rules and 
                  ('distributed_attempts' in matched_rules or 'lockout_confirmed' in matched_rules)) or \
                  ('lockout_confirmed' in matched_rules)
        
        recommended_actions = []
        if detected:
            recommended_actions = [
                "Temporarily block suspicious IPs",
                "Enforce account lockout policy",
                "Enable multi-factor authentication",
                "Review failed login attempts for patterns"
            ]
        
        return DetectionResult(
            attack_type="Brute Force",
            detected=detected,
            matched_rules=matched_rules,
            confidence_percent=round(confidence, 2),
            evidence=evidence,
            recommended_actions=recommended_actions
        )

    # Add other detection methods with similar structure
    # For brevity, I'm including stubs for other detection methods
    
    def detect_phishing(self, email_content: str, sender_address: str, 
                       urls: str, suspicious_keywords: str) -> DetectionResult:
        """Detect phishing attempts in emails."""
        matched_rules = []
        evidence = {
            'sender_domain': sender_address.split('@')[-1] if '@' in sender_address else sender_address,
            'matched_keywords': [],
            'suspicious_urls': []
        }
        
        # Check for keywords
        keywords = [k.strip().lower() for k in suspicious_keywords.split(',') if k.strip()]
        common_phishing_terms = ['verify', 'password', 'urgent', 'account', 'suspended', 
                               'login', 'confirm', 'update', 'security', 'banking']
        
        all_keywords = set(keywords + common_phishing_terms)
        found_keywords = [kw for kw in all_keywords if kw in email_content.lower()]
        
        if found_keywords:
            evidence['matched_keywords'] = found_keywords
            matched_rules.append('keywords_present')
        
        # Check for domain mismatch
        sender_domain = sender_address.split('@')[-1].lower() if '@' in sender_address else ''
        url_domains = set()
        suspicious_urls = []
        
        for url in urls.split(','):
            url = url.strip()
            if not url:
                continue
                
            # Extract domain from URL (simplified)
            domain = url.split('//')[-1].split('/')[0].lower()
            url_domains.add(domain)
            
            # Check for suspicious URL patterns
            if any(term in url.lower() for term in ['login', 'verify', 'account', 'secure']):
                suspicious_urls.append(url)
        
        if url_domains and sender_domain and not any(sender_domain.endswith(d) for d in url_domains):
            matched_rules.append('domain_mismatch')
            evidence['url_domains'] = list(url_domains)
        
        if suspicious_urls:
            evidence['suspicious_urls'] = suspicious_urls
            matched_rules.append('suspicious_url')
        
        # Calculate confidence
        weights = {'keywords_present': 1, 'domain_mismatch': 1, 'suspicious_url': 1}
        total_weight = sum(weights.values())
        matched_weight = sum(weights.get(rule, 0) for rule in matched_rules)
        confidence = (matched_weight / total_weight) * 100
        
        # Determine if attack is detected
        detected = (len(matched_rules) >= 2 or 
                  (set(['domain_mismatch', 'suspicious_url']).issubset(set(matched_rules))))
        
        recommended_actions = []
        if detected:
            recommended_actions = [
                "Do not click on any links in the email",
                "Report the email as phishing",
                "Verify the sender through a trusted channel",
                "Update spam filters"
            ]
        
        return DetectionResult(
            attack_type="Phishing",
            detected=detected,
            matched_rules=matched_rules,
            confidence_percent=round(confidence, 2),
            evidence=evidence,
            recommended_actions=recommended_actions
        )

    def detect_ddos(self, request_rate: float, source_ips: int, 
                   traffic_spike: float, user_agents: int) -> DetectionResult:
        """Detect DDoS or traffic flood attacks."""
        matched_rules = []
        evidence = {
            'request_rate': request_rate,
            'unique_ips': source_ips,
            'traffic_spike_percent': traffic_spike,
            'unique_user_agents': user_agents
        }
        
        # Rule 1: High request rate
        if request_rate > 1000:
            matched_rules.append('high_rate')
        
        # Rule 2: Botnet pattern (many IPs, few UAs)
        if source_ips > 1000 and user_agents < 10:
            matched_rules.append('botnet_pattern')
        
        # Rule 3: Sudden traffic spike
        if traffic_spike > 100:
            matched_rules.append('sudden_spike')
        
        # Calculate confidence
        weights = {'high_rate': 1.5, 'botnet_pattern': 1, 'sudden_spike': 1}
        total_weight = sum(weights.values())
        matched_weight = sum(weights.get(rule, 0) for rule in matched_rules)
        confidence = (matched_weight / total_weight) * 100
        
        # Determine if attack is detected
        detected = (len(matched_rules) >= 2 or 
                  ('high_rate' in matched_rules and traffic_spike > 200))
        
        recommended_actions = []
        if detected:
            recommended_actions = [
                "Activate DDoS mitigation services",
                "Block suspicious IP ranges",
                "Rate limit traffic from suspicious sources",
                "Scale up infrastructure to handle the load"
            ]
        
        return DetectionResult(
            attack_type="DDoS/Traffic Flood",
            detected=detected,
            matched_rules=matched_rules,
            confidence_percent=round(confidence, 2),
            evidence=evidence,
            recommended_actions=recommended_actions
        )

    def detect_mitm(self, protocol: str, certificate_mismatch: bool,
                   unencrypted_traffic: bool, ssl_errors: int) -> DetectionResult:
        """Detect Man-in-the-Middle attacks."""
        matched_rules = []
        evidence = {
            'protocol': protocol,
            'certificate_mismatch': certificate_mismatch,
            'unencrypted_traffic': unencrypted_traffic,
            'ssl_errors': ssl_errors
        }
        
        # Rule 1: Plaintext traffic
        if protocol.lower() == 'http' or unencrypted_traffic:
            matched_rules.append('plaintext_seen')
        
        # Rule 2: Certificate issues (high severity)
        if certificate_mismatch:
            matched_rules.append('cert_issue')
        
        # Rule 3: SSL/TLS errors
        if ssl_errors > 5:
            matched_rules.append('ssl_errors')
        
        # Calculate confidence
        weights = {'plaintext_seen': 1, 'cert_issue': 2, 'ssl_errors': 1}
        total_weight = sum(weights.values())
        matched_weight = sum(weights.get(rule, 0) for rule in matched_rules)
        confidence = (matched_weight / total_weight) * 100
        
        # Determine if attack is detected
        detected = ('cert_issue' in matched_rules or 
                  ('plaintext_seen' in matched_rules and 'ssl_errors' in matched_rules))
        
        recommended_actions = []
        if detected:
            recommended_actions = [
                "Terminate suspicious connections",
                "Verify SSL/TLS certificates",
                "Enforce HTTPS for all communications",
                "Implement certificate pinning"
            ]
        
        return DetectionResult(
            attack_type="Man-in-the-Middle (MITM)",
            detected=detected,
            matched_rules=matched_rules,
            confidence_percent=round(confidence, 2),
            evidence=evidence,
            recommended_actions=recommended_actions
        )

    def detect_sql_injection(self, query_string: str, suspicious_patterns: str,
                           error_messages: str, query_time: int) -> DetectionResult:
        """Detect SQL injection attempts."""
        matched_rules = []
        evidence = {
            'query_time_ms': query_time,
            'matched_patterns': [],
            'error_messages': error_messages
        }
        
        # Check for suspicious patterns
        patterns = [p.strip() for p in suspicious_patterns.split(',') if p.strip()]
        common_patterns = ['or 1=1', 'union select', '--', ';--', '/*', '*/', 'xp_', 'exec ']
        all_patterns = set(patterns + common_patterns)
        
        found_patterns = [p for p in all_patterns if p.lower() in query_string.lower()]
        
        if found_patterns:
            evidence['matched_patterns'] = found_patterns
            matched_rules.append('pattern_match')
        
        # Check for database errors
        sql_errors = ['syntax error', 'unterminated string', 'sql error', 'type mismatch']
        error_found = any(err in error_messages.lower() for err in sql_errors)
        if error_found:
            matched_rules.append('db_errors')
        
        # Check for slow queries
        if query_time > 2000:  # 2 seconds threshold
            matched_rules.append('slow_query_anomaly')
        
        # Calculate confidence
        weights = {'pattern_match': 1, 'db_errors': 1, 'slow_query_anomaly': 1}
        total_weight = sum(weights.values())
        matched_weight = sum(weights.get(rule, 0) for rule in matched_rules)
        confidence = (matched_weight / total_weight) * 100
        
        # Determine if attack is detected
        detected = ('pattern_match' in matched_rules and 
                  ('db_errors' in matched_rules or 'slow_query_anomaly' in matched_rules))
        
        recommended_actions = []
        if detected:
            recommended_actions = [
                "Block the source IP address",
                "Review and sanitize all database queries",
                "Implement parameterized queries or prepared statements",
                "Update WAF rules to block similar patterns"
            ]
        
        return DetectionResult(
            attack_type="SQL Injection",
            detected=detected,
            matched_rules=matched_rules,
            confidence_percent=round(confidence, 2),
            evidence=evidence,
            recommended_actions=recommended_actions
        )

    def detect_xss(self, input_data: str, script_tags: int, 
                  event_handlers: int, url_parameters: str) -> DetectionResult:
        """Detect Cross-Site Scripting (XSS) attempts."""
        matched_rules = []
        evidence = {
            'script_tags_found': script_tags,
            'event_handlers_found': event_handlers,
            'suspicious_payloads': []
        }
        
        # Check for script tags and event handlers in input data
        script_patterns = [r'<script>', r'javascript:', r'onerror=', r'onload=', r'eval\(']
        found_patterns = []
        
        for pattern in script_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                found_patterns.append(pattern)
        
        if found_patterns:
            evidence['suspicious_payloads'] = found_patterns
            matched_rules.append('script_payload')
        
        # Check for script tags count
        if script_tags > 0:
            matched_rules.append('script_tags_found')
        
        # Check for event handlers
        if event_handlers > 0:
            matched_rules.append('event_handlers_present')
        
        # Calculate confidence
        weights = {'script_payload': 1, 'script_tags_found': 1, 'event_handlers_present': 1}
        total_weight = sum(weights.values())
        matched_weight = sum(weights.get(rule, 0) for rule in matched_rules)
        confidence = (matched_weight / total_weight) * 100
        
        # Determine if attack is detected
        detected = ('script_payload' in matched_rules or 
                  (set(['script_tags_found', 'event_handlers_present']).issubset(set(matched_rules))))
        
        recommended_actions = []
        if detected:
            recommended_actions = [
                "Sanitize all user inputs",
                "Implement Content Security Policy (CSP) headers",
                "Encode output to prevent script execution",
                "Use XSS protection libraries"
            ]
        
        return DetectionResult(
            attack_type="Cross-Site Scripting (XSS)",
            detected=detected,
            matched_rules=matched_rules,
            confidence_percent=round(confidence, 2),
            evidence=evidence,
            recommended_actions=recommended_actions
        )

    def detect_malware(self, file_hash: str, file_size: int, 
                      entropy_score: float, packed: bool) -> DetectionResult:
        """Detect potential malware based on file characteristics."""
        matched_rules = []
        evidence = {
            'file_size_bytes': file_size,
            'entropy_score': entropy_score,
            'packed': packed,
            'file_hash': file_hash
        }
        
        # In a real implementation, you would check against a hash blacklist here
        # For this example, we'll simulate a blacklist check
        known_malware_hashes = [
            'd41d8cd98f00b204e9800998ecf8427e',  # Example MD5 hash
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'  # Example SHA-256 hash
        ]
        
        # Rule 1: Hash in blacklist (immediate detection)
        if file_hash.lower() in known_malware_hashes:
            matched_rules.append('hash_blacklist')
        
        # Rule 2: High entropy and packed
        if packed and entropy_score > 0.85:
            matched_rules.append('packed_high_entropy')
        
        # Rule 3: Suspicious file size
        if file_size < 1024 or file_size > 500 * 1024 * 1024:  # <1KB or >500MB
            matched_rules.append('suspicious_size')
        
        # Calculate confidence
        weights = {'hash_blacklist': 2, 'packed_high_entropy': 1, 'suspicious_size': 1}
        total_weight = sum(weights.values())
        matched_weight = sum(weights.get(rule, 0) for rule in matched_rules)
        confidence = (matched_weight / total_weight) * 100
        
        # Determine if malware is detected
        detected = ('hash_blacklist' in matched_rules or 
                  len(set(matched_rules) - {'hash_blacklist'}) >= 2)
        
        recommended_actions = []
        if detected:
            recommended_actions = [
                "Quarantine the file immediately",
                "Scan the system with updated antivirus",
                "Check for signs of compromise",
                "Update security signatures"
            ]
        
        return DetectionResult(
            attack_type="Malware",
            detected=detected,
            matched_rules=matched_rules,
            confidence_percent=round(confidence, 2),
            evidence=evidence,
            recommended_actions=recommended_actions
        )

    def detect_insider_threat(self, user_id: str, data_volume: float, 
                            unusual_time: bool, sensitive_files: int) -> DetectionResult:
        """Detect potential insider threats."""
        matched_rules = []
        evidence = {
            'user_id': user_id,
            'data_volume_mb': data_volume,
            'unusual_time': unusual_time,
            'sensitive_files_accessed': sensitive_files
        }
        
        # Rule 1: Large data transfer
        if data_volume > 500:  # MB
            matched_rules.append('large_transfer')
        
        # Rule 2: Unusual access time
        if unusual_time:
            matched_rules.append('offhours_access')
        
        # Rule 3: Access to sensitive files
        if sensitive_files >= 10:
            matched_rules.append('sensitive_accesses')
        
        # Calculate confidence
        weights = {'large_transfer': 1, 'offhours_access': 1, 'sensitive_accesses': 1}
        total_weight = sum(weights.values())
        matched_weight = sum(weights.get(rule, 0) for rule in matched_rules)
        confidence = (matched_weight / total_weight) * 100
        
        # Determine if threat is detected
        detected = (len(matched_rules) >= 2 or 
                  (set(['large_transfer', 'sensitive_accesses']).issubset(set(matched_rules))))
        
        recommended_actions = []
        if detected:
            recommended_actions = [
                "Review user activity logs for suspicious behavior",
                "Temporarily restrict user access if necessary",
                "Initiate a security investigation",
                "Consult with HR and legal teams"
            ]
        
        return DetectionResult(
            attack_type="Insider Threat",
            detected=detected,
            matched_rules=matched_rules,
            confidence_percent=round(confidence, 2),
            evidence=evidence,
            recommended_actions=recommended_actions
        )

    def detect_zero_day(self, behavior_patterns: str, system_calls: int, 
                       memory_usage: float, anomaly_score: float) -> DetectionResult:
        """Detect zero-day or novel anomalies."""
        matched_rules = []
        evidence = {
            'system_calls': system_calls,
            'memory_usage_mb': memory_usage,
            'anomaly_score': anomaly_score,
            'behavior_patterns': [p.strip() for p in behavior_patterns.split(',') if p.strip()]
        }
        
        # Rule 1: High anomaly score
        if anomaly_score >= 80:
            matched_rules.append('high_anomaly')
        
        # Rule 2: System call spike (simplified)
        baseline_syscalls = 1000  # This would be dynamic in a real system
        if system_calls > baseline_syscalls * 3:
            matched_rules.append('syscall_spike')
        
        # Rule 3: Memory spike (simplified)
        baseline_memory = 200  # MB - would be dynamic in a real system
        if memory_usage > baseline_memory * 1.8:  # 80% over baseline
            matched_rules.append('memory_spike')
        
        # Rule 4: New behavior patterns
        known_patterns = {'normal_behavior1', 'normal_behavior2'}  # Would be more comprehensive
        new_patterns = [p for p in evidence['behavior_patterns'] if p not in known_patterns]
        if new_patterns:
            matched_rules.append('new_pattern')
            evidence['new_behavior_patterns'] = new_patterns
        
        # Calculate confidence
        weights = {'high_anomaly': 2, 'syscall_spike': 1, 'memory_spike': 1, 'new_pattern': 1}
        total_weight = sum(weights.values())
        matched_weight = sum(weights.get(rule, 0) for rule in matched_rules)
        confidence = (matched_weight / total_weight) * 100
        
        # Determine if anomaly is detected
        detected = ('high_anomaly' in matched_rules or 
                  len(set(matched_rules) - {'high_anomaly'}) >= 2)
        
        recommended_actions = []
        if detected:
            recommended_actions = [
                "Isolate the affected system",
                "Collect and preserve forensic evidence",
                "Update intrusion detection signatures",
                "Investigate the root cause"
            ]
        
        return DetectionResult(
            attack_type="Zero-Day/Novel Anomaly",
            detected=detected,
            matched_rules=matched_rules,
            confidence_percent=round(confidence, 2),
            evidence=evidence,
            recommended_actions=recommended_actions
        )

    def detect(self, attack_type: str, **kwargs) -> DetectionResult:
        """Main detection method that routes to the appropriate detection function."""
        if attack_type not in self.rules:
            raise ValueError(f"Unknown attack type: {attack_type}")
        
        return self.rules[attack_type](**kwargs)
