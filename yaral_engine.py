"""
YARAL (Yet Another Rule Alert Language) Engine
A simple, JSON-based rule engine for security event detection in BlackStar SIEM
"""

import json
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import os
import tempfile
import subprocess
import shutil
import logging

# Set up logging
logger = logging.getLogger(__name__)


class YARALRule:
    """Represents a single YARAL rule"""
    
    def __init__(self, rule_dict: Dict[str, Any]):
        self.name = rule_dict.get('name', 'Unnamed Rule')
        self.description = rule_dict.get('description', '')
        self.severity = rule_dict.get('severity', 'medium')
        self.enabled = rule_dict.get('enabled', True)
        self.conditions = rule_dict.get('conditions', {})
        self.metadata = rule_dict.get('metadata', {})
        self.created_at = rule_dict.get('created_at', datetime.now().isoformat())
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary"""
        return {
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'enabled': self.enabled,
            'conditions': self.conditions,
            'metadata': self.metadata,
            'created_at': self.created_at
        }
    
    def match_event(self, event: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Check if an event matches this rule.
        Returns (matched: bool, reasons: List[str])
        """
        if not self.enabled:
            return False, []
        
        matches = []
        reasons = []
        
        # Process conditions
        for field, condition in self.conditions.items():
            if self._check_condition(event, field, condition):
                matches.append(field)
                reasons.append(f"Matched condition on field '{field}': {condition}")
        
        # All conditions must match for the rule to trigger
        all_matched = len(matches) == len(self.conditions) and len(matches) > 0
        
        return all_matched, reasons if all_matched else []
    
    def _check_condition(self, event: Dict[str, Any], field: str, condition: Any) -> bool:
        """
        Check a single condition against an event field.
        Supports various condition types:
        - Simple equality: {"field": "value"}
        - Contains: {"field": {"contains": "substring"}}
        - Regex: {"field": {"regex": "pattern"}}
        - In list: {"field": {"in": ["val1", "val2"]}}
        - Greater than: {"field": {"gt": value}}
        - Less than: {"field": {"lt": value}}
        - Equals: {"field": {"eq": value}}
        - Not equals: {"field": {"ne": value}}
        """
        # Get the event value for this field
        event_value = self._get_nested_value(event, field)
        
        if event_value is None:
            return False
        
        # Simple string/value equality
        if isinstance(condition, (str, int, float, bool)):
            return str(event_value).lower() == str(condition).lower()
        
        # Complex conditions
        if isinstance(condition, dict):
            if 'contains' in condition:
                return str(condition['contains']).lower() in str(event_value).lower()
            
            if 'regex' in condition:
                try:
                    pattern = re.compile(condition['regex'], re.IGNORECASE)
                    return bool(pattern.search(str(event_value)))
                except re.error:
                    return False
            
            if 'in' in condition:
                return str(event_value) in [str(v) for v in condition['in']]
            
            if 'eq' in condition:
                return str(event_value).lower() == str(condition['eq']).lower()
            
            if 'ne' in condition:
                return str(event_value).lower() != str(condition['ne']).lower()
            
            if 'gt' in condition:
                try:
                    return float(event_value) > float(condition['gt'])
                except (ValueError, TypeError):
                    return False
            
            if 'lt' in condition:
                try:
                    return float(event_value) < float(condition['lt'])
                except (ValueError, TypeError):
                    return False
        
        return False
    
    def _get_nested_value(self, data: Dict[str, Any], field: str) -> Any:
        """Get a nested field value from event data using dot notation or direct key"""
        # First try direct key access (for fields like 'event.action' that are actual keys)
        if field in data:
            return data[field]
        
        # Then try nested access
        keys = field.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
                if value is None:
                    return None
            else:
                return None
        
        return value


class YARALEngine:
    """Engine for managing and executing YARAL rules"""
    
    def __init__(self):
        self.rules: List[YARALRule] = []
    
    def add_rule(self, rule_dict: Dict[str, Any]) -> bool:
        """Add a new rule to the engine"""
        try:
            rule = YARALRule(rule_dict)
            self.rules.append(rule)
            return True
        except Exception as e:
            logger.error(f"Error adding rule: {e}")
            return False
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a rule by name"""
        initial_count = len(self.rules)
        self.rules = [r for r in self.rules if r.name != rule_name]
        return len(self.rules) < initial_count
    
    def get_rule(self, rule_name: str) -> Optional[YARALRule]:
        """Get a rule by name"""
        for rule in self.rules:
            if rule.name == rule_name:
                return rule
        return None
    
    def scan_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan an event against all enabled rules.
        Returns list of matches with details.
        """
        matches = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            matched, reasons = rule.match_event(event)
            
            if matched:
                matches.append({
                    'rule_name': rule.name,
                    'description': rule.description,
                    'severity': rule.severity,
                    'reasons': reasons,
                    'event': event,
                    'timestamp': datetime.now()
                })
        
        return matches
    
    def export_rules(self) -> str:
        """Export all rules as JSON string"""
        rules_data = [rule.to_dict() for rule in self.rules]
        return json.dumps(rules_data, indent=2)
    
    def import_rules(self, rules_json: str) -> Tuple[int, List[str]]:
        """
        Import rules from JSON string.
        Returns (count_imported, errors)
        """
        errors = []
        count = 0
        
        try:
            rules_data = json.loads(rules_json)
            
            if not isinstance(rules_data, list):
                rules_data = [rules_data]
            
            for rule_dict in rules_data:
                if self.add_rule(rule_dict):
                    count += 1
                else:
                    errors.append(f"Failed to import rule: {rule_dict.get('name', 'Unknown')}")
        
        except json.JSONDecodeError as e:
            errors.append(f"JSON decode error: {str(e)}")
        except Exception as e:
            errors.append(f"Import error: {str(e)}")
        
        return count, errors
    
    def import_from_git(self, git_url: str, branch: str = 'main') -> Tuple[int, List[str]]:
        """
        Import YARAL rules from a Git repository.
        Clones the repo and imports all .yaral files.
        Returns (count_imported, errors)
        """
        errors = []
        count = 0
        temp_dir = None
        
        try:
            # Validate Git URL format to prevent command injection
            if not git_url or not isinstance(git_url, str):
                errors.append("Invalid Git URL provided")
                return 0, errors
            
            # Basic validation - ensure it looks like a valid URL
            # Allow http://, https://, git://, and file:// protocols
            valid_protocols = ['http://', 'https://', 'git://', 'file://']
            if not any(git_url.startswith(proto) for proto in valid_protocols):
                # Also allow local paths for testing
                if not os.path.exists(git_url):
                    errors.append("Git URL must start with http://, https://, git://, or file://")
                    return 0, errors
            
            # Validate branch name to prevent injection
            if not branch or not isinstance(branch, str) or not branch.replace('-', '').replace('_', '').replace('/', '').isalnum():
                errors.append("Invalid branch name")
                return 0, errors
            
            # Create temporary directory for cloning
            temp_dir = tempfile.mkdtemp(prefix='yaral_import_')
            
            # Clone the repository with proper escaping
            try:
                subprocess.run(
                    ['git', 'clone', '--depth', '1', '--branch', branch, '--', git_url, temp_dir],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
            except subprocess.CalledProcessError as e:
                errors.append(f"Git clone failed: {e.stderr}")
                return 0, errors
            except subprocess.TimeoutExpired:
                errors.append("Git clone timeout after 60 seconds")
                return 0, errors
            
            # Find all .yaral files
            yaral_files = []
            for root, dirs, files in os.walk(temp_dir):
                # Skip .git directory
                if '.git' in root:
                    continue
                for file in files:
                    if file.endswith('.yaral'):
                        yaral_files.append(os.path.join(root, file))
            
            if not yaral_files:
                errors.append("No .yaral files found in repository")
                return 0, errors
            
            # Import each file
            for yaral_file in yaral_files:
                try:
                    with open(yaral_file, 'r') as f:
                        content = f.read()
                        imported, file_errors = self.import_rules(content)
                        count += imported
                        errors.extend(file_errors)
                except Exception as e:
                    errors.append(f"Error reading {os.path.basename(yaral_file)}: {str(e)}")
        
        except Exception as e:
            errors.append(f"Unexpected error during Git import: {str(e)}")
        
        finally:
            # Cleanup temp directory
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except Exception:
                    pass
        
        return count, errors
    
    def get_all_rules(self) -> List[Dict[str, Any]]:
        """Get all rules as dictionaries"""
        return [rule.to_dict() for rule in self.rules]


def get_sample_yaral_rules() -> List[Dict[str, Any]]:
    """Return sample YARAL rules for common security threats"""
    return [
        {
            'name': 'SSH_Brute_Force_Detection',
            'description': 'Detects potential SSH brute force attempts',
            'severity': 'high',
            'enabled': True,
            'conditions': {
                'event.action': {'in': ['ssh_login', 'failed_login']},
                'event.outcome': 'failure',
                'user.name': {'in': ['root', 'admin', 'administrator']}
            },
            'metadata': {
                'author': 'BlackStar SIEM',
                'created': '2024-01-01',
                'mitre_attack': 'T1110.001'
            }
        },
        {
            'name': 'Port_Scan_Activity',
            'description': 'Detects port scanning activity',
            'severity': 'medium',
            'enabled': True,
            'conditions': {
                'event.action': {'in': ['port_scan', 'nmap_scan']},
                'event.category': 'network'
            },
            'metadata': {
                'author': 'BlackStar SIEM',
                'created': '2024-01-01',
                'mitre_attack': 'T1046'
            }
        },
        {
            'name': 'Critical_Event_Alert',
            'description': 'Alert on any critical severity event',
            'severity': 'critical',
            'enabled': True,
            'conditions': {
                'event.severity': 'critical'
            },
            'metadata': {
                'author': 'BlackStar SIEM',
                'created': '2024-01-01'
            }
        },
        {
            'name': 'Failed_Authentication_Multiple_Users',
            'description': 'Detects failed authentication attempts',
            'severity': 'high',
            'enabled': True,
            'conditions': {
                'event.category': 'authentication',
                'event.outcome': 'failure'
            },
            'metadata': {
                'author': 'BlackStar SIEM',
                'created': '2024-01-01',
                'mitre_attack': 'T1110'
            }
        },
        {
            'name': 'Suspicious_File_Access',
            'description': 'Detects access to sensitive files',
            'severity': 'medium',
            'enabled': True,
            'conditions': {
                'event.action': 'file_access',
                'event.category': 'file'
            },
            'metadata': {
                'author': 'BlackStar SIEM',
                'created': '2024-01-01',
                'mitre_attack': 'T1005'
            }
        }
    ]


def validate_yaral_rule(rule_dict: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate a YARAL rule structure.
    Returns (is_valid, errors)
    """
    errors = []
    
    # Required fields
    if 'name' not in rule_dict or not rule_dict['name']:
        errors.append("Rule must have a 'name' field")
    
    if 'conditions' not in rule_dict or not rule_dict['conditions']:
        errors.append("Rule must have 'conditions' field with at least one condition")
    
    # Validate severity if present
    valid_severities = ['low', 'medium', 'high', 'critical']
    if 'severity' in rule_dict and rule_dict['severity'] not in valid_severities:
        errors.append(f"Severity must be one of: {', '.join(valid_severities)}")
    
    # Validate conditions structure
    if 'conditions' in rule_dict and isinstance(rule_dict['conditions'], dict):
        for field, condition in rule_dict['conditions'].items():
            if not isinstance(field, str) or not field:
                errors.append(f"Invalid field name: {field}")
    
    return len(errors) == 0, errors
