"""
SilentSeal - PII Detection Accuracy Modes
Strict / Balanced / Triage sensitivity modes and custom regex/rule editor.
"""

import os
import re
import json
from typing import Dict, List, Any
from datetime import datetime
from enum import Enum


class DetectionMode(str, Enum):
    STRICT = "strict"
    BALANCED = "balanced"
    TRIAGE = "triage"


MODE_CONFIGS = {
    DetectionMode.STRICT: {
        'min_confidence': 0.3, 'enable_fuzzy': True,
        'description': 'Maximum sensitivity — flags every potential match'
    },
    DetectionMode.BALANCED: {
        'min_confidence': 0.6, 'enable_fuzzy': False,
        'description': 'Optimized precision/recall balance'
    },
    DetectionMode.TRIAGE: {
        'min_confidence': 0.85, 'enable_fuzzy': False,
        'description': 'Only high-confidence detections'
    }
}


class DetectionRule:
    def __init__(self, name, entity_type, pattern, confidence=0.8,
                 description='', is_custom=False, enabled=True):
        self.name = name
        self.entity_type = entity_type
        self.pattern = pattern
        self.confidence = confidence
        self.description = description
        self.is_custom = is_custom
        self.enabled = enabled
        self._compiled = None

    def compile(self):
        if self._compiled is None:
            try:
                self._compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error:
                self._compiled = None
        return self._compiled

    def match(self, text):
        compiled = self.compile()
        if not compiled:
            return []
        return [{'text': m.group().strip(), 'start': m.start(), 'end': m.end(),
                 'type': self.entity_type, 'confidence': self.confidence,
                 'rule_name': self.name, 'is_custom': self.is_custom}
                for m in compiled.finditer(text)]

    def to_dict(self):
        return {'name': self.name, 'entity_type': self.entity_type,
                'pattern': self.pattern, 'confidence': self.confidence,
                'description': self.description, 'is_custom': self.is_custom,
                'enabled': self.enabled}

    @classmethod
    def from_dict(cls, d):
        return cls(d['name'], d['entity_type'], d['pattern'],
                   d.get('confidence', 0.8), d.get('description', ''),
                   d.get('is_custom', True), d.get('enabled', True))


BUILTIN_RULES = [
    DetectionRule('aadhaar', 'AADHAAR', r'\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b', 0.9, 'Aadhaar number'),
    DetectionRule('pan', 'PAN', r'\b[A-Z]{5}\d{4}[A-Z]\b', 0.95, 'PAN card'),
    DetectionRule('phone_in', 'PHONE', r'\b(?:\+91[\-\s]?)?[6-9]\d{9}\b', 0.85, 'Indian phone'),
    DetectionRule('email', 'EMAIL', r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', 0.95),
    DetectionRule('credit_card', 'CREDIT_CARD', r'\b(?:\d{4}[\s\-]?){3}\d{4}\b', 0.8),
    DetectionRule('ifsc', 'IFSC', r'\b[A-Z]{4}0[A-Z0-9]{6}\b', 0.9, 'Bank IFSC code'),
    DetectionRule('passport', 'PASSPORT', r'\b[A-Z]\d{7}\b', 0.7, 'Passport number'),
    DetectionRule('voter_id', 'VOTER_ID', r'\b[A-Z]{3}\d{7}\b', 0.75),
    DetectionRule('dob', 'DOB', r'\b\d{1,2}[\\/\-\.]\d{1,2}[\\/\-\.]\d{2,4}\b', 0.6),
    DetectionRule('ip', 'IP_ADDRESS', r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 0.7),
    DetectionRule('ssn', 'SSN', r'\b\d{3}[\-\s]?\d{2}[\-\s]?\d{4}\b', 0.75),
    DetectionRule('gst', 'GST', r'\b\d{2}[A-Z]{5}\d{4}[A-Z]\d[Z][A-Z0-9]\b', 0.95, 'GST number'),
]


class DetectionModeManager:
    """Manages PII detection sensitivity modes and custom rules."""

    def __init__(self, rulesets_dir=None):
        if rulesets_dir is None:
            rulesets_dir = os.path.join(os.path.dirname(__file__), '..', 'rulesets')
        os.makedirs(rulesets_dir, exist_ok=True)
        self.rulesets_dir = rulesets_dir
        self.current_mode = DetectionMode.BALANCED
        self.custom_rules = []
        self._load_custom_rules()

    def _load_custom_rules(self):
        path = os.path.join(self.rulesets_dir, 'custom_rules.json')
        if os.path.exists(path):
            try:
                with open(path) as f:
                    self.custom_rules = [DetectionRule.from_dict(r) for r in json.load(f)]
            except Exception:
                self.custom_rules = []

    def _save_custom_rules(self):
        path = os.path.join(self.rulesets_dir, 'custom_rules.json')
        with open(path, 'w') as f:
            json.dump([r.to_dict() for r in self.custom_rules], f, indent=2)

    def set_mode(self, mode):
        try:
            self.current_mode = DetectionMode(mode)
        except ValueError:
            return {'error': f'Invalid mode: {mode}'}
        return {'mode': self.current_mode.value, 'config': MODE_CONFIGS[self.current_mode],
                'active_rules': len(self.get_active_rules())}

    def get_mode(self):
        cfg = MODE_CONFIGS[self.current_mode]
        return {'mode': self.current_mode.value, 'config': cfg,
                'custom_rules_count': len(self.custom_rules),
                'total_active_rules': len(self.get_active_rules()),
                'available_modes': {m.value: MODE_CONFIGS[m]['description'] for m in DetectionMode}}

    def get_active_rules(self):
        min_conf = MODE_CONFIGS[self.current_mode]['min_confidence']
        return [r for r in BUILTIN_RULES + self.custom_rules
                if r.enabled and r.confidence >= min_conf]

    def add_custom_rule(self, name, entity_type, pattern, confidence=0.8, description=''):
        try:
            re.compile(pattern)
        except re.error as e:
            return {'error': f'Invalid regex: {e}'}
        if any(r.name == name for r in self.custom_rules):
            return {'error': f'Rule "{name}" already exists'}
        rule = DetectionRule(name, entity_type.upper(), pattern,
                             min(max(confidence, 0.0), 1.0), description, True)
        self.custom_rules.append(rule)
        self._save_custom_rules()
        return {'status': 'created', 'rule': rule.to_dict()}

    def remove_rule(self, name):
        before = len(self.custom_rules)
        self.custom_rules = [r for r in self.custom_rules if r.name != name]
        if len(self.custom_rules) == before:
            return {'error': f'Rule "{name}" not found'}
        self._save_custom_rules()
        return {'status': 'removed', 'name': name}

    def list_rules(self, include_builtin=True):
        result = {'custom_rules': [r.to_dict() for r in self.custom_rules]}
        if include_builtin:
            result['builtin_rules'] = [r.to_dict() for r in BUILTIN_RULES]
        return result

    def apply_rules(self, text):
        all_matches = []
        for rule in self.get_active_rules():
            all_matches.extend(rule.match(text))
        all_matches.sort(key=lambda x: (-x['confidence'], x['start']))
        deduped, used = [], []
        for m in all_matches:
            if not any(m['start'] < e and m['end'] > s for s, e in used):
                deduped.append(m)
                used.append((m['start'], m['end']))
        return deduped

    def save_ruleset(self, name, description=''):
        data = {'name': name, 'description': description,
                'mode': self.current_mode.value,
                'created_at': datetime.now().isoformat(),
                'rules': [r.to_dict() for r in self.custom_rules]}
        path = os.path.join(self.rulesets_dir, f'{name}.json')
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        return {'status': 'saved', 'name': name, 'rules_count': len(self.custom_rules)}

    def load_ruleset(self, name):
        path = os.path.join(self.rulesets_dir, f'{name}.json')
        if not os.path.exists(path):
            return {'error': f'Ruleset "{name}" not found'}
        with open(path) as f:
            data = json.load(f)
        self.custom_rules = [DetectionRule.from_dict(r) for r in data.get('rules', [])]
        if 'mode' in data:
            try:
                self.current_mode = DetectionMode(data['mode'])
            except ValueError:
                pass
        self._save_custom_rules()
        return {'status': 'loaded', 'name': name, 'rules_count': len(self.custom_rules)}

    def list_rulesets(self):
        rulesets = []
        for fn in os.listdir(self.rulesets_dir):
            if fn.endswith('.json') and fn != 'custom_rules.json':
                try:
                    with open(os.path.join(self.rulesets_dir, fn)) as f:
                        d = json.load(f)
                    rulesets.append({'name': d.get('name', fn[:-5]),
                                    'description': d.get('description', ''),
                                    'rules_count': len(d.get('rules', []))})
                except Exception:
                    pass
        return rulesets

    def test_rule(self, pattern, sample_text):
        try:
            c = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            matches = [{'text': m.group(), 'start': m.start(), 'end': m.end()}
                       for m in c.finditer(sample_text)]
            return {'valid': True, 'matches_count': len(matches), 'matches': matches[:20]}
        except re.error as e:
            return {'valid': False, 'error': str(e)}


_detection_manager = None

def get_detection_mode_manager():
    global _detection_manager
    if _detection_manager is None:
        _detection_manager = DetectionModeManager()
    return _detection_manager
