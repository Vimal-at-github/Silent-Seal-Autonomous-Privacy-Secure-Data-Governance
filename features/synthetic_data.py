"""
SilentSeal - Synthetic Data Generator
Novel feature: Generates realistic fake data to replace sensitive information
"""

import random
import string
from typing import Dict, Any, Optional
from datetime import datetime, timedelta, timezone


class SyntheticDataGenerator:
    """
    Generates realistic synthetic data to replace sensitive information
    
    Instead of black boxes [REDACTED], replace with believable fake data
    that maintains document utility while ensuring privacy.
    
    This is a NOVEL FEATURE that transforms unusable redacted documents
    into privacy-preserving, analytically useful documents.
    """
    
    # Indian first names by gender
    INDIAN_FIRST_NAMES = {
        "male": [
            "Rahul", "Amit", "Vikram", "Arjun", "Sanjay", "Rajesh", "Anil", "Suresh",
            "Karthik", "Venkat", "Prakash", "Mohan", "Krishna", "Ravi", "Ajay",
            "Deepak", "Manoj", "Vijay", "Sunil", "Ashok", "Ramesh", "Ganesh",
            "Arun", "Naveen", "Harish", "Girish", "Srinivas", "Mahesh", "Dinesh",
            "Satish", "Nikhil", "Varun", "Rohan", "Kunal", "Ankur", "Gaurav"
        ],
        "female": [
            "Priya", "Anita", "Lakshmi", "Sunita", "Kavitha", "Divya", "Sneha",
            "Pooja", "Meera", "Anjali", "Ritu", "Neha", "Swati", "Shalini",
            "Deepika", "Rekha", "Padma", "Geetha", "Radha", "Uma", "Jyoti",
            "Asha", "Bhavana", "Chitra", "Durga", "Esha", "Hema", "Ira",
            "Jaya", "Kamala", "Lata", "Maya", "Nandini", "Pallavi", "Rashmi"
        ]
    }
    
    # Indian last names
    INDIAN_LAST_NAMES = [
        "Sharma", "Verma", "Singh", "Kumar", "Gupta", "Patel", "Shah",
        "Reddy", "Rao", "Naidu", "Iyer", "Iyengar", "Nair", "Menon",
        "Pillai", "Mukherjee", "Banerjee", "Chatterjee", "Das", "Sen",
        "Kapoor", "Malhotra", "Khanna", "Chopra", "Joshi", "Kulkarni",
        "Deshmukh", "Patil", "Jadhav", "More", "Shinde", "Pawar"
    ]
    
    # Indian cities
    INDIAN_CITIES = [
        "Mumbai", "Delhi", "Bangalore", "Chennai", "Hyderabad", "Kolkata",
        "Pune", "Ahmedabad", "Jaipur", "Lucknow", "Kochi", "Chandigarh",
        "Coimbatore", "Indore", "Nagpur", "Vadodara", "Bhopal", "Patna",
        "Visakhapatnam", "Thiruvananthapuram", "Mysore", "Mangalore"
    ]
    
    # Indian states
    INDIAN_STATES = [
        "Maharashtra", "Karnataka", "Tamil Nadu", "Andhra Pradesh", "Telangana",
        "Kerala", "Gujarat", "Rajasthan", "Uttar Pradesh", "West Bengal",
        "Punjab", "Haryana", "Bihar", "Madhya Pradesh", "Odisha"
    ]
    
    # Email domains
    EMAIL_DOMAINS = [
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
        "rediffmail.com", "protonmail.com", "icloud.com"
    ]
    
    # Organization suffixes
    ORG_SUFFIXES = [
        "Technologies", "Solutions", "Systems", "Enterprises", "Industries",
        "Consulting", "Services", "Limited", "Pvt Ltd", "Corporation"
    ]
    
    def __init__(self, seed: int = None):
        """Initialize with optional seed for reproducibility"""
        if seed:
            random.seed(seed)
    
    def generate(self, entity_type: str, context: Dict = None) -> str:
        """
        Generate synthetic data for a given entity type
        
        Args:
            entity_type: Type of entity (PAN, AADHAAR, EMAIL, etc.)
            context: Optional context for more realistic generation
            
        Returns:
            Synthetic replacement value
        """
        context = context or {}
        
        generators = {
            "PAN": self._generate_pan,
            "AADHAAR": self._generate_aadhaar,
            "EMAIL": self._generate_email,
            "PHONE": self._generate_phone,
            "PERSON_NAME": self._generate_name,
            "LOCATION": self._generate_location,
            "ORGANIZATION": self._generate_organization,
            "DATE_OF_BIRTH": self._generate_dob,
            "CREDIT_CARD": self._generate_credit_card,
            "IFSC": self._generate_ifsc,
            "PASSPORT": self._generate_passport,
            "DRIVING_LICENSE": self._generate_driving_license,
            "BANK_ACCOUNT": self._generate_bank_account,
            "IP_ADDRESS": self._generate_ip_address
        }
        
        generator = generators.get(entity_type, self._generate_generic)
        return generator(context)
    
    def _generate_pan(self, context: Dict) -> str:
        """Generate valid-format PAN number"""
        # Format: AAAAA0000A
        letters = ''.join(random.choices(string.ascii_uppercase, k=5))
        # Fourth letter indicates holder type
        holder_types = ['A', 'B', 'C', 'F', 'G', 'H', 'L', 'J', 'P', 'T']
        letters = letters[:3] + random.choice(holder_types) + letters[4]
        numbers = ''.join(random.choices(string.digits, k=4))
        check = random.choice(string.ascii_uppercase)
        return f"{letters}{numbers}{check}"
    
    def _generate_aadhaar(self, context: Dict) -> str:
        """Generate valid-format Aadhaar number"""
        # First digit: 2-9, then 11 more digits
        first = str(random.randint(2, 9))
        rest = ''.join(random.choices(string.digits, k=11))
        aadhaar = first + rest
        # Format with spaces
        return f"{aadhaar[:4]} {aadhaar[4:8]} {aadhaar[8:]}"
    
    def _generate_email(self, context: Dict) -> str:
        """Generate realistic email address"""
        name = context.get("name", self._generate_name({})).lower().replace(" ", ".")
        # Add random suffix
        suffix = random.choice(["", str(random.randint(1, 99)), str(random.randint(1990, 2005))])
        domain = random.choice(self.EMAIL_DOMAINS)
        return f"{name}{suffix}@{domain}"
    
    def _generate_phone(self, context: Dict) -> str:
        """Generate valid Indian phone number"""
        # Indian mobile: starts with 6-9
        first = str(random.randint(6, 9))
        rest = ''.join(random.choices(string.digits, k=9))
        return f"+91 {first}{rest[:4]} {rest[4:]}"
    
    def _generate_name(self, context: Dict) -> str:
        """Generate realistic Indian name"""
        gender = context.get("gender", random.choice(["male", "female"]))
        first_name = random.choice(self.INDIAN_FIRST_NAMES[gender])
        last_name = random.choice(self.INDIAN_LAST_NAMES)
        
        # Sometimes add middle initial
        if random.random() < 0.3:
            middle = random.choice(string.ascii_uppercase) + "."
            return f"{first_name} {middle} {last_name}"
        
        return f"{first_name} {last_name}"
    
    def _generate_location(self, context: Dict) -> str:
        """Generate Indian location"""
        city = random.choice(self.INDIAN_CITIES)
        state = random.choice(self.INDIAN_STATES)
        
        # Different formats
        formats = [
            city,
            f"{city}, {state}",
            f"{city}, {state}, India"
        ]
        return random.choice(formats)
    
    def _generate_organization(self, context: Dict) -> str:
        """Generate realistic organization name"""
        prefixes = ["Tech", "Global", "Prime", "Nova", "Alpha", "Apex", "Elite"]
        suffix = random.choice(self.ORG_SUFFIXES)
        
        if random.random() < 0.5:
            return f"{random.choice(prefixes)} {suffix}"
        else:
            # Use name-based org
            name = random.choice(self.INDIAN_LAST_NAMES)
            return f"{name} {suffix}"
    
    def _generate_dob(self, context: Dict) -> str:
        """Generate realistic date of birth"""
        # Generate age between 18 and 80
        min_age = context.get("min_age", 18)
        max_age = context.get("max_age", 70)
        
        age = random.randint(min_age, max_age)
        today = datetime.now(timezone.utc)
        birth_year = today.year - age
        birth_month = random.randint(1, 12)
        birth_day = random.randint(1, 28)  # Safe for all months
        
        # Random format
        formats = [
            f"{birth_day:02d}/{birth_month:02d}/{birth_year}",
            f"{birth_day:02d}-{birth_month:02d}-{birth_year}",
            f"{birth_year}-{birth_month:02d}-{birth_day:02d}"
        ]
        return random.choice(formats)
    
    def _generate_credit_card(self, context: Dict) -> str:
        """Generate valid-format credit card number (Luhn compliant)"""
        # Visa prefix
        prefix = "4"
        number = prefix + ''.join(random.choices(string.digits, k=14))
        
        # Calculate Luhn checksum
        digits = [int(d) for d in number]
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        
        total = sum(odd_digits)
        for d in even_digits:
            d = d * 2
            if d > 9:
                d = d - 9
            total += d
        
        check = (10 - (total % 10)) % 10
        full_number = number + str(check)
        
        # Format with spaces
        return f"{full_number[:4]} {full_number[4:8]} {full_number[8:12]} {full_number[12:]}"
    
    def _generate_ifsc(self, context: Dict) -> str:
        """Generate valid-format IFSC code"""
        # Format: AAAA0NNNNNN
        bank_codes = ["SBIN", "HDFC", "ICIC", "AXIS", "UTIB", "KKBK", "PUNB"]
        bank = random.choice(bank_codes)
        branch = ''.join(random.choices(string.digits + string.ascii_uppercase, k=6))
        return f"{bank}0{branch}"
    
    def _generate_passport(self, context: Dict) -> str:
        """Generate valid-format Indian passport number"""
        # Format: A1234567
        letter = random.choice(string.ascii_uppercase)
        numbers = ''.join(random.choices(string.digits, k=7))
        return f"{letter}{numbers}"
    
    def _generate_driving_license(self, context: Dict) -> str:
        """Generate valid-format Indian driving license"""
        # Format: SS00 0000 0000000
        state_codes = ["MH", "KA", "TN", "AP", "TS", "KL", "GJ", "RJ", "DL"]
        state = random.choice(state_codes)
        year = str(random.randint(10, 24))
        issue = ''.join(random.choices(string.digits, k=4))
        number = ''.join(random.choices(string.digits, k=7))
        return f"{state}{year} {issue} {number}"
    
    def _generate_bank_account(self, context: Dict) -> str:
        """Generate bank account number"""
        # 9-18 digits
        length = random.randint(9, 16)
        return ''.join(random.choices(string.digits, k=length))
    
    def _generate_ip_address(self, context: Dict) -> str:
        """Generate IP address"""
        # Avoid reserved ranges
        first = random.choice([10, 172, 192, random.randint(1, 223)])
        return f"{first}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def _generate_generic(self, context: Dict) -> str:
        """Generate generic placeholder"""
        return "[SYNTHETIC DATA]"
    
    def generate_batch(self, entities: list) -> Dict[str, str]:
        """
        Generate synthetic replacements for a batch of entities
        Maintains consistency (same original value → same synthetic value)
        """
        replacement_map = {}
        
        # Track generated names to use in email generation
        name_context = {}
        
        for entity in entities:
            entity_text = entity.get("text", "")
            entity_type = entity.get("type", "")
            
            # Skip if already generated
            if entity_text in replacement_map:
                continue
            
            # Context-aware generation
            context = {}
            
            if entity_type == "EMAIL" and name_context:
                context["name"] = list(name_context.values())[0]
            
            synthetic = self.generate(entity_type, context)
            replacement_map[entity_text] = synthetic
            
            if entity_type == "PERSON_NAME":
                name_context[entity_text] = synthetic
        
        return replacement_map
