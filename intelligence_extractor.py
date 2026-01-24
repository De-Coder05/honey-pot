import re
from typing import Dict, List

def extract_intelligence(text: str) -> Dict[str, List[str]]:
    intelligence = {
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "suspiciousKeywords": []
    }
    
    # Regex Patterns
    upi_pattern = r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}"
    # Simple bank account pattern (9-18 digits often found near IFSC or just explicitly stated)
    # This is a bit generous, usually need context, but good for hackathon
    bank_acc_pattern = r"\b\d{9,18}\b" 
    url_pattern = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"
    phone_pattern = r"(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"
    
    # Keywords
    suspicious_words = ["urgent", "verify", "block", "freeze", "kyc", "pan", "aadhar", "otp", "credit card"]
    
    intelligence["upiIds"] = re.findall(upi_pattern, text)
    intelligence["bankAccounts"] = [m for m in re.findall(bank_acc_pattern, text) if len(m) > 9] # Filter out short numbers
    intelligence["phishingLinks"] = re.findall(url_pattern, text)
    intelligence["phoneNumbers"] = re.findall(phone_pattern, text)
    
    found_keywords = []
    lower_text = text.lower()
    for word in suspicious_words:
        if word in lower_text:
            found_keywords.append(word)
    intelligence["suspiciousKeywords"] = found_keywords
    
    return intelligence

def merge_intelligence(existing: Dict, new_data: Dict) -> Dict:
    for key in existing:
        if key in new_data:
            # Add unique new items
            current_set = set(existing[key])
            for item in new_data[key]:
                if item not in current_set:
                    existing[key].append(item)
    return existing
