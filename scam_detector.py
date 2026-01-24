import google.generativeai as genai
from config import GEMINI_API_KEY

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

def detect_scam(text: str) -> bool:
    if not GEMINI_API_KEY:
        # Fallback if no key provided (for testing structure)
        return "urgent" in text.lower() or "block" in text.lower()
    
    model = genai.GenerativeModel('gemini-flash-latest')
    prompt = f"""
    Analyze the following message. Determine if it indicates a scam attempt (phishing, fraud, social engineering).
    
    Message: "{text}"
    
    Return ONLY 'TRUE' if it is a scam, and 'FALSE' if it is legitimate.
    """
    try:
        response = model.generate_content(prompt)
        result = response.text.strip().upper()
        return "TRUE" in result
    except Exception as e:
        print(f"Scam Detector Error (using fallback): {e}")
        # Robust Fallback: Check for suspicious keywords if API fails (e.g. Rate Limit)
        suspicious = ["urgent", "block", "freeze", "kyc", "pan", "aadhar", "otp", "credit", "debit", "bank", "account", "verify"]
        return any(word in text.lower() for word in suspicious)
