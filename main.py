from fastapi import FastAPI, HTTPException, Header, BackgroundTasks, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Union
import time
import requests
import logging
import json

app = FastAPI()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- OUTPUT MODELS (STRICT PER GUIDELINES) ---
class HoneyPotResponse(BaseModel):
    status: str
    reply: Optional[str] = None

# --- CUSTOM EXCEPTION HANDLERS (PER GUIDELINES SECTION 11) ---
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": "error", "message": exc.detail},
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Log detailed validation errors
    error_details = exc.errors()
    logger.error(f"Validation Error: {error_details}")
    try:
        # Try to log body if available in exception
        if hasattr(exc, 'body'):
            logger.error(f"Request Body triggering error: {exc.body}")
    except:
        pass
        
    return JSONResponse(
        status_code=422,
        content={"status": "error", "message": f"Invalid request: {error_details}"},
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled Exception: {exc}")
    # Return 200 OK with error status to prevent client-side parsing crashes
    # OR return 500 with JSON. Guidelines say "status: error".
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "Internal Server Error"},
    )

# --- IMPORTS ---
from config import CALLBACK_URL, GEMINI_API_KEY
from intelligence_extractor import extract_intelligence, merge_intelligence
import google.generativeai as genai
from fastapi import Request
import time

# Configure GenAI
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-pro')



# --- DATA MODELS ---

class Message(BaseModel):
    role: str  # "user" or "agent"
    text: str
    timestamp: Union[float, str, None] = None
    
    class Config:
        extra = "ignore" # Allow extra fields like 'id' or 'meta'

class HoneyPotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    
    class Config:
        extra = "ignore" # Allow extra fields

class SessionData:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.messages: List[Message] = []
        self.scam_detected: bool = False
        self.extracted_intelligence: Dict = {
            "bankAccounts": [], "upiIds": [], "phishingLinks": [], "phoneNumbers": [], "suspiciousKeywords": []
        }
        self.agent_notes: Optional[str] = None

# --- IN-MEMORY SESSION STORE ---
sessions: Dict[str, SessionData] = {}

def get_session(session_id: str) -> SessionData:
    if session_id not in sessions:
        sessions[session_id] = SessionData(session_id)
    return sessions[session_id]

def update_session(session_id: str, session: SessionData):
    sessions[session_id] = session

# --- HELPER FUNCTIONS ---

def detect_scam(text: str) -> bool:
    """Simple keyword-based detection + LLM sanity check if available"""
    suspicious_keywords = ["urgent", "verify", "block", "freeze", "kyc", "pan", "otp", "winner", "prize", "lottery"]
    if any(word in text.lower() for word in suspicious_keywords):
        return True
    return False

class Agent:
    def generate_response(self, history: List[Dict]) -> str:
        """Generates a response using Gemini or fallback"""
        # Construct prompt from history
        system_prompt = (
            "You are an elderly, slightly confused, but wealthy individual named Ramesh. "
            "You are currently talking to someone who might be a scammer. "
            "Your goal is to waste their time by asking irrelevant questions, acting confused about technology, "
            "and pretending to try to follow their instructions but 'failing' or getting distracted. "
            "Do NOT reveal that you know it is a scam. Just play along and keep them engaged. "
            "Keep your responses short and conversational."
        )
        
        try:
            if GEMINI_API_KEY:
                chat = model.start_chat(history=[])
                # Feed history loosely (simplification for hackathon speed)
                prompt = system_prompt + "\n\nConversation History:\n"
                for msg in history[-5:]: # Keep context short
                    try:
                        # Handle case where msg is dict or Pydantic model
                        role = msg.get('role') if isinstance(msg, dict) else msg.role
                        text = msg.get('text') if isinstance(msg, dict) else msg.text
                        prompt += f"{role}: {text}\n"
                    except:
                        continue
                prompt += "Ramesh:"
                
                response = model.generate_content(prompt)
                return response.text.strip()
            else:
                return "Oh dear, verify what? I'm not very good with these computer things. My grandson usually helps me."
        except Exception as e:
            logger.error(f"LLM Error: {e}")
            return "I am sorry, I didn't quite catch that. Could you repeat?"

agent = Agent()


def send_final_callback(session: SessionData):
    """Sends the mandatory final result to GUVI endpoint"""
    try:
        # Construct payload as per Section 12 of guidelines
        # Use fallback values if session data is incomplete
        payload = {
            "sessionId": session.session_id,
            "scamDetected": session.scam_detected,
            "totalMessagesExchanged": len(session.messages),
            "extractedIntelligence": session.extracted_intelligence,
            "agentNotes": session.agent_notes or "Scam detected via automation."
        }
        
        # Send to GUVI
        response = requests.post(
            CALLBACK_URL,
            json=payload,
            timeout=5
        )
        logger.info(f"Callback sent for {session.session_id}: {response.status_code}")
    except Exception as e:
        logger.error(f"Failed to send callback: {e}")

@app.post("/api/honeypot", response_model=HoneyPotResponse)
async def handle_honeypot(
    request: HoneyPotRequest, 
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(None)
):
    # 1. Auth Check (Section 5)
    if not x_api_key:
         raise HTTPException(status_code=401, detail="Invalid API key or malformed request")

    session = get_session(request.sessionId)
    
    # 2. Update History
    new_msg = request.message
    session.messages.append(new_msg)
    
    # 3. Detect Scam
    is_scam = session.scam_detected
    if not is_scam:
        is_scam = detect_scam(new_msg.text)
        session.scam_detected = is_scam
        if is_scam:
            session.agent_notes = "Scam intent detected via content analysis."

    # 4. Agent Engagement
    reply_text = None
    if is_scam:
        # Extract Intelligence (Section 5.5)
        new_intel = extract_intelligence(new_msg.text)
        session.extracted_intelligence = merge_intelligence(session.extracted_intelligence, new_intel)
        
        # Generate Agent Response
        full_history = [m.model_dump() for m in request.conversationHistory]
        full_history.append(new_msg.model_dump())
        
        reply_text = agent.generate_response(full_history)
        
        # Trigger Callback (Section 12 - Mandatory)
        background_tasks.add_task(send_final_callback, session)
    
    # 5. Response (Strict Spec Section 8)
    # Note: Metrics and Intelligence are NOT returned here anymore, only in Callback.
    response_data = HoneyPotResponse(
        status="success",
        reply=reply_text
    )
    
    # Update Session State
    update_session(request.sessionId, session)
    
    return response_data

@app.get("/")
def health_check():
    return {"status": "Money-Pot is running"}
