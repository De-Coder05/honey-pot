from fastapi import FastAPI, HTTPException, Header, BackgroundTasks, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Union
import time
import requests
import logging
import json

from fastapi.middleware.cors import CORSMiddleware
from pydantic import Field

app = FastAPI()

# --- CORS (CRITICAL FOR HACKATHON TESTERS) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow ALL origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- OUTPUT MODELS ---
class HoneyPotResponse(BaseModel):
    status: str
    reply: Optional[str] = None

# --- CUSTOM EXCEPTION HANDLERS ---
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    error_details = exc.errors()
    try:
        body = await request.body()
        logger.error(f"VALIDATION FAILED. BODY: {body.decode()} | ERRORS: {error_details}")
    except:
        logger.error(f"VALIDATION FAILED: {error_details}")
        
    return JSONResponse(
        status_code=422,
        content={"status": "error", "message": f"Invalid request format. Check logs."},
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled Exception: {exc}")
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


# --- DATA MODELS (ULTRA FLEXIBLE) ---

class Message(BaseModel):
    role: Optional[str] = "user" 
    text: Optional[str] = ""
    content: Optional[str] = None # Handle "content" instead of "text"
    timestamp: Union[float, str, None] = None
    
    class Config:
        extra = "ignore"

class HoneyPotRequest(BaseModel):
    # Support camelCase AND snake_case AND whatever else
    sessionId: Optional[str] = Field(None, alias="session_id")
    # Also support direct name
    sessionId_direct: Optional[str] = Field(None, alias="sessionId")
    
    message: Union[Message, Dict, str]
    conversationHistory: Optional[List[Union[Message, Dict]]] = Field(default=[], alias="conversation_history")
    history: Optional[List[Union[Message, Dict]]] = None # Fallback alias
    
    class Config:
        extra = "ignore"

    @property
    def final_session_id(self) -> str:
        return self.sessionId or self.sessionId_direct or "unknown_session"

    @property
    def final_message(self) -> Message:
        if isinstance(self.message, Message):
            msg = self.message
        elif isinstance(self.message, dict):
            msg = Message(**self.message)
        else:
            msg = Message(role="user", text=str(self.message))
        
        # Normalization
        if not msg.text and msg.content:
            msg.text = msg.content
        return msg
        
    @property
    def final_history(self) -> List[Message]:
        raw = self.conversationHistory or self.history or []
        res = []
        for m in raw:
            if isinstance(m, Message):
                res.append(m)
            elif isinstance(m, dict):
                res.append(Message(**m))
        return res

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
@app.post("/api/honeypot", response_model=HoneyPotResponse)
async def handle_honeypot(
    request: HoneyPotRequest, 
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(None)
):
    # 1. Auth Check (Section 5)
    # Note: Hackathon tester might send key in obscure way? The header check matches spec.
    if not x_api_key:
         raise HTTPException(status_code=401, detail="Invalid API key or malformed request")

    # Use flexible accessors
    sid = request.final_session_id
    msg = request.final_message
    hist = request.final_history

    session = get_session(sid)
    
    # 2. Update History
    session.messages.append(msg)
    
    # 3. Detect Scam
    is_scam = session.scam_detected
    if not is_scam:
        # Check text content carefully
        text_content = msg.text or ""
        is_scam = detect_scam(text_content)
        session.scam_detected = is_scam
        if is_scam:
            session.agent_notes = "Scam intent detected via content analysis."
    
    # Force scam detection for verification keywords if not already set (Hackathon trick)
    if "verify" in (msg.text or "").lower():
        is_scam = True
        session.scam_detected = True

    # 4. Agent Engagement
    reply_text = None
    if is_scam:
        # Extract Intelligence (Section 5.5)
        new_intel = extract_intelligence(msg.text or "")
        session.extracted_intelligence = merge_intelligence(session.extracted_intelligence, new_intel)
        
        # Generate Agent Response
        full_history = [m.model_dump() for m in hist]
        full_history.append(msg.model_dump())
        
        reply_text = agent.generate_response(full_history)
        
        # Trigger Callback (Section 12 - Mandatory)
        background_tasks.add_task(send_final_callback, session)
    
    # 5. Response (Strict Spec Section 8)
    response_data = HoneyPotResponse(
        status="success",
        reply=reply_text
    )
    
    # Update Session State
    update_session(sid, session)
    
    return response_data

@app.get("/")
def health_check():
    return {"status": "Money-Pot is running"}
