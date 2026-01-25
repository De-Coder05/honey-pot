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

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    body = await request.body()
    logger.error(f"Validation Error: {exc}")
    try:
        logger.error(f"Request Body: {body.decode()}")
    except:
        logger.error("Request Body: <could not decode>")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": str(body)},
    )

# RESTORED IMPORTS
from config import API_SECRET_KEY, CALLBACK_URL
from session_manager import get_session, update_session, Message, SessionData
from scam_detector import detect_scam
from honeypot_agent import HoneypotAgent
from intelligence_extractor import extract_intelligence, merge_intelligence

agent = HoneypotAgent()

# --- INPUT MODELS ---
class MessageContent(BaseModel):
    sender: str
    text: str
    timestamp: Optional[Union[str, int, float]] = None

class ConversationMetadata(BaseModel):
    channel: Optional[str] = "unknown"
    language: Optional[str] = "en"
    locale: Optional[str] = "IN"

class HoneyPotRequest(BaseModel):
    sessionId: str
    message: MessageContent
    conversationHistory: List[MessageContent] = []
    metadata: Optional[ConversationMetadata] = None

# --- OUTPUT MODELS ---
class EngagementMetrics(BaseModel):
    engagementDurationSeconds: float
    totalMessagesExchanged: int

class IntelligenceData(BaseModel):
    bankAccounts: List[str]
    upiIds: List[str]
    phishingLinks: List[str]
    phoneNumbers: List[str]
    suspiciousKeywords: List[str]

class HoneyPotResponse(BaseModel):
    status: str
    scamDetected: bool
    engagementMetrics: EngagementMetrics
    extractedIntelligence: IntelligenceData
    agentNotes: str
    reply: Optional[str] = None # Added for agent interaction

# --- LOGIC ---

def send_final_callback(session: SessionData):
    """Sends the mandatory final result to GUVI endpoint"""
    try:
        # Construct payload as per Section 12 of guidelines
        payload = {
            "sessionId": session.session_id,
            "scamDetected": session.scam_detected,
            "totalMessagesExchanged": len(session.messages),
            "extractedIntelligence": session.extracted_intelligence,
            "agentNotes": session.agent_notes or "Scam detected via automation."
        }
        
        # Send to GUVI
        # using a timeout to not block anything (though this is running in background)
        response = requests.post(
            CALLBACK_URL,
            json=payload,
            timeout=5
        )
        logger.info(f"Callback sent for {session.session_id}: {response.status_code}")
    except Exception as e:
        logger.error(f"Failed to send callback: {e}")

@app.post("/api/honeypot")
async def handle_honeypot(
    request: HoneyPotRequest, 
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(None)
):
    # 1. Auth Check
    # In a real hackathon, we might just compare with our own secret 
    # or accept any key if we are the ones providing it to the judge.
    # For now, simplistic check:
    if not x_api_key:
         raise HTTPException(status_code=401, detail="Missing API Key")

    session = get_session(request.sessionId)
    
    # 2. Update History
    # We trust the incoming history usually, but we also keep our own copy 
    # just in case the platform sends partials.
    # For simplicity, let's append the NEW message to our session log.
    new_msg = request.message
    session.messages.append(new_msg)
    
    # 3. Detect Scam (If not already detected)
    is_scam = session.scam_detected
    if not is_scam:
        is_scam = detect_scam(new_msg.text)
        session.scam_detected = is_scam
        if is_scam:
            session.agent_notes = "Scam intent detected via content analysis."

    # 4. Agent Engagement & Intelligence Extraction
    reply_text = None
    if is_scam:
        # Extract Intelligence from the INCOMING message
        new_intel = extract_intelligence(new_msg.text)
        session.extracted_intelligence = merge_intelligence(session.extracted_intelligence, new_intel)
        
        # Generate Agent Response
        # We pass the FULL history (request.conversationHistory + new_msg)
        full_history = [m.model_dump() for m in request.conversationHistory]
        full_history.append(new_msg.model_dump())
        
        reply_text = agent.generate_response(full_history)
        
        # Log our reply to session
        # Note: The platform might not send this back in 'history' next time if we don't output it.
        # Ideally we should see 'sender': 'user' in next request history.
        
    # 5. Metrics
    duration = time.time() - session.start_time
    total_msgs = len(session.messages) + len(request.conversationHistory) 
    
    response_data = HoneyPotResponse(
        status="success",
        scamDetected=is_scam,
        engagementMetrics=EngagementMetrics(
            engagementDurationSeconds=round(duration, 2),
            totalMessagesExchanged=total_msgs
        ),
        extractedIntelligence=IntelligenceData(**session.extracted_intelligence),
        agentNotes=session.agent_notes,
        reply=reply_text
    )
    
    # Update Session State
    update_session(request.sessionId, session)
    
    # 6. Trigger Callback (Mandatory for Evaluation)
    # We send this in the background to not slow down the response.
    # We send it if scam is detected, acting as a real-time update/final report.
    if is_scam:
        background_tasks.add_task(send_final_callback, session)
    
    return response_data

@app.get("/")
def health_check():
    return {"status": "Money-Pot is running"}
