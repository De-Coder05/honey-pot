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
    logger.error(f"Validation Error: {exc}")
    return JSONResponse(
        status_code=422,
        content={"status": "error", "message": "Invalid or malformed request"},
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

# --- LOGIC ---

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
