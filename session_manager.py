from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel

class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

class SessionData(BaseModel):
    session_id: str
    messages: List[Message] = []
    scam_detected: bool = False
    metadata: Dict = {}
    extracted_intelligence: Dict = {
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "suspiciousKeywords": []
    }
    agent_notes: str = ""
    start_time: float = 0.0

# In-memory storage
sessions: Dict[str, SessionData] = {}

def get_session(session_id: str) -> SessionData:
    if session_id not in sessions:
        sessions[session_id] = SessionData(
            session_id=session_id, 
            start_time=datetime.now().timestamp()
        )
    return sessions[session_id]

def update_session(session_id: str, data: SessionData):
    sessions[session_id] = data
