import google.generativeai as genai
from config import GEMINI_API_KEY
from typing import List, Dict

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

PERSONA = """
You are Ramesh, a 68-year-old retired railway clerk living in Chennai.
You are technologically naive, slightly confused, but polite.
You are chatting with someone who claims to be from a bank or official service.
Your goal is to waste their time.

Guidelines:
1. Act confused about technology (app downloads, UPI pins).
2. Ask clarifying questions that don't make sense.
3. Pretend to try to follow their instructions but "fail" (e.g., "It says invalid password" or "The battery died").
4. Occasionally give them fake wrong numbers or codes.
5. NEVER reveal you know it is a scam.
6. Keep your responses short (1-2 sentences).
"""

class HoneypotAgent:
    def __init__(self):
        self.model = genai.GenerativeModel('gemini-flash-latest')

    def generate_response(self, history: List[Dict]) -> str:
        if not GEMINI_API_KEY:
            return "Hello? I am listening. what do i do?"

        # Construct chat history for Gemini
        chat_context = PERSONA + "\n\nConversation History:\n"
        for msg in history:
            sender = "Scammer" if msg['sender'] == 'scammer' else "Me"
            chat_context += f"{sender}: {msg['text']}\n"
        
        chat_context += "Me: "

        try:
            response = self.model.generate_content(chat_context)
            return response.text.strip()
        except Exception as e:
            print(f"Agent Error (using fallback): {e}")
            import random
            
            # Expanded list of fallbacks
            fallbacks = [
                "I am sorry, I am a bit old. Can you explain that again?",
                "My grandson usually handles this. One moment please.",
                "I am pressing the button but nothing is happening.",
                "Is it possible to do this at the bank branch? I can come tomorrow.",
                "I am submitting the details... please wait...",
                "Wait, my connection is very slow... I am trying.",
                "Can you hear me? The line is breaking up.",
                "I cannot find my reading glasses, one second...",
                "It is asking for a code again, did you send a new one?"
            ]
            
            # Ensure we don't pick the same one twice in a row (simple logic)
            # Since we don't have persistent state for 'last message' per session easily here without DB,
            # we will just pick random. Ideally, we'd track this.
            # But let's at least make the list larger to reduce collision chance.
            return random.choice(fallbacks)
