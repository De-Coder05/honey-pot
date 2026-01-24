import subprocess
import time
import requests
import sys
import json
import os
import signal

def test_integration():
    print("--- STARTING INTEGRATION TEST ---")
    
    # 1. Start Server
    server_process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=os.getcwd()
    )
    
    print("Waiting for server to start...")
    time.sleep(5)
    
    try:
        # Check health
        health = requests.get("http://127.0.0.1:8000/")
        print("Health Check:", health.json())
        
        # 2. Test Scam Scenario
        url = "http://127.0.0.1:8000/api/honeypot"
        headers = {"x-api-key": "test_key", "Content-Type": "application/json"}
        
        payload_1 = {
            "sessionId": "integ_test_001",
            "message": {
                "sender": "scammer",
                "text": "URGENT: Your account is blocked. Visit http://fake-bank.com/login",
                "timestamp": "2026-01-24T12:00:00Z"
            },
            "conversationHistory": []
        }
        
        print("\n[TEST 1] Sending Scam Payload...")
        resp1 = requests.post(url, json=payload_1, headers=headers)
        print("Status:", resp1.status_code)
        data1 = resp1.json()
        print("Response:", json.dumps(data1, indent=2))
        
        assert data1['scamDetected'] == True
        assert "fake-bank.com" in str(data1['extractedIntelligence']['phishingLinks'])
        print("✅ TEST 1 PASSED: Scam Detected & Link Extracted")
        
        # 3. Test Agent Reply
        if data1.get('reply'):
            print(f"✅ Agent Replied: {data1['reply']}")
        else:
            print("⚠️ Agent did not reply (Check GEMINI_API_KEY)")

    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
    finally:
        print("\nStopping Server...")
        server_process.send_signal(signal.SIGTERM)
        server_process.wait()

if __name__ == "__main__":
    test_integration()
