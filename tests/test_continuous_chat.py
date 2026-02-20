import requests
import json
import time
import os

BASE_URL = "http://localhost:8000"
API_KEY = "sentinal-hackathon-2026"

def print_separator():
    print("-" * 50)

def chat_turn(session_id, message_text, sender, history):
    url = f"{BASE_URL}/analyze"
    headers = {
        "x-api-key": API_KEY,
        "Content-Type": "application/json"
    }
    
    payload = {
        "sessionId": session_id,
        "message": {
            "sender": sender,
            "text": message_text,
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": history
    }
    
    print(f"\n[SENDING] {sender}: {message_text}")
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
        
        reply = data.get("reply", "")
        intel = data.get("extractedIntelligence", {})
        scam_detected = data.get("scamDetected", False)
        
        print(f"[RECEIVED] Reply: {reply}")
        print(f"[STATUS] Scam Detected: {scam_detected}")
        print(f"[INTELLIGENCE] {json.dumps(intel, indent=2)}")
        
        # Anti-Gravity Fields
        if "scammerProfile" in data:
            print(f"[SCAMMER DNA] {json.dumps(data['scammerProfile'], indent=2)}")
        if "engagementMetrics" in data:
            print(f"[METRICS] {json.dumps(data['engagementMetrics'], indent=2)}")
        
        # Return updated history for next turn
        new_history = history + [
            {"sender": sender, "text": message_text, "timestamp": int(time.time() * 1000)},
            {"sender": "HONEYPOT", "text": reply, "timestamp": int(time.time() * 1000) + 1000}
        ]
        return new_history
        
    except Exception as e:
        print(f"[ERROR] {e}")
        try:
            print(response.text)
        except:
            pass
        return history

def run_continuous_test():
    session_id = f"test-continuous-{int(time.time())}"
    history = []
    
    print_separator()
    print(f"Starting Continuous Chat Test (Session: {session_id})")
    print_separator()
    
    # Turn 1: Initial contact
    history = chat_turn(
        session_id, 
        "Hello, this is Bank Support. Your KYC is expired.", 
        "SCAMMER", 
        history
    )
    
    # Turn 2: Providing fake details
    input("\nPress Enter to continue to Turn 2...")
    history = chat_turn(
        session_id, 
        "Please transfer 5000 INR to verify account.", 
        "SCAMMER", 
        history
    )
    
    # Turn 3: Providing specific intelligence
    input("\nPress Enter to continue to Turn 3 (Adding Intel)...")
    history = chat_turn(
        session_id, 
        "Send money to UPI ID: fraudster@okicici and call +919998887776", 
        "SCAMMER", 
        history
    )
    
    print_separator()
    print("Test Completed. Verify that 'fraudster@okicici' and '+919998887776' were captured in the final intelligence.")

if __name__ == "__main__":
    run_continuous_test()
