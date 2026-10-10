import requests
import time

# 1. SETUP
API_KEY = "67fAb6dc5806f0bf23fc40148f811543"  # Replace with your actual key
BASE_URL = "https://hero-sms.com/stubs/handler_api.php"

# We will try Indonesia (6) for Telegram (tg), because USA (0) had no stock.
# You can change these numbers/letters later. 0=USA, 6=Indonesia, 16=UK
SERVICE = "tg"  
COUNTRY = 6     

def buy_number():
    """Buys a number and returns the activation ID and phone number."""
    params = {
        "api_key": API_KEY,
        "action": "getNumber",
        "service": SERVICE,
        "country": COUNTRY
    }
    response = requests.get(BASE_URL, params=params)
    print("Buy Number Response:", response.text)
    
    if "ACCESS_NUMBER" in response.text:
        # Format is ACCESS_NUMBER:activation_id:phone_number
        parts = response.text.split(":")
        return parts[1], parts[2]
    else:
        return None, None

def check_sms(activation_id):
    """Polls for the SMS code until it arrives or timeout (120 seconds)."""
    print("Waiting for SMS code...")
    start_time = time.time()
    
    while time.time() - start_time < 120:
        params = {
            "api_key": API_KEY,
            "action": "getStatus",
            "id": activation_id
        }
        response = requests.get(BASE_URL, params=params)
        status = response.text
        
        if "STATUS_OK" in status:
            # Format is STATUS_OK:1234
            code = status.split(":")[1]
            return code
        elif "STATUS_WAIT_CODE" in status:
            print("SMS not yet received. Checking again in 5 seconds...")
            time.sleep(5)
        else:
            print(f"Received unexpected status: {status}")
            return None
            
    print("Timeout: No SMS received within 2 minutes.")
    return None

def cancel_number(activation_id):
    """Cancels the activation to get a refund from HeroSMS."""
    params = {
        "api_key": API_KEY,
        "action": "setStatus",
        "status": 8,  # 8 means "cancel" (refund)
        "id": activation_id
    }
    requests.get(BASE_URL, params=params)
    print("Activation cancelled. You have been refunded on HeroSMS.")

def finish_number(activation_id):
    """Marks the activation as complete (you keep the charge)."""
    params = {
        "api_key": API_KEY,
        "action": "setStatus",
        "status": 6,  # 6 means "complete"
        "id": activation_id
    }
    requests.get(BASE_URL, params=params)
    print("Activation completed successfully!")

# --- MAIN FLOW ---
print(f"Attempting to buy a {SERVICE} number in country {COUNTRY}...")
act_id, phone = buy_number()

if act_id:
    print(f"Success! You bought the number: {phone}")
    print("Go to Telegram now and try to register with this number.")
    
    code = check_sms(act_id)
    
    if code:
        print(f"🎉 SUCCESS! Your SMS code is: {code}")
        finish_number(act_id)
    else:
        print("No SMS arrived. Cancelling to protect your balance...")
        cancel_number(act_id)
else:
    print("Could not buy a number. The country or service might be out of stock.")
    print("Try changing COUNTRY to 16 (UK) or SERVICE to 'wa' (WhatsApp).")
