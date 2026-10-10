import requests

# PASTE YOUR ACTUAL HERO-SMS API KEY BETWEEN THE QUOTES BELOW
API_KEY = "67fAb6dc5806f0bf23fc40148f811543"
BASE_URL = "https://hero-sms.com/stubs/handler_api.php"

# 1. Check your balance
params = {
    "api_key": API_KEY,
    "action": "getBalance"
}
response = requests.get(BASE_URL, params=params)
print("Balance Response:", response.text)

# 2. Get available numbers for Telegram in the USA (country code 0)
params = {
    "api_key": API_KEY,
    "action": "getNumbersStatus",
    "country": 0
}
response = requests.get(BASE_URL, params=params)
print("Available Numbers:", response.text)