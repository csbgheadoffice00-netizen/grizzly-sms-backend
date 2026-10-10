import asyncio
from herosms import HeroSMSClient

async def main():
    # Replace with your actual API key
   async with HeroSMSClient(api_key="67fAb6dc5806f0bf23fc40148f811543") as client:
        # 1. Print balance
        balance = await client.get_balance()
        print(f"Balance: {balance}")

        # 2. Create an activation for Telegram in the UK (country 16)
        print("Creating activation for Telegram in the UK...")
        activation = await client.activations.create(service="tg", country=16)
        print(f"Phone Number: {activation.phone}")
        print("Go to Telegram now and request an SMS to this number.")

        # 3. Wait for the SMS (5-minute timeout)
        print("Waiting for SMS code...")
        try:
            status = await activation.wait_for_sms(timeout=300)
            print(f"🎉 SUCCESS! Your code is: {status.code}")

            # 4. Mark the activation as complete
            await activation.complete()
            print("Activation completed successfully!")
        except Exception as e:
            print(f"Error or timeout: {e}")
            print("Cancelling activation to get a refund...")
            await activation.cancel()
            print("Activation cancelled.")

if __name__ == "__main__":
    asyncio.run(main())