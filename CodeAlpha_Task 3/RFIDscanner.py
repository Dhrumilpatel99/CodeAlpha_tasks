import time
import RPi.GPIO as GPIO
from mfrc522 import SimpleMFRC522

# Initialize RFID Reader
reader = SimpleMFRC522()

def detect_rfid():
    print("RFID Scanner is active. Bring a card near the reader...")
    try:
        while True:
            id, text = reader.read()
            print(f"Unauthorized RFID detected! Card ID: {id}")
            print("Take necessary actions to block or secure your card!")
            time.sleep(5)  # Delay to prevent repeated alerts
    except KeyboardInterrupt:
        print("RFID Scanner Stopped.")
        GPIO.cleanup()

if __name__ == "__main__":
    detect_rfid()