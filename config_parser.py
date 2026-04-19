import os
from dotenv import load_dotenv

dotenv_path = os.path.join(os.path.dirname(__file__), 'config.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
OTX_KEY = os.getenv("OTX_KEY")

URL_ABUSEIPDB = os.getenv("URL_ABUSEIPDB")
URL_VIRUSTOTAL = os.getenv("URL_VIRUSTOTAL")
URL_OTX = os.getenv("URL_OTX")

TELEGRAM_BOT_TOKEN=os.getenv("TELEGRAM_BOT_TOKEN")