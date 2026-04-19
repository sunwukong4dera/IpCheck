import re
import telebot
import requests

from config_parser import (
    VIRUSTOTAL_API_KEY, ABUSEIPDB_KEY, OTX_KEY,
    URL_VIRUSTOTAL, URL_ABUSEIPDB, URL_OTX, TELEGRAM_BOT_TOKEN
)
from normalizer import normalize
from util import get_modified_ip, esc_for_copied_text


bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)


def fetch_virustotal(ip: str) -> dict:
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
    r = requests.get(f"{URL_VIRUSTOTAL}ip_addresses/{ip}", headers=headers, timeout=15)
    r.raise_for_status()
    return r.json()


def fetch_abuseipdb(ip: str) -> dict:
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_KEY}
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
    r = requests.get(URL_ABUSEIPDB, headers=headers, params=params, timeout=15)
    r.raise_for_status()
    return r.json()


def fetch_otx(ip: str) -> dict:
    headers = {"X-OTX-API-KEY": OTX_KEY}
    r = requests.get(f"{URL_OTX}indicators/IPv4/{ip}/general", headers=headers, timeout=15)
    r.raise_for_status()
    return r.json()


def check_ip(ip: str) -> str:
    vt = fetch_virustotal(ip)
    abuse = fetch_abuseipdb(ip)
    otx = fetch_otx(ip)
    return normalize(vt, abuse, otx)


@bot.message_handler(func=lambda m: True)
def handle_message(message: telebot.types.Message) -> None:
    ip_list = list(dict.fromkeys(re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").findall(message.text or "")))
    if not ip_list:
        return

    for ip in ip_list:
        try:
            screened_ip = get_modified_ip(ip)
            report = check_ip(ip)
            text = (f"IP\-адрес:\n```{esc_for_copied_text(ip)}```\n\n"
                    f"Экранированный IP\-адрес:\n```{esc_for_copied_text(screened_ip)}```\n\n"
                    f"Отчет:\n```\n{esc_for_copied_text(report)}\n```")
        except Exception as e:
            bot.send_message(message.chat.id,
                             f"Ошибка {ip}: {esc_for_copied_text(str(e))}",
                             parse_mode='MarkdownV2')
            continue
        bot.send_message(message.chat.id,
                         text,
                         parse_mode='MarkdownV2')


if __name__ == "__main__":
    bot.infinity_polling()
