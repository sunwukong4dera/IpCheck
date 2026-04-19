import re


def get_modified_ip(ip: str) -> str:
    last_point_index = ip.rfind('.')
    return f"{ip[:last_point_index]}*{ip[last_point_index + 1:]}"


def esc_for_copied_text(s: str) -> str:
    return re.sub(r"([_*\[\]()~`>#+\-=|{}.!\\])", r"\\\1", s)
