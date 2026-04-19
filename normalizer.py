from util import get_modified_ip

ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


def normalize(virustotal_rsp: dict, abuseipdb_rsp: dict, otx_rsp: dict) -> str:
    ret_lst = []

    # header
    vt_attrs = virustotal_rsp.get("data", {}).get("attributes", {})
    abuse_data = abuseipdb_rsp.get("data", {})
    ip = abuse_data.get("ipAddress", "N/A")
    country = abuse_data.get("countryName", "N/A")
    isp = abuse_data.get("isp", "N/A")

    screened_ip = get_modified_ip(ip)
    ret_lst.append(f"IP-адрес: {screened_ip}\n")
    ret_lst.append(f"Страна: {country}")
    ret_lst.append(f"Провайдер: {isp}\n")

    # virustotal
    stats = vt_attrs.get("last_analysis_stats", {})
    results = vt_attrs.get("last_analysis_results", {})
    total = sum(stats.values())
    detected = stats.get("malicious", 0) + stats.get("suspicious", 0)

    ret_lst.append(
        f"При проверке на TI платформах установлено, что IP-адрес был зафиксирован во вредоносной активности. "
        f"По данным VirusTotal {detected}/{total} TI вендоров отметили IP-адрес в своих отчётах:\n"
    )

    by_result: dict[str, list[str]] = {}
    for engine, info in results.items():
        cat = info.get("category")
        res = info.get("result")
        if cat in ("malicious", "suspicious") or (cat == "malicious" and res not in ("malicious",)):
            label = res if res not in ("malicious", "suspicious") else cat
            by_result.setdefault(label, []).append(engine)

    for label, engines in sorted(by_result.items()):
        ret_lst.append(f"с классификацией {label}:")
        for e in engines:
            ret_lst.append(f"    - {e}")

    # abuseipdb
    all_cats: set[int] = set()
    for report in abuse_data.get("reports", []):
        all_cats.update(report.get("categories", []))
    cat_names = [ABUSE_CATEGORIES.get(c, str(c)) for c in sorted(all_cats) if c in ABUSE_CATEGORIES]
    total_reports = abuse_data.get("totalReports", 0)

    ret_lst.append(
        f"\nПо отчётам пользователей на AbuseIPDB за последние 3 месяца ({total_reports} репортов) "
        f"представлен в категориях: {', '.join(cat_names)}"
    )

    # otx
    pulse_count = otx_rsp.get("pulse_info", {}).get("count", 0)
    ret_lst.append(f"\nПри проверке на Open Threat Exchange замечен в {pulse_count} TI отчетах.")

    malware_families: list[str] = []
    for pulse in otx_rsp.get("pulse_info", {}).get("pulses", []):
        for mf in pulse.get("malware_families", []):
            name = mf.get("display_name") or mf.get("id")
            if name and name not in malware_families:
                malware_families.append(name)

    if malware_families:
        ret_lst.append(f"\nСвязан с следующими APT или ВПО [{len(malware_families)}]:")
        for mf in malware_families:
            ret_lst.append(f"    - {mf}")

    ret_str = "\n".join(ret_lst)

    return ret_str
