#!/usr/bin/env python3
"""
audit_email_auth.py

Script audit SPF, DKIM, dan DMARC untuk domain institusi Indonesia,
mengikuti metodologi di paper "Guarding Against Email Spoofing".

CARA PAKAI:
    1. pip install dnspython --upgrade
    2. Siapkan file domains.csv (lihat contoh di bagian bawah script ini,
       atau file domains_template.csv yang disertakan terpisah).
       Format: domain,sector
       Contoh:
           kemendikbud.go.id,government
           ui.ac.id,university
    3. Jalankan: python3 audit_email_auth.py domains.csv hasil_audit.csv

Script ini TIDAK menyimpan atau mengirim data ke pihak manapun selain
melakukan query DNS standar (sama seperti perintah dig/nslookup),
seluruhnya berjalan lokal di komputermu.
"""

import sys
import csv
import time
import re
import dns.resolver
import dns.exception

# ------------------------------------------------------------------
# Konfigurasi
# ------------------------------------------------------------------

# Selector DKIM yang paling umum dipakai penyedia layanan email.
# Daftar ini TIDAK lengkap (memang tidak mungkin lengkap, karena DKIM
# selector bisa bebas ditentukan admin domain), makanya statusnya
# dikategorikan Confirmed / Not Confirmed / Inconclusive, bukan
# sekadar ada / tidak ada. Sesuaikan/tambah daftar ini kalau kamu tahu
# selector spesifik yang lebih umum dipakai di Indonesia.
DKIM_SELECTORS = [
    "google",       # Google Workspace
    "selector1",    # Microsoft 365
    "selector2",    # Microsoft 365 (cadangan)
    "k1",           # Mailchimp / Sendgrid / beberapa ESP lain
    "dkim",         # generik
    "default",      # generik, cPanel, banyak mail server lokal
    "mail",         # generik
    "s1",
    "s2",
    "smtp",
    "zoho",         # Zoho Mail
]

# Pola hostname MX untuk mengenali provider (dipakai untuk kategori
# provider di Bagian III-F paper, dan untuk membantu menilai apakah
# DKIM Inconclusive itu wajar atau tidak).
MX_PROVIDER_PATTERNS = [
    (r"google\.com$|googlemail\.com$|aspmx\.l\.google\.com$", "Google Workspace"),
    (r"outlook\.com$|protection\.outlook\.com$", "Microsoft 365"),
    (r"zoho\.com$", "Zoho Mail"),
    (r"qq\.com$", "Tencent QQ Mail"),
    (r"pphosted\.com$", "Proofpoint (hosted)"),
    (r"mimecast\.com$", "Mimecast (hosted)"),
]

RESOLVER_TIMEOUT = 5.0   # detik, per query
DELAY_BETWEEN_DOMAINS = 0.5  # detik, biar sopan ke server DNS

resolver = dns.resolver.Resolver()
resolver.timeout = RESOLVER_TIMEOUT
resolver.lifetime = RESOLVER_TIMEOUT


# ------------------------------------------------------------------
# Fungsi bantu query DNS
# ------------------------------------------------------------------

def query_txt(name):
    """Ambil semua TXT record untuk sebuah nama domain. Return list
    string (sudah digabung kalau TXT record terpecah beberapa
    potongan), atau list kosong kalau tidak ada / gagal."""
    try:
        answers = resolver.resolve(name, "TXT")
        records = []
        for rdata in answers:
            # TXT record bisa terdiri dari beberapa potongan string,
            # gabungkan jadi satu.
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            records.append(txt)
        return records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []


def query_mx(domain):
    """Ambil daftar hostname MX untuk sebuah domain, urut berdasar
    prioritas. Return list string hostname (lowercase, tanpa titik di
    akhir), atau list kosong."""
    try:
        answers = resolver.resolve(domain, "MX")
        hosts = sorted(
            [(r.preference, str(r.exchange).rstrip(".").lower()) for r in answers]
        )
        return [h for _, h in hosts]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []


# ------------------------------------------------------------------
# SPF
# ------------------------------------------------------------------

def _count_lookup_terms(spf_record):
    """Hitung mekanisme SPF yang memicu DNS lookup (include, a, mx,
    ptr, exists, redirect), dengan cara memecah record per kata,
    bukan regex tunggal, supaya kata "all"/"-all"/"~all" tidak salah
    kehitung sebagai mekanisme "a"."""
    count = 0
    lookup_prefixes = (
        "include:", "a:", "a/", "mx:", "mx/", "ptr:", "exists:", "redirect=",
    )
    for term in spf_record.split():
        t = term.lower()
        if t in ("v=spf1",):
            continue
        stripped = t.lstrip("+-~?")
        if stripped == "all":
            continue
        if any(t.startswith(p) for p in lookup_prefixes):
            count += 1
        elif t in ("a", "mx", "ptr"):
            count += 1
    return count


def count_spf_lookups(spf_record, domain, depth=0, seen=None):
    """Hitung perkiraan jumlah DNS lookup yang dipicu satu SPF record,
    termasuk include/redirect yang bersifat rekursif, untuk mengecek
    batas 10 lookup dari RFC 7208. Ini adalah pendekatan sederhana,
    bukan implementasi SPF evaluator penuh."""
    if seen is None:
        seen = set()
    if domain in seen or depth > 5:
        # Hindari infinite loop kalau ada konfigurasi SPF yang salah
        # (misalnya saling redirect).
        return 0
    seen.add(domain)

    lookup_mechanisms = _count_lookup_terms(spf_record)
    count = lookup_mechanisms

    # Ikuti include/redirect secara rekursif (opsional, bisa lambat
    # kalau domainnya banyak chain include-nya).
    includes = re.findall(r"include:([^\s]+)", spf_record)
    redirects = re.findall(r"redirect=([^\s]+)", spf_record)
    for inc_domain in includes + redirects:
        inc_records = query_txt(inc_domain)
        for rec in inc_records:
            if rec.lower().startswith("v=spf1"):
                count += count_spf_lookups(rec, inc_domain, depth + 1, seen)

    return count


def audit_spf(domain):
    """Return dict berisi status SPF untuk satu domain."""
    result = {
        "spf_present": False,
        "spf_record": "",
        "spf_lookup_count": None,
        "spf_has_plus_all": False,
        "spf_valid": False,  # present, lookup <=10, tidak pakai +all
    }
    records = query_txt(domain)
    spf_records = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf_records:
        return result

    # Kalau lebih dari satu SPF record ditemukan, itu sendiri sudah
    # jadi masalah konfigurasi (RFC 7208 melarang lebih dari satu),
    # tapi untuk analisis kita tetap ambil yang pertama.
    spf_record = spf_records[0]
    result["spf_present"] = True
    result["spf_record"] = spf_record

    lookup_count = count_spf_lookups(spf_record, domain)
    result["spf_lookup_count"] = lookup_count

    has_plus_all = bool(re.search(r"(^|\s)\+all\b", spf_record)) or bool(
        re.search(r"(^|\s)all\b", spf_record)
        and not re.search(r"[-~?]all\b", spf_record)
    )
    result["spf_has_plus_all"] = has_plus_all

    result["spf_valid"] = (lookup_count <= 10) and (not has_plus_all)
    return result


# ------------------------------------------------------------------
# DKIM
# ------------------------------------------------------------------

def audit_dkim(domain, mx_provider):
    """Return dict berisi status DKIM untuk satu domain, dengan tiga
    kategori: Confirmed, Not Confirmed, atau Inconclusive."""
    result = {
        "dkim_status": "Inconclusive",
        "dkim_selector_found": "",
    }
    for selector in DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        records = query_txt(name)
        for rec in records:
            if "v=dkim1" in rec.lower() or "p=" in rec.lower():
                result["dkim_status"] = "Confirmed"
                result["dkim_selector_found"] = selector
                return result

    # Tidak ketemu di selector umum. Statusnya Not Confirmed HANYA
    # kalau kita cukup yakin sudah tahu provider mail-nya (karena
    # kalau providernya dikenal, selector defaultnya biasanya sudah
    # masuk daftar di atas). Kalau provider tidak dikenali, ini tetap
    # Inconclusive, bukan Not Confirmed, karena selector aslinya bisa
    # jadi memang bukan yang kita coba.
    if mx_provider in ("Google Workspace", "Microsoft 365", "Zoho Mail"):
        result["dkim_status"] = "Not Confirmed"
    else:
        result["dkim_status"] = "Inconclusive"

    return result


# ------------------------------------------------------------------
# DMARC
# ------------------------------------------------------------------

def audit_dmarc(domain):
    """Return dict berisi status DMARC untuk satu domain."""
    result = {
        "dmarc_present": False,
        "dmarc_record": "",
        "dmarc_policy": "",
        "dmarc_subdomain_policy": "",
    }
    records = query_txt(f"_dmarc.{domain}")
    dmarc_records = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dmarc_records:
        return result

    record = dmarc_records[0]
    result["dmarc_present"] = True
    result["dmarc_record"] = record

    p_match = re.search(r"\bp=([a-zA-Z]+)", record)
    sp_match = re.search(r"\bsp=([a-zA-Z]+)", record)
    result["dmarc_policy"] = p_match.group(1).lower() if p_match else ""
    result["dmarc_subdomain_policy"] = sp_match.group(1).lower() if sp_match else ""
    return result


# ------------------------------------------------------------------
# MX / provider
# ------------------------------------------------------------------

def identify_mx_provider(domain):
    """Return (mx_hosts_str, provider_name)."""
    mx_hosts = query_mx(domain)
    if not mx_hosts:
        return "", "No MX / Unidentified"

    combined = " ".join(mx_hosts)
    for pattern, provider in MX_PROVIDER_PATTERNS:
        if re.search(pattern, combined):
            return "; ".join(mx_hosts), provider

    return "; ".join(mx_hosts), "Unidentified / Self-hosted"


# ------------------------------------------------------------------
# Klasifikasi maturity (mengikuti Tabel I di paper)
# ------------------------------------------------------------------

def classify_maturity(spf, dkim_status, dmarc):
    """Return (level:int, name:str) sesuai skema 6 level di paper.

    Aturan penting: DKIM Inconclusive tetap dihitung "ada" untuk
    keperluan mencapai level 3 (Authenticated), tapi TIDAK PERNAH
    bisa membawa domain ke level 4 atau 5, karena level tersebut
    mengklaim enforcement yang mensyaratkan DKIM benar-benar
    terverifikasi (Confirmed), bukan sekadar tidak diketahui."""
    spf_present = spf["spf_present"]
    spf_valid = spf["spf_valid"]
    spf_ok = spf_present and spf_valid and not spf["spf_has_plus_all"]

    dmarc_present = dmarc["dmarc_present"]
    policy = dmarc["dmarc_policy"]
    sp_policy = dmarc["dmarc_subdomain_policy"] or policy

    dkim_confirmed = dkim_status == "Confirmed"
    dkim_inconclusive = dkim_status == "Inconclusive"
    dkim_broad = dkim_confirmed or dkim_inconclusive  # khusus gate level 3

    has_any = spf_present or dkim_confirmed or dmarc_present
    if not has_any:
        return 0, "Unprotected"

    all_three_broad = spf_present and dkim_broad and dmarc_present

    if (all_three_broad and dkim_confirmed and spf_ok
            and policy == "reject" and sp_policy in ("reject", "quarantine")):
        return 5, "Strong Enforcement"

    if all_three_broad and dkim_confirmed and spf_valid and policy == "quarantine":
        return 4, "Enforced"

    if all_three_broad:
        # Termasuk kasus DKIM Inconclusive yang sengaja dibatasi di
        # sini walau SPF/DMARC saja sudah cukup kuat untuk level 4/5,
        # dan kasus SPF tidak valid (misalnya karena +all) yang gagal
        # syarat level 4/5 di atas meski ketiga sinyal ada.
        return 3, "Authenticated"

    two_of_three = sum([spf_present, dkim_confirmed, dmarc_present]) >= 2
    if two_of_three:
        return 2, "Partial"

    if spf_present or dkim_confirmed:
        return 1, "Basic"

    return 0, "Unprotected"


# ------------------------------------------------------------------
# Program utama
# ------------------------------------------------------------------

def audit_domain(domain, sector):
    mx_hosts, mx_provider = identify_mx_provider(domain)
    spf = audit_spf(domain)
    dkim = audit_dkim(domain, mx_provider)
    dmarc = audit_dmarc(domain)

    level, level_name = classify_maturity(spf, dkim["dkim_status"], dmarc)

    return {
        "domain": domain,
        "sector": sector,
        "mx_hosts": mx_hosts,
        "mx_provider": mx_provider,
        "spf_present": spf["spf_present"],
        "spf_valid": spf["spf_valid"],
        "spf_lookup_count": spf["spf_lookup_count"],
        "spf_has_plus_all": spf["spf_has_plus_all"],
        "dkim_status": dkim["dkim_status"],
        "dkim_selector_found": dkim["dkim_selector_found"],
        "dmarc_present": dmarc["dmarc_present"],
        "dmarc_policy": dmarc["dmarc_policy"],
        "dmarc_subdomain_policy": dmarc["dmarc_subdomain_policy"],
        "maturity_level": level,
        "maturity_name": level_name,
    }


def main():
    if len(sys.argv) < 3:
        print("Cara pakai: python3 audit_email_auth.py domains.csv hasil_audit.csv")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    with open(input_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        domains = [(row["domain"].strip(), row["sector"].strip()) for row in reader]

    print(f"Memulai audit untuk {len(domains)} domain...\n")

    fieldnames = [
        "domain", "sector", "mx_hosts", "mx_provider",
        "spf_present", "spf_valid", "spf_lookup_count", "spf_has_plus_all",
        "dkim_status", "dkim_selector_found",
        "dmarc_present", "dmarc_policy", "dmarc_subdomain_policy",
        "maturity_level", "maturity_name",
    ]

    results = []
    with open(output_path, "w", newline="", encoding="utf-8") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=fieldnames)
        writer.writeheader()

        for i, (domain, sector) in enumerate(domains, start=1):
            print(f"[{i}/{len(domains)}] Mengaudit {domain} ({sector}) ...", end=" ")
            try:
                row = audit_domain(domain, sector)
                writer.writerow(row)
                out_f.flush()
                results.append(row)
                print(f"selesai -> level {row['maturity_level']} ({row['maturity_name']})")
            except Exception as e:
                print(f"GAGAL: {e}")
            time.sleep(DELAY_BETWEEN_DOMAINS)

    print(f"\nSelesai. Hasil disimpan ke {output_path}\n")
    print_summary(results)


def print_summary(results):
    if not results:
        return
    total = len(results)
    print("=" * 50)
    print("RINGKASAN")
    print("=" * 50)

    spf_count = sum(1 for r in results if r["spf_present"])
    dkim_count = sum(1 for r in results if r["dkim_status"] == "Confirmed")
    dmarc_count = sum(1 for r in results if r["dmarc_present"])

    print(f"Total domain diaudit : {total}")
    print(f"SPF ditemukan        : {spf_count} ({spf_count/total*100:.1f}%)")
    print(f"DKIM Confirmed       : {dkim_count} ({dkim_count/total*100:.1f}%)")
    print(f"DMARC ditemukan      : {dmarc_count} ({dmarc_count/total*100:.1f}%)")
    print()

    print("Distribusi maturity level:")
    for level in range(6):
        names = {0: "Unprotected", 1: "Basic", 2: "Partial",
                  3: "Authenticated", 4: "Enforced", 5: "Strong Enforcement"}
        count = sum(1 for r in results if r["maturity_level"] == level)
        print(f"  Level {level} ({names[level]:<18}): {count} domain ({count/total*100:.1f}%)")

    print()
    print("Per sektor:")
    sectors = sorted(set(r["sector"] for r in results))
    for sector in sectors:
        sector_results = [r for r in results if r["sector"] == sector]
        n = len(sector_results)
        avg_level = sum(r["maturity_level"] for r in sector_results) / n
        print(f"  {sector}: {n} domain, rata-rata maturity level = {avg_level:.2f}")


if __name__ == "__main__":
    main()
