# extract_features.py — FINAL STABLE VERSION (Windows Compatible)
import pyshark
import pandas as pd
import argparse, json, os, time, math, asyncio
from datetime import datetime
from collections import Counter
from tqdm import tqdm
import requests
from geoip2.database import Reader as GeoIPReader

# --------------------------
# CONFIG
# --------------------------
VT_API_KEY = None  # Add your VirusTotal API key if available
WHOIS_ENABLED = False
VT_ENABLED = False if VT_API_KEY is None else True
ENRICH_CACHE = "cache_enrich.json"
OUTPUT_CSV = "features_output.csv"

# GeoIP databases
GEOIP_CITY_DB = "GeoLite2-City.mmdb"
GEOIP_ASN_DB = "GeoLite2-ASN.mmdb"

geo_reader_city = GeoIPReader(GEOIP_CITY_DB) if os.path.exists(GEOIP_CITY_DB) else None
geo_reader_asn = GeoIPReader(GEOIP_ASN_DB) if os.path.exists(GEOIP_ASN_DB) else None

# --------------------------
# Utilities
# --------------------------
def entropy(s: str):
    if not s:
        return 0.0
    freqs = Counter(s)
    l = len(s)
    return -sum((n / l) * math.log2(n / l) for n in freqs.values())

def load_cache():
    cache = {}
    if os.path.exists(ENRICH_CACHE):
        with open(ENRICH_CACHE, "r", encoding="utf8") as f:
            try:
                cache = json.load(f)
            except json.JSONDecodeError:
                cache = {}
    for sec in ["vt", "whois", "geoip", "tls"]:
        if sec not in cache:
            cache[sec] = {}
    return cache

def save_cache(cache):
    with open(ENRICH_CACHE, "w", encoding="utf8") as f:
        json.dump(cache, f, indent=2)

cache = load_cache()

# --------------------------
# Enrichment helpers
# --------------------------
def vt_lookup(domain):
    """VirusTotal lookup with caching."""
    if not VT_ENABLED:
        return {}
    if domain in cache["vt"]:
        return cache["vt"][domain]
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code == 200:
            data = r.json()
            result = {
                "vt_categories": data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {}),
                "vt_last_analysis_date": data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_date"),
            }
        else:
            result = {"error": f"status_{r.status_code}"}
    except Exception as e:
        result = {"error": str(e)}

    cache["vt"][domain] = result
    save_cache(cache)
    time.sleep(1.5)
    return result

def whois_lookup(domain):
    """Placeholder WHOIS lookup with caching."""
    if not WHOIS_ENABLED:
        return {}
    if domain in cache["whois"]:
        return cache["whois"][domain]
    result = {"whois_raw": None}
    cache["whois"][domain] = result
    save_cache(cache)
    return result

def geoip_lookup(ip_addr):
    """GeoIP (City + ASN) lookup with caching."""
    if not ip_addr:
        return {}
    if ip_addr in cache["geoip"]:
        return cache["geoip"][ip_addr]
    result = {}
    try:
        if geo_reader_city:
            city_resp = geo_reader_city.city(ip_addr)
            result["country"] = city_resp.country.name
            result["city"] = city_resp.city.name
        if geo_reader_asn:
            asn_resp = geo_reader_asn.asn(ip_addr)
            result["asn"] = f"AS{asn_resp.autonomous_system_number} {asn_resp.autonomous_system_organization}"
    except Exception as e:
        result["error"] = str(e)
    cache["geoip"][ip_addr] = result
    save_cache(cache)
    return result

# --------------------------
# Packet parsing
# --------------------------
def parse_pcap(pcap_file, output_csv=OUTPUT_CSV, max_packets=None):
    # ✅ Fix for Windows asyncio issue
    try:
        asyncio.set_event_loop(asyncio.new_event_loop())
    except Exception:
        pass

    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
    rows = []
    count = 0

    for pkt in tqdm(cap, desc="Processing packets"):
        try:
            count += 1
            if max_packets and count > max_packets:
                break

            ts = float(pkt.sniff_timestamp)
            ts_iso = datetime.utcfromtimestamp(ts).isoformat()
            frame_len = getattr(pkt, "length", "") or getattr(pkt, "frame_len", "")
            src_ip = (
                pkt.ip.src
                if hasattr(pkt, "ip") and hasattr(pkt.ip, "src")
                else getattr(pkt, "ipv6.src", "")
                if hasattr(pkt, "ipv6")
                else ""
            )
            dst_ip = (
                pkt.ip.dst
                if hasattr(pkt, "ip") and hasattr(pkt.ip, "dst")
                else getattr(pkt, "ipv6.dst", "")
                if hasattr(pkt, "ipv6")
                else ""
            )

            src_port, dst_port, proto = "", "", ""
            if hasattr(pkt, "tcp"):
                proto = "TCP"
                src_port = getattr(pkt.tcp, "srcport", "")
                dst_port = getattr(pkt.tcp, "dstport", "")
            elif hasattr(pkt, "udp"):
                proto = "UDP"
                src_port = getattr(pkt.udp, "srcport", "")
                dst_port = getattr(pkt.udp, "dstport", "")
            elif hasattr(pkt, "icmp"):
                proto = "ICMP"
            else:
                proto = pkt.highest_layer if hasattr(pkt, "highest_layer") else ""

            # GeoIP enrichment
            geo_src = geoip_lookup(src_ip)
            geo_dst = geoip_lookup(dst_ip)

            row = {
                "pcap_file": os.path.basename(pcap_file),
                "packet_index": count,
                "ts": ts,
                "ts_iso": ts_iso,
                "frame_len": frame_len,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "geoip_src_country": geo_src.get("country", ""),
                "geoip_src_asn": geo_src.get("asn", ""),
                "geoip_dst_country": geo_dst.get("country", ""),
                "geoip_dst_asn": geo_dst.get("asn", ""),
            }

            # DNS Layer
            if "DNS" in pkt:
                try:
                    dns = pkt.dns
                    qname = getattr(dns, "qry_name", "")
                    qtype = getattr(dns, "qry_type", "")
                    resp_code = getattr(dns, "resp_code", "")
                    a_record = getattr(dns, "a", "")
                    a_ttl = getattr(dns, "a_ttl", "")

                    row.update(
                        {
                            "is_dns": 1,
                            "dns_qname": qname,
                            "dns_qtype": qtype,
                            "dns_resp_code": resp_code,
                            "dns_a_record": a_record,
                            "dns_a_ttl": a_ttl,
                            "dns_qname_length": len(qname),
                            "dns_qname_entropy": entropy(qname),
                        }
                    )

                    # enrichment
                    if qname:
                        domain = qname.strip().lower().rstrip(".")
                        vt = vt_lookup(domain) if VT_ENABLED else {}
                        who = whois_lookup(domain) if WHOIS_ENABLED else {}
                        row["enrich_vt"] = json.dumps(vt)
                        row["enrich_whois"] = json.dumps(who)
                except Exception:
                    row["is_dns"] = 1
            else:
                row["is_dns"] = 0

            # HTTP Layer
            if hasattr(pkt, "http"):
                try:
                    http = pkt.http
                    row.update(
                        {
                            "is_http": 1,
                            "http_method": getattr(http, "request_method", ""),
                            "http_host": getattr(http, "host", ""),
                            "http_uri": getattr(http, "request_uri", ""),
                            "http_user_agent": getattr(http, "user_agent", ""),
                            "http_response_code": getattr(http, "response_code", ""),
                        }
                    )
                except Exception:
                    row["is_http"] = 1
            else:
                row["is_http"] = 0

            # TLS Layer
            tls_layer = pkt.ssl if hasattr(pkt, "ssl") else pkt.tls if hasattr(pkt, "tls") else None
            if tls_layer:
                try:
                    sni = getattr(tls_layer, "handshake_extensions_server_name", "") or getattr(tls_layer, "server_name", "")
                    cert_issuer = getattr(pkt, "x509ce_issuer", "")
                    fingerprint = getattr(tls_layer, "handshake_certificate_sha1", "")
                    tls_key = fingerprint or sni or dst_ip
                    tls_info = {}
                    if fingerprint and fingerprint in cache["tls"]:
                        tls_info = cache["tls"][fingerprint]
                    elif fingerprint:
                        tls_info = {
                            "issuer": cert_issuer,
                            "subject": getattr(tls_layer, "handshake_certificate_subject", ""),
                            "not_before": getattr(tls_layer, "handshake_certificate_valid_from", ""),
                            "not_after": getattr(tls_layer, "handshake_certificate_valid_to", ""),
                        }
                        cache["tls"][fingerprint] = tls_info
                        save_cache(cache)
                    row.update(
                        {
                            "is_tls": 1,
                            "tls_sni": sni,
                            "tls_cert_issuer": cert_issuer,
                            "tls_cert_fingerprint": fingerprint,
                            "tls_cached_info": json.dumps(tls_info),
                        }
                    )
                except Exception:
                    row["is_tls"] = 1
            else:
                row["is_tls"] = 0

            # TCP flags
            row["tcp_flags"] = getattr(pkt.tcp, "flags", "") if hasattr(pkt, "tcp") else ""

            rows.append(row)

            if len(rows) >= 5000:
                df = pd.DataFrame(rows)
                if not os.path.exists(output_csv):
                    df.to_csv(output_csv, index=False)
                else:
                    df.to_csv(output_csv, index=False, mode="a", header=False)
                rows = []

        except Exception as e:
            print(f"Packet {count} parse error: {e}")
            continue

    if rows:
        df = pd.DataFrame(rows)
        if not os.path.exists(output_csv):
            df.to_csv(output_csv, index=False)
        else:
            df.to_csv(output_csv, index=False, mode="a", header=False)

    cap.close()
    print(f"Processed {count} packets. Output: {output_csv}")

# --------------------------
# CLI
# --------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract packet features via pyshark and output CSV.")
    parser.add_argument("--pcap", "-r", required=True, help="Path to PCAP file")
    parser.add_argument("--out", "-o", default=OUTPUT_CSV, help="Output CSV file")
    parser.add_argument("--max", type=int, default=0, help="Max packets to process (0 = all)")
    args = parser.parse_args()
    parse_pcap(args.pcap, args.out, max_packets=(args.max or None))
