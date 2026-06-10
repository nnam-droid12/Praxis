"""
gen_scenario.py - Praxis synthetic attack dataset generator.

Produces 4 ingestable log files (one per sourcetype) plus a HEC-format
combined file, containing:
  - The planted APT campaign: 5 stages, all tied to user j.okonkwo,
    spanning a 22-minute window, with a host pivot WKSTN-OKONKWO -> FS01.
  - 2 false-alarm scenarios (for the Devil's Advocate agent).
  - 200 benign noise events spread across the last 24 hours.

Run:
    python data/gen_scenario.py

Output:
    data/events/praxis_auth.log
    data/events/praxis_network.log
    data/events/praxis_endpoint.log
    data/events/praxis_egress.log
    data/events/hec_events.jsonl
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(1337)

OUT_DIR = Path(__file__).parent / "events"
OUT_DIR.mkdir(parents=True, exist_ok=True)

NOW = datetime.now()

events: list[dict] = []  # {"time": datetime, "sourcetype": str, "fields": dict}


def add(t: datetime, sourcetype: str, **fields) -> None:
    events.append({"time": t, "sourcetype": sourcetype, "fields": fields})


# ---------------------------------------------------------------------------
# THE PLANTED CAMPAIGN - j.okonkwo, 22-minute window, 5 stages
# ---------------------------------------------------------------------------
CAMPAIGN_START = NOW - timedelta(minutes=35)

# Stage 1 - Identity: impossible travel login (London -> Moscow in 11 min)
add(CAMPAIGN_START, "praxis:auth",
    user="j.okonkwo", app="okta", action="login", status="success",
    auth_method="password", src_ip="185.220.101.45", src_country="RU", src_city="Moscow",
    host="WKSTN-OKONKWO", prev_country="GB", prev_city="London",
    prev_login_minutes_ago=11, geo_velocity_kmh=13636)

# Stage 2 - Identity: MFA fatigue (5 push denials + 1 approval within ~80s)
mfa_start = CAMPAIGN_START + timedelta(minutes=2, seconds=30)
for i in range(5):
    add(mfa_start + timedelta(seconds=i * 12), "praxis:auth",
        user="j.okonkwo", app="okta", action="mfa_challenge", status="denied",
        auth_method="mfa_push", src_ip="185.220.101.45", src_country="RU", src_city="Moscow",
        host="WKSTN-OKONKWO", mfa_attempt_number=i + 1)
add(mfa_start + timedelta(seconds=68), "praxis:auth",
    user="j.okonkwo", app="okta", action="mfa_challenge", status="approved",
    auth_method="mfa_push", src_ip="185.220.101.45", src_country="RU", src_city="Moscow",
    host="WKSTN-OKONKWO", mfa_attempt_number=6)

# Stage 3 - Lateral Movement: SMB then RDP from workstation to file server
lat_time = CAMPAIGN_START + timedelta(minutes=8)
add(lat_time, "praxis:network",
    user="j.okonkwo", src_host="WKSTN-OKONKWO", dest_host="FS01",
    src_ip="10.10.12.45", dest_ip="10.10.20.10", protocol="SMB", dest_port=445,
    action="connection_established", dest_role="file_server", bytes_in=18420, bytes_out=612000)
add(lat_time + timedelta(seconds=40), "praxis:network",
    user="j.okonkwo", src_host="WKSTN-OKONKWO", dest_host="FS01",
    src_ip="10.10.12.45", dest_ip="10.10.20.10", protocol="RDP", dest_port=3389,
    action="connection_established", dest_role="file_server", bytes_in=220000, bytes_out=4400000)

# Stage 4 - Persistence: new scheduled task created on the file server
add(CAMPAIGN_START + timedelta(minutes=14), "praxis:endpoint",
    user="j.okonkwo", host="FS01", action="scheduled_task_created",
    task_name="WindowsTelemetryUpdate",
    task_command=r"powershell.exe -nop -w hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
    task_trigger="daily 03:00", parent_process="schtasks.exe", signed="false")

# Stage 5 - Exfiltration: DNS tunneling (15 queries) + large outbound transfer
DNS_TUNNEL_DOMAIN = "cdn-update-sync.xyz"
dns_start = CAMPAIGN_START + timedelta(minutes=20)
for i in range(15):
    subdomain = "".join(random.choices("abcdef0123456789", k=32))
    add(dns_start + timedelta(seconds=i * 4), "praxis:egress",
        user="j.okonkwo", src_host="FS01", src_ip="10.10.20.10", dest_ip="203.0.113.77",
        dest_domain=f"{subdomain}.{DNS_TUNNEL_DOMAIN}", protocol="DNS", query_type="TXT",
        bytes_out=random.randint(180, 240), dest_reputation="low",
        subdomain_entropy=round(random.uniform(3.8, 4.2), 2))
add(CAMPAIGN_START + timedelta(minutes=22), "praxis:egress",
    user="j.okonkwo", src_host="FS01", src_ip="10.10.20.10", dest_ip="203.0.113.77",
    dest_domain=DNS_TUNNEL_DOMAIN, protocol="HTTPS", bytes_out=482000000, dest_reputation="low")


# ---------------------------------------------------------------------------
# FALSE ALARM 1 - Traveling executive (timezone-skewed velocity calc, but
# a confirmed travel record explains it). Crosses the alert threshold.
# ---------------------------------------------------------------------------
add(NOW - timedelta(hours=19), "praxis:auth",
    user="m.okafor", app="okta", action="login", status="success", auth_method="mfa_totp",
    src_ip="81.2.69.142", src_country="GB", src_city="London", host="LAPTOP-OKAFOR")
add(NOW - timedelta(hours=1), "praxis:auth",
    user="m.okafor", app="okta", action="login", status="success", auth_method="mfa_totp",
    src_ip="175.45.16.88", src_country="SG", src_city="Singapore", host="LAPTOP-OKAFOR",
    prev_country="GB", prev_city="London", prev_login_minutes_ago=540,
    geo_velocity_kmh=1206, travel_record="CONFIRMED-TRV-2026-0091")


# ---------------------------------------------------------------------------
# FALSE ALARM 2 - Legitimate IT maintenance scheduled task (signed binary,
# tied to an approved change ticket).
# ---------------------------------------------------------------------------
add(NOW - timedelta(hours=3), "praxis:endpoint",
    user="it.admin", host="FS02", action="scheduled_task_created",
    task_name="CHG0045231_PatchDeploy",
    task_command=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File \\corp\sysvol\scripts\patch_deploy.ps1",
    task_trigger="once 02:30", parent_process="mmc.exe", signed="true", change_ticket="CHG0045231")


# ---------------------------------------------------------------------------
# BENIGN NOISE - 200 events across all 4 sourcetypes, spread over 24h
# ---------------------------------------------------------------------------
BENIGN_USERS = ["a.smith", "r.patel", "l.garcia", "k.muller", "t.nguyen", "s.dubois", "h.yamamoto", "e.osei"]
BENIGN_HOSTS = {u: f"WKSTN-{u.split('.')[1].upper()}" for u in BENIGN_USERS}
NORMAL_LOCATIONS = [("GB", "London"), ("GB", "Manchester"), ("US", "New York")]
INTERNAL_SERVERS = ["FS01", "FS02", "APP01", "WEB01", "DC01", "DB01"]
GOOD_DOMAINS = ["github.com", "microsoft.com", "google.com", "slack.com", "zoom.us", "salesforce.com"]
ROUTINE_TASKS = ["GoogleUpdateTaskMachineCore", "AdobeAAMUpdater", "OneDriveStandaloneUpdate", "MicrosoftEdgeUpdateTaskMachineUA"]


def random_recent_time() -> datetime:
    return NOW - timedelta(seconds=random.randint(0, 24 * 3600))


for _ in range(50):
    user = random.choice(BENIGN_USERS)
    country, city = random.choice(NORMAL_LOCATIONS)
    add(random_recent_time(), "praxis:auth",
        user=user, app=random.choice(["okta", "vpn", "o365"]), action="login", status="success",
        auth_method=random.choice(["password", "mfa_push", "mfa_totp"]),
        src_ip=f"81.2.69.{random.randint(2, 254)}", src_country=country, src_city=city,
        host=BENIGN_HOSTS[user])

for _ in range(50):
    user = random.choice(BENIGN_USERS)
    proto, port, role = random.choice([("HTTPS", 443, "web_server"), ("SMB", 445, "file_server"), ("RPC", 135, "app_server")])
    add(random_recent_time(), "praxis:network",
        user=user, src_host=BENIGN_HOSTS[user], dest_host=random.choice(INTERNAL_SERVERS),
        src_ip=f"10.10.12.{random.randint(2, 254)}", dest_ip=f"10.10.20.{random.randint(2, 254)}",
        protocol=proto, dest_port=port, action="connection_established", dest_role=role,
        bytes_in=random.randint(1000, 50000), bytes_out=random.randint(1000, 50000))

for _ in range(50):
    user = random.choice(BENIGN_USERS)
    add(random_recent_time(), "praxis:endpoint",
        user=user, host=BENIGN_HOSTS[user], action="scheduled_task_created",
        task_name=random.choice(ROUTINE_TASKS),
        task_command=r"C:\Program Files\Common Files\updater.exe", task_trigger="daily 09:00",
        parent_process="services.exe", signed="true")

for _ in range(50):
    user = random.choice(BENIGN_USERS)
    add(random_recent_time(), "praxis:egress",
        user=user, src_host=BENIGN_HOSTS[user],
        src_ip=f"10.10.12.{random.randint(2, 254)}",
        dest_ip=f"{random.randint(20, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        dest_domain=random.choice(GOOD_DOMAINS), protocol="HTTPS",
        bytes_out=random.randint(2000, 200000), dest_reputation="high")


# ---------------------------------------------------------------------------
# WRITE OUTPUT
# ---------------------------------------------------------------------------
def fmt_time(t: datetime) -> str:
    return t.strftime("%Y-%m-%d %H:%M:%S")


def fmt_kv(fields: dict) -> str:
    parts = []
    for k, v in fields.items():
        if isinstance(v, str) and (" " in v or "\\" in v):
            v = f'"{v}"'
        parts.append(f"{k}={v}")
    return " ".join(parts)


SOURCETYPES = ["praxis:auth", "praxis:network", "praxis:endpoint", "praxis:egress"]

for st in SOURCETYPES:
    rows = sorted((e for e in events if e["sourcetype"] == st), key=lambda e: e["time"])
    out_path = OUT_DIR / f"{st.replace(':', '_')}.log"
    with out_path.open("w", encoding="utf-8") as f:
        for e in rows:
            f.write(f"{fmt_time(e['time'])} {fmt_kv(e['fields'])}\n")
    print(f"Wrote {len(rows)} events -> {out_path}")

hec_path = OUT_DIR / "hec_events.jsonl"
with hec_path.open("w", encoding="utf-8") as f:
    for e in sorted(events, key=lambda e: e["time"]):
        # Set HEC's metadata "host" explicitly, otherwise Splunk falls back
        # to the HTTP Host header (e.g. "localhost:8088"), which shadows any
        # in-event host/src_host field of the same name at search time.
        host = e["fields"].get("host") or e["fields"].get("src_host")
        record = {
            "time": e["time"].timestamp(),
            "host": host,
            "sourcetype": e["sourcetype"],
            "index": "main",
            "event": fmt_kv(e["fields"]),
        }
        f.write(json.dumps(record) + "\n")
print(f"Wrote {len(events)} events -> {hec_path}")


# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
print("\n=== Campaign window ===")
print(f"Start: {fmt_time(CAMPAIGN_START)}")
print(f"End:   {fmt_time(CAMPAIGN_START + timedelta(minutes=22))}")
print("User:  j.okonkwo")
print("Host pivot: WKSTN-OKONKWO -> FS01")
print(f"\nTotal events: {len(events)}")
for st in SOURCETYPES:
    print(f"  {st}: {sum(1 for e in events if e['sourcetype'] == st)}")
