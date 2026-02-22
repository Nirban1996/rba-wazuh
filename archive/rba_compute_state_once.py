import os, math
from datetime import datetime, timezone
from dotenv import load_dotenv
from opensearchpy import OpenSearch

load_dotenv()

# --- OpenSearch connection ---
host = os.getenv("OS_HOST")
port = int(os.getenv("OS_PORT", "9200"))
user = os.getenv("OS_USER")
pwd = os.getenv("OS_PASS")
use_ssl = os.getenv("OS_SSL", "true").lower() == "true"
verify_certs = os.getenv("OS_VERIFY_CERTS", "false").lower() == "true"

client = OpenSearch(
    hosts=[{"host": host, "port": port}],
    http_auth=(user, pwd),
    use_ssl=use_ssl,
    verify_certs=verify_certs,
    ssl_show_warn=False,
)

# --- RBA settings ---
TW_HOURS = int(os.getenv("RBA_TIME_WINDOW_HOURS", "24"))
HALF_LIFE_MIN = float(os.getenv("RBA_HALF_LIFE_MINUTES", "240"))
QUERY_SIZE = int(os.getenv("RBA_QUERY_SIZE", "2000"))

# decay factor lambda from half-life: lambda = ln(2)/half_life_seconds
half_life_seconds = HALF_LIFE_MIN * 60.0
lam = math.log(2.0) / half_life_seconds

STATE_INDEX = "rba-entity-state"

def iso_to_dt(s: str) -> datetime:
    # Wazuh timestamps often look like: 2026-02-07T23:26:08.865+0000
    # Normalize +0000 -> +00:00 for fromisoformat
    if s.endswith("+0000"):
        s = s[:-5] + "+00:00"
    return datetime.fromisoformat(s)

def ensure_state_index():
    if client.indices.exists(index=STATE_INDEX):
        return
    body = {
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "updated_at": {"type": "date"},
                "entity": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "name": {"type": "keyword"},
                    }
                },
                "risk": {"type": "float"},
                "last_event_ts": {"type": "date"},
                "half_life_minutes": {"type": "float"},
                "time_window_hours": {"type": "integer"},
                "last_rule": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "level": {"type": "integer"},
                        "groups": {"type": "keyword"},
                        "description": {"type": "text"},
                    }
                },
            }
        },
    }
    client.indices.create(index=STATE_INDEX, body=body)
    print(f"Created index: {STATE_INDEX}")

def event_risk(rule_level: int) -> float:
    # PoC mapping: risk points from rule level
    # simple + visually effective for demos
    return float(2 * rule_level)

def main():
    ensure_state_index()

    # Pull alerts within the last Tw hours (date math)
    query = {
        "size": QUERY_SIZE,
        "sort": [{"@timestamp": {"order": "asc"}}],  # chronological for decay updates
        "_source": [
            "@timestamp",
            "agent.id",
            "agent.name",
            "rule.id",
            "rule.level",
            "rule.groups",
            "rule.description",
        ],
        "query": {
            "range": {
                "@timestamp": {
                    "gte": f"now-{TW_HOURS}h",
                    "lte": "now"
                }
            }
        },
    }

    resp = client.search(index="wazuh-alerts-*", body=query)
    hits = resp["hits"]["hits"]
    print(f"Fetched {len(hits)} alerts from last {TW_HOURS}h (size cap={QUERY_SIZE}).")

    # In-memory entity state for this run
    # state[eid] = {"risk": float, "last_ts": datetime, "name": str}
    state = {}

    for h in hits:
        src = h["_source"]
        ts_s = src.get("@timestamp")
        agent = src.get("agent", {})
        rule = src.get("rule", {})

        agent_id = agent.get("id")
        agent_name = agent.get("name", "unknown")
        rule_level = int(rule.get("level", 0))

        if not ts_s or not agent_id:
            continue

        t = iso_to_dt(ts_s)

        eid = f"host:{agent_id}"

        if eid not in state:
            state[eid] = {"risk": 0.0, "last_ts": t, "name": agent_name, "last_rule": None}

        # decay previous risk since last event
        prev_t = state[eid]["last_ts"]
        dt = max(0.0, (t - prev_t).total_seconds())
        decayed = state[eid]["risk"] * math.exp(-lam * dt)

        # add current event contribution
        inc = event_risk(rule_level)
        new_risk = decayed + inc

        state[eid]["risk"] = new_risk
        state[eid]["last_ts"] = t
        state[eid]["name"] = agent_name
        state[eid]["last_rule"] = {
            "id": rule.get("id"),
            "level": rule_level,
            "groups": rule.get("groups", []),
            "description": rule.get("description"),
        }

    now = datetime.now(timezone.utc).isoformat()

    # Write each entity state to OpenSearch
    updated = 0
    for eid, st in state.items():
        doc = {
            "@timestamp": now,
            "updated_at": now,
            "entity": {"id": eid, "type": "host", "name": st["name"]},
            "risk": st["risk"],
            "last_event_ts": st["last_ts"].astimezone(timezone.utc).isoformat(),
            "half_life_minutes": HALF_LIFE_MIN,
            "time_window_hours": TW_HOURS,
            "last_rule": st["last_rule"],
        }
        client.index(index=STATE_INDEX, id=eid, body=doc, refresh=True)
        updated += 1

    print(f"Updated {updated} entity risk profiles in {STATE_INDEX}.")

    # Print top 5 by risk
    top = sorted(state.items(), key=lambda kv: kv[1]["risk"], reverse=True)[:5]
    print("\nTop entities by risk (this run):")
    for eid, st in top:
        print(f"  {eid}  risk={st['risk']:.2f}  last={st['last_ts']}  name={st['name']}")

if __name__ == "__main__":
    main()
