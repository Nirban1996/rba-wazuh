import os, math, statistics
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

BASELINE_HOURS = int(os.getenv("RBA_BASELINE_WINDOW_HOURS", "6"))
K_SIGMA = float(os.getenv("RBA_K_SIGMA", "3"))

half_life_seconds = HALF_LIFE_MIN * 60.0
lam = math.log(2.0) / half_life_seconds

STATE_INDEX = "rba-entity-state"

def iso_to_dt(s: str) -> datetime:
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
                "mu": {"type": "float"},
                "sigma": {"type": "float"},
                "k": {"type": "float"},
                "threshold": {"type": "float"},
                "last_event_ts": {"type": "date"},
                "half_life_minutes": {"type": "float"},
                "time_window_hours": {"type": "integer"},
                "baseline_window_hours": {"type": "integer"},
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

def ensure_snapshot_index(index_name: str):
    if client.indices.exists(index=index_name):
        return
    body = {
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "entity": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "name": {"type": "keyword"},
                    }
                },
                "risk": {"type": "float"},
                "mu": {"type": "float"},
                "sigma": {"type": "float"},
                "k": {"type": "float"},
                "threshold": {"type": "float"},
            }
        },
    }
    client.indices.create(index=index_name, body=body)
    print(f"Created index: {index_name}")

def event_risk(rule_level: int) -> float:
    return float(2 * rule_level)

def compute_baseline_from_snapshots(entity_id: str) -> tuple[float, float]:
    # Pull last BASELINE_HOURS of snapshots for this entity
    snap_index = "rba-risk-snapshots-*"
    q = {
        "size": 5000,
        "_source": ["risk"],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"entity.id": entity_id}},
                    {"range": {"@timestamp": {"gte": f"now-{BASELINE_HOURS}h", "lte": "now"}}},
                ]
            }
        },
    }
    try:
        resp = client.search(index=snap_index, body=q)
        vals = [h["_source"]["risk"] for h in resp["hits"]["hits"] if "risk" in h["_source"]]
    except Exception:
        vals = []

    if len(vals) < 5:
        # If not enough data yet, use a safe default baseline
        # (mu=0, sigma=5 gives threshold ~15 when k=3)
        return 0.0, 5.0

    mu = float(statistics.mean(vals))
    sigma = float(statistics.pstdev(vals))  # stable even for small sets
    if sigma < 0.1:
        sigma = 0.1
    return mu, sigma

def main():
    ensure_state_index()

    # --- 1) Compute risk from Wazuh alerts (last TW_HOURS) ---
    query = {
        "size": QUERY_SIZE,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "_source": [
            "@timestamp",
            "agent.id",
            "agent.name",
            "rule.id",
            "rule.level",
            "rule.groups",
            "rule.description",
        ],
        "query": {"range": {"@timestamp": {"gte": f"now-{TW_HOURS}h", "lte": "now"}}},
    }

    resp = client.search(index="wazuh-alerts-*", body=query)
    hits = resp["hits"]["hits"]
    print(f"Fetched {len(hits)} alerts from last {TW_HOURS}h (size cap={QUERY_SIZE}).")

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

        prev_t = state[eid]["last_ts"]
        dt = max(0.0, (t - prev_t).total_seconds())
        decayed = state[eid]["risk"] * math.exp(-lam * dt)

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

    # --- 2) For each entity, compute baseline mu/sigma from snapshots and calculate threshold ---
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    snap_index_today = f"rba-risk-snapshots-{now_dt.strftime('%Y.%m.%d')}"
    ensure_snapshot_index(snap_index_today)

    updated = 0
    for eid, st in state.items():
        mu, sigma = compute_baseline_from_snapshots(eid)
        threshold = mu + K_SIGMA * sigma

        # update state doc
        doc = {
            "@timestamp": now,
            "updated_at": now,
            "entity": {"id": eid, "type": "host", "name": st["name"]},
            "risk": st["risk"],
            "mu": mu,
            "sigma": sigma,
            "k": K_SIGMA,
            "threshold": threshold,
            "last_event_ts": st["last_ts"].astimezone(timezone.utc).isoformat(),
            "half_life_minutes": HALF_LIFE_MIN,
            "time_window_hours": TW_HOURS,
            "baseline_window_hours": BASELINE_HOURS,
            "last_rule": st["last_rule"],
        }
        client.index(index=STATE_INDEX, id=eid, body=doc, refresh=True)

        # write a snapshot point for charts
        snap_doc = {
            "@timestamp": now,
            "entity": {"id": eid, "type": "host", "name": st["name"]},
            "risk": st["risk"],
            "mu": mu,
            "sigma": sigma,
            "k": K_SIGMA,
            "threshold": threshold,
        }
        client.index(index=snap_index_today, body=snap_doc, refresh=True)

        updated += 1

    print(f"Updated {updated} entity states + wrote {updated} snapshots.")

    # print top 5 by risk with threshold
    top = sorted(state.items(), key=lambda kv: kv[1]["risk"], reverse=True)[:5]
    print("\nTop entities by risk (this run):")
    for eid, st in top:
        # fetch threshold from stored doc (quick get)
        cur = client.get(index=STATE_INDEX, id=eid)["_source"]
        print(f"  {eid} risk={st['risk']:.2f}  θ={cur['threshold']:.2f}  μ={cur['mu']:.2f} σ={cur['sigma']:.2f}")

if __name__ == "__main__":
    main()
