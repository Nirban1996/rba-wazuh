#!/usr/bin/env python3
# rba_compute_snapshot_and_alert_once.py

import os
import math
import statistics
from datetime import datetime, timezone, timedelta
from math import isfinite

from dotenv import load_dotenv
from opensearchpy import OpenSearch


def agent_id_from_entity_id(entity_id: str) -> str:
    # "host:003" -> "003"
    try:
        return entity_id.split(":")[1].zfill(3)
    except Exception:
        return entity_id


def fetch_top_wazuh_rules(client, agent_id: str, alert_ts_iso: str, hours: int, size: int):
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"agent.id": agent_id}},
                    {"range": {"@timestamp": {"gte": f"{alert_ts_iso}||-{hours}h", "lte": alert_ts_iso}}},
                ]
            }
        },
        "aggs": {
            "top_rules": {
                "terms": {"field": "rule.id", "size": size},
                "aggs": {
                    "max_level": {"max": {"field": "rule.level"}},
                    "sample": {
                        "top_hits": {
                            "size": 1,
                            "_source": {"includes": ["rule.description", "rule.groups", "agent.name"]},
                        }
                    },
                },
            }
        },
    }

    resp = client.search(index="wazuh-alerts-*", body=body)
    buckets = resp.get("aggregations", {}).get("top_rules", {}).get("buckets", [])

    out = []
    for b in buckets:
        sample_hit = (b.get("sample", {}).get("hits", {}).get("hits") or [{}])[0]
        src = sample_hit.get("_source", {}) or {}
        rule = src.get("rule", {}) or {}
        agent = src.get("agent", {}) or {}

        max_level = float(b.get("max_level", {}).get("value") or 0.0)
        count = int(b.get("doc_count") or 0)

        out.append(
            {
                "rule_id": str(b.get("key")),
                "count": count,
                "max_level": max_level,
                "score": count * max_level,
                "description": rule.get("description"),
                "groups": rule.get("groups"),
                "agent_name": agent.get("name"),
            }
        )

    out.sort(key=lambda x: x["score"], reverse=True)
    return out


# =========================
# Env / OpenSearch
# =========================
load_dotenv()

host = os.getenv("OS_HOST")
port = int(os.getenv("OS_PORT", "9200"))
user = os.getenv("OS_USER")
pwd = os.getenv("OS_PASS")
use_ssl = os.getenv("OS_SSL", "true").lower() == "true"
verify_certs = os.getenv("OS_VERIFY_CERTS", "false").lower() == "true"

if not host:
    raise RuntimeError("OS_HOST is not set in environment (.env)")

client = OpenSearch(
    hosts=[{"host": host, "port": port}],
    http_auth=(user, pwd) if user or pwd else None,
    use_ssl=use_ssl,
    verify_certs=verify_certs,
    ssl_show_warn=False,
)

# =========================
# RBA settings
# =========================
TW_HOURS = int(os.getenv("RBA_TIME_WINDOW_HOURS", "24"))
HALF_LIFE_MIN = float(os.getenv("RBA_HALF_LIFE_MINUTES", "240"))
QUERY_SIZE = int(os.getenv("RBA_QUERY_SIZE", "2000"))

BASELINE_HOURS = int(os.getenv("RBA_BASELINE_WINDOW_HOURS", "168"))
K_SIGMA = float(os.getenv("RBA_K_SIGMA", "3"))
BASELINE_MIN_SNAPSHOTS = int(os.getenv("RBA_BASELINE_MIN_SNAPSHOTS", "30"))

DELTA_MIN = float(os.getenv("RBA_DELTA_MIN", "1"))
COOLDOWN_MIN = int(os.getenv("RBA_ALERT_COOLDOWN_MINUTES", "60"))
TOP_CONTRIB = int(os.getenv("RBA_TOP_CONTRIBUTORS", "5"))
MAX_ALERTS_PER_RUN = int(os.getenv("RBA_MAX_ALERTS_PER_RUN", "20"))

# --- Standardization + threshold control ---
MAX_SIGMA_MULTIPLIER = float(os.getenv("RBA_MAX_SIGMA_MULTIPLIER", "2.5"))
THRESHOLD_DECAY = float(os.getenv("RBA_THRESHOLD_DECAY", "0.97"))
MIN_THRESHOLD = float(os.getenv("RBA_MIN_THRESHOLD", "0.0"))
USE_DECAYED_THRESHOLD = os.getenv("RBA_USE_DECAYED_THRESHOLD", "true").lower() == "true"

half_life_seconds = HALF_LIFE_MIN * 60.0
lam = math.log(2.0) / half_life_seconds

STATE_INDEX = "rba-entity-state"


def iso_to_dt(s: str) -> datetime:
    # Handle "2026-02-18T02:45:06.055+0000" -> "+00:00"
    if s.endswith("+0000"):
        s = s[:-5] + "+00:00"
    return datetime.fromisoformat(s)


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
                "sigma_capped": {"type": "float"},
                "k": {"type": "float"},
                "threshold": {"type": "float"},
                "z": {"type": "float"},
                "ratio": {"type": "float"},
            }
        },
    }
    client.indices.create(index=index_name, body=body)
    print(f"Created index: {index_name}")


def ensure_alert_index(index_name: str):
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
                "threshold": {"type": "float"},
                "mu": {"type": "float"},
                "sigma": {"type": "float"},
                "sigma_capped": {"type": "float"},
                "k": {"type": "float"},
                "delta_risk": {"type": "float"},
                "z": {"type": "float"},
                "ratio": {"type": "float"},
                "time_window_hours": {"type": "integer"},
                "baseline_window_hours": {"type": "integer"},
                "half_life_minutes": {"type": "float"},
                "event_count_window": {"type": "integer"},
                "top_contributors": {
                    "type": "nested",
                    "properties": {
                        "ts": {"type": "date"},
                        "rule_id": {"type": "keyword"},
                        "level": {"type": "integer"},
                        "groups": {"type": "keyword"},
                        "risk_inc": {"type": "float"},
                        "desc": {"type": "text"},
                    },
                },
                "contributors_rules": {"type": "nested"},
                "contributors_rules_window_hours": {"type": "integer"},
            }
        },
    }
    client.indices.create(index=index_name, body=body)
    print(f"Created index: {index_name}")


def event_risk(rule_level: int) -> float:
    # PoC mapping: risk points from rule level
    return float(2 * int(rule_level))


def robust_mu_sigma(values: list[float]) -> tuple[float, float]:
    """
    Compute μ and σ robustly to prevent a single spike from exploding σ.
    - For small samples: MAD-based outlier filter
    - For larger samples: 10% trimmed sample
    """
    vals = [v for v in values if v is not None and isfinite(v)]
    if len(vals) < 5:
        return 0.0, 5.0  # fallback baseline

    vals.sort()

    # Large sample: 10% trim
    if len(vals) >= 20:
        trim = max(1, int(0.10 * len(vals)))
        core = vals[trim:-trim]
    else:
        # Small sample: MAD-based outlier filter
        med = statistics.median(vals)
        abs_dev = [abs(x - med) for x in vals]
        mad = statistics.median(abs_dev) if abs_dev else 0.0
        sigma_robust = 1.4826 * mad  # robust scale estimate

        if sigma_robust > 0:
            core = [x for x in vals if abs(x - med) <= 3.0 * sigma_robust]
            if len(core) < 5:
                core = vals
        else:
            core = vals

    mu = float(statistics.mean(core))
    sigma = float(statistics.pstdev(core))
    min_sigma = float(os.getenv("RBA_MIN_SIGMA", "0.1"))
    if sigma < min_sigma:
        sigma = min_sigma
    return mu, sigma


def compute_baseline_from_snapshots(entity_id: str) -> tuple[float, float, int]:
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
        hits = resp.get("hits", {}).get("hits", [])
        vals = [h["_source"]["risk"] for h in hits if "risk" in (h.get("_source") or {})]
    except Exception:
        vals = []

    n = len(vals)
    if n < 5:
        return 0.0, 5.0, n

    mu, sigma = robust_mu_sigma(vals)
    return mu, sigma, n


def get_previous_state(eid: str) -> dict:
    try:
        return client.get(index=STATE_INDEX, id=eid)["_source"]
    except Exception:
        return {}


def parse_last_alert_ts(prev: dict) -> datetime | None:
    ts = prev.get("last_alert_ts")
    if not ts:
        return None
    try:
        return iso_to_dt(ts).astimezone(timezone.utc)
    except Exception:
        return None


def main():
    # --- 1) Pull alerts in last TW hours ---
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
    hits = resp.get("hits", {}).get("hits", [])
    print(f"Fetched {len(hits)} alerts from last {TW_HOURS}h (size cap={QUERY_SIZE}).")

    # state[eid] = risk profile computed from events in window
    state: dict[str, dict] = {}

    for h in hits:
        src = h.get("_source", {}) or {}
        ts_s = src.get("@timestamp")
        agent = src.get("agent", {}) or {}
        rule = src.get("rule", {}) or {}

        agent_id = agent.get("id")
        agent_name = agent.get("name", "unknown")
        rule_level = int(rule.get("level", 0))

        if not ts_s or not agent_id:
            continue

        t = iso_to_dt(ts_s)
        eid = f"host:{agent_id}"
        eid = f"host:{agent_id}"

        # DEMO: ignore ubuntu noisy agent
        if eid == "host:000":
            continue

        if eid not in state:
            state[eid] = {
                "risk": 0.0,
                "last_ts": t,
                "name": agent_name,
                "event_count": 0,     # true count in TW
                "events_sample": [],  # capped list for explainability
                "last_rule": None,
            }

        prev_t = state[eid]["last_ts"]
        dt = max(0.0, (t - prev_t).total_seconds())
        decayed = state[eid]["risk"] * math.exp(-lam * dt)

        inc = event_risk(rule_level)
        new_risk = decayed + inc

        state[eid]["event_count"] += 1
        state[eid]["risk"] = new_risk
        state[eid]["last_ts"] = t
        state[eid]["name"] = agent_name
        state[eid]["last_rule"] = {
            "id": rule.get("id"),
            "level": rule_level,
            "groups": rule.get("groups", []),
            "description": rule.get("description"),
        }

        # store small contributor record
        state[eid]["events_sample"].append(
            {
                "ts": t.astimezone(timezone.utc).isoformat(),
                "rule_id": rule.get("id"),
                "level": rule_level,
                "groups": rule.get("groups", []),
                "risk_inc": inc,
                "desc": rule.get("description"),
            }
        )
        if len(state[eid]["events_sample"]) > 50:
            state[eid]["events_sample"] = state[eid]["events_sample"][-50:]

    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()

    snap_index_today = f"rba-risk-snapshots-{now_dt.strftime('%Y.%m.%d')}"
    alert_index_today = f"rba-alerts-{now_dt.strftime('%Y.%m.%d')}"
    ensure_snapshot_index(snap_index_today)
    ensure_alert_index(alert_index_today)

    alerts_written = 0
    states_updated = 0

    # --- 2) Update entity state + snapshots + generate RBA alerts ---
    # Sort entities by risk descending so we alert on top risky first
    for eid, st in sorted(state.items(), key=lambda kv: kv[1]["risk"], reverse=True):
        # Decay risk from last event time -> now (so decay is visible on dashboard)
        dt_now = max(0.0, (now_dt - st["last_ts"].astimezone(timezone.utc)).total_seconds())
        risk_now = st["risk"] * math.exp(-lam * dt_now)

        prev = get_previous_state(eid)
        prev_risk = float(prev.get("risk", 0.0))

        mu, sigma, baseline_n = compute_baseline_from_snapshots(eid)

        # --- Prevent threshold blow-ups (sigma cap) ---
        sigma_capped = min(sigma, MAX_SIGMA_MULTIPLIER * max(mu, 1.0))

        # Candidate threshold from baseline stats
        threshold_candidate = mu + K_SIGMA * sigma_capped
        threshold_candidate = max(threshold_candidate, MIN_THRESHOLD)

        # --- Make threshold self-heal (decay) ---
        prev_threshold = float(prev.get("threshold", threshold_candidate))
        if USE_DECAYED_THRESHOLD:
            threshold = max(mu, prev_threshold * THRESHOLD_DECAY)
            threshold = min(threshold, threshold_candidate)  # don't drift above the candidate
            threshold = max(threshold, MIN_THRESHOLD)
        else:
            threshold = threshold_candidate

        # Standardized comparability metrics
        z = 0.0 if sigma_capped <= 0 else (risk_now - mu) / sigma_capped
        ratio = 0.0 if threshold <= 0 else risk_now / threshold

        delta_risk = risk_now - prev_risk

        # cooldown check
        last_alert_ts = parse_last_alert_ts(prev)
        in_cooldown = False
        if last_alert_ts is not None:
            in_cooldown = (now_dt - last_alert_ts) < timedelta(minutes=COOLDOWN_MIN)

        # Alert if risk_now >= threshold AND delta_risk > DELTA_MIN, and not in cooldown
        enough_baseline = baseline_n >= BASELINE_MIN_SNAPSHOTS
        should_alert = (
            enough_baseline
            and (risk_now >= threshold)
            and (delta_risk > DELTA_MIN)
            and (not in_cooldown)
        )

        # --- write state doc ---
        doc = {
            "@timestamp": now,
            "updated_at": now,
            "entity": {"id": eid, "type": "host", "name": st["name"]},
            "risk": risk_now,
            "mu": mu,
            "sigma": sigma,
            "sigma_capped": sigma_capped,
            "k": K_SIGMA,
            "threshold": threshold,
            "z": z,
            "ratio": ratio,
            "delta_risk": delta_risk,
            "last_event_ts": st["last_ts"].astimezone(timezone.utc).isoformat(),
            "half_life_minutes": HALF_LIFE_MIN,
            "time_window_hours": TW_HOURS,
            "baseline_window_hours": BASELINE_HOURS,
            "last_rule": st["last_rule"],
        }

        if should_alert:
            doc["last_alert_ts"] = now

        client.index(index=STATE_INDEX, id=eid, body=doc, refresh=True)
        states_updated += 1

        # --- snapshot for charts ---
        snap_doc = {
            "@timestamp": now,
            "entity": {"id": eid, "type": "host", "name": st["name"]},
            "risk": risk_now,
            "mu": mu,
            "sigma": sigma,
            "sigma_capped": sigma_capped,
            "k": K_SIGMA,
            "threshold": threshold,
            "z": z,
            "ratio": ratio,
        }
        client.index(index=snap_index_today, body=snap_doc, refresh=True)

        # --- alert doc ---
        if should_alert and alerts_written < MAX_ALERTS_PER_RUN:
            top_contrib = sorted(st["events_sample"], key=lambda e: e["risk_inc"], reverse=True)[:TOP_CONTRIB]
            alert_doc = {
                "@timestamp": now,
                "entity": {"id": eid, "type": "host", "name": st["name"]},
                "risk": risk_now,
                "threshold": threshold,
                "mu": mu,
                "sigma": sigma,
                "sigma_capped": sigma_capped,
                "k": K_SIGMA,
                "z": z,
                "ratio": ratio,
                "delta_risk": delta_risk,
                "time_window_hours": TW_HOURS,
                "baseline_window_hours": BASELINE_HOURS,
                "half_life_minutes": HALF_LIFE_MIN,
                "event_count_window": int(st.get("event_count", 0)),
                "top_contributors": top_contrib,
            }

            agent_id_for_rules = agent_id_from_entity_id(eid)
            rule_contrib = fetch_top_wazuh_rules(
                client,
                agent_id_for_rules,
                alert_doc["@timestamp"],
                TW_HOURS,
                TOP_CONTRIB,
            )
            alert_doc["contributors_rules"] = rule_contrib
            alert_doc["contributors_rules_window_hours"] = TW_HOURS

            client.index(index=alert_index_today, body=alert_doc, refresh=True)
            alerts_written += 1

    print(
        f"Updated {states_updated} states; wrote {states_updated} snapshots; "
        f"generated {alerts_written} RBA alerts."
    )
    print(f"Alert index: {alert_index_today}")


if __name__ == "__main__":
    main()
