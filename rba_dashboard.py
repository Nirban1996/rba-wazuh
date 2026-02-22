#!/usr/bin/env python3
# rba_dashboard.py

import os
import json
import uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from dotenv import load_dotenv
from opensearchpy import OpenSearch


# =========================
# Env helpers
# =========================
load_dotenv()


def env_str(key: str, default: str | None = None) -> str | None:
    v = os.getenv(key)
    if v is None:
        return default
    v = str(v).strip()
    return v if v != "" else default


def env_bool(key: str, default: bool = False) -> bool:
    v = env_str(key, None)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "y", "on")


def parse_host_and_ssl(os_host: str | None, use_ssl_default: bool = True):
    """
    Accepts:
      - "192.168.1.10"
      - "https://192.168.1.10"
      - "http://opensearch.local"
    Returns: (host, use_ssl)
    """
    if not os_host:
        return None, use_ssl_default

    h = os_host.strip()
    if h.startswith("http://") or h.startswith("https://"):
        u = urlparse(h)
        host = u.hostname or h
        use_ssl = (u.scheme == "https")
        return host, use_ssl

    return h, use_ssl_default


# =========================
# Config / Connection
# =========================
OS_TIMEOUT = int(env_str("OS_TIMEOUT", "20"))
RBA_DEBUG = env_bool("RBA_DEBUG", False)

OS_HOST_RAW = env_str("OS_HOST", None)
USE_SSL_ENV = env_bool("OS_SSL", True)
HOST, USE_SSL = parse_host_and_ssl(OS_HOST_RAW, use_ssl_default=USE_SSL_ENV)

PORT = int(env_str("OS_PORT", "9200"))
USER = env_str("OS_USER", None)
PWD = env_str("OS_PASS", None)
VERIFY_CERTS = env_bool("OS_VERIFY_CERTS", False)

STATE_INDEX = env_str("RBA_STATE_INDEX", "rba-entity-state")
SNAP_INDEX = env_str("RBA_SNAP_INDEX", "rba-risk-snapshots-*")
ALERT_INDEX = env_str("RBA_ALERT_INDEX", "rba-alerts-*")
WAZUH_ALERTS = env_str("WAZUH_ALERTS_INDEX", "wazuh-alerts-*")

# Timestamp fields (auto-fallback if env is blank)
WAZUH_TS_FIELD = env_str("WAZUH_TS_FIELD", None) or "timestamp"
RBA_TS_FIELD = env_str("RBA_TS_FIELD", None) or "@timestamp"
RBA_SNAP_TS_FIELD = env_str("RBA_SNAP_TS_FIELD", None) or "@timestamp"

# Case management storage
CASES_INDEX = env_str("RBA_CASES_INDEX", "rba-cases")
LOCAL_CASES_FILE = Path(env_str("RBA_CASES_LOCAL_FILE", "rba_cases.json"))

# delta gate for report alignment
DELTA_MIN = float(env_str("RBA_DELTA_MIN", "1"))

# Rank mode for "Top entities"
# - "ratio": risk/threshold (best for "close to alerting")
# - "z": (risk-mu)/sigma_capped (best for "most anomalous")
RBA_RANK_MODE = (env_str("RBA_RANK_MODE", "ratio") or "ratio").strip().lower()
if RBA_RANK_MODE not in ("ratio", "z", "risk"):
    RBA_RANK_MODE = "ratio"

st.set_page_config(page_title="RBA Control Center", layout="wide")

if not HOST or not USER:
    st.error("Missing OS_HOST / OS_USER in environment. Check your .env file.")
    st.stop()

client = OpenSearch(
    hosts=[{"host": HOST, "port": PORT}],
    http_auth=(USER, PWD),
    use_ssl=USE_SSL,
    verify_certs=VERIFY_CERTS,
    ssl_show_warn=False,
    timeout=OS_TIMEOUT,
    max_retries=2,
    retry_on_timeout=True,
)


# =========================
# Utilities
# =========================
def _rerun():
    try:
        st.rerun()
    except Exception:
        st.experimental_rerun()


def qp_get(key: str, default=None):
    try:
        return st.query_params.get(key, default)
    except Exception:
        q = st.experimental_get_query_params()
        if key not in q:
            return default
        return q[key][0] if isinstance(q[key], list) and q[key] else default


def qp_set(**kwargs):
    try:
        for k, v in kwargs.items():
            st.query_params[k] = str(v)
    except Exception:
        st.experimental_set_query_params(**{k: str(v) for k, v in kwargs.items()})


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def get_time_range(hours: int):
    end = utc_now().replace(second=0, microsecond=0)  # stable cache keys
    start = end - timedelta(hours=int(hours))
    return start, end


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _ffloat(x, default=0.0) -> float:
    try:
        if x is None:
            return default
        return float(x)
    except Exception:
        return default


def _as_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def safe_get(d: dict, path: str, default=None):
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def ensure_unique_columns(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    return df.loc[:, ~df.columns.duplicated()].copy()


def entity_to_agent(entity_id: str):
    """
    Your entity ids look like "host:000". Wazuh agent.id is usually "000".
    """
    if not entity_id:
        return None
    if ":" in entity_id:
        return entity_id.split(":")[-1]
    return entity_id


def minutes_ago(ts) -> int | None:
    """
    Returns minutes ago from now (UTC). Safe for tz-aware/tz-naive and strings.
    """
    if ts is None:
        return None
    t = pd.to_datetime(ts, errors="coerce", utc=True)
    if pd.isna(t):
        return None
    now = pd.Timestamp.now(tz="UTC")
    return int((now - t).total_seconds() // 60)


def inject_css():
    st.markdown(
        """
<style>
.stApp {
  background: radial-gradient(1200px 800px at 20% 10%, rgba(0, 140, 255, 0.10), rgba(0,0,0,0)) ,
              radial-gradient(1200px 800px at 80% 30%, rgba(255, 0, 100, 0.08), rgba(0,0,0,0)) ,
              #0b0f14;
  color: #e9eef7;
}
section[data-testid="stSidebar"] {
  background: #0a0d12;
  border-right: 1px solid rgba(255,255,255,0.06);
}
h1, h2, h3 { letter-spacing: 0.2px; }
.rba-card {
  background: rgba(255,255,255,0.04);
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 14px;
  padding: 14px 14px 10px 14px;
  box-shadow: 0 8px 24px rgba(0,0,0,0.35);
}
a.kpi-link { text-decoration: none !important; color: inherit !important; }
.kpi {
  background: rgba(255,255,255,0.04);
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 16px;
  padding: 14px 16px;
  box-shadow: 0 10px 28px rgba(0,0,0,0.38);
  transition: transform 0.10s ease, border-color 0.10s ease;
}
.kpi:hover { transform: translateY(-2px); border-color: rgba(0,140,255,0.35); }
.kpi-title { font-size: 12px; opacity: 0.80; margin-bottom: 6px; }
.kpi-value { font-size: 28px; font-weight: 700; line-height: 1.05; }
.kpi-sub { font-size: 11px; opacity: 0.70; margin-top: 6px; }
.pill {
  display: inline-block;
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid rgba(255,255,255,0.10);
  background: rgba(255,255,255,0.03);
  font-size: 12px;
  margin-right: 6px;
  opacity: 0.9;
}
div[data-testid="stDataFrame"] {
  border-radius: 14px;
  overflow: hidden;
  border: 1px solid rgba(255,255,255,0.08);
}
footer {visibility: hidden;}
</style>
""",
        unsafe_allow_html=True,
    )


inject_css()


# =========================
# OpenSearch helpers
# =========================
def os_search(index: str, body: dict):
    return client.search(index=index, body=body, request_timeout=OS_TIMEOUT)


@st.cache_data(ttl=60)
def count_index_fast(index_pattern: str, start_iso: str, end_iso: str, ts_field: str, cap: int = 10000):
    """
    Faster than count(): uses search(size=0) with track_total_hits capped.
    Returns (value, relation, err)
    """
    body = {
        "size": 0,
        "track_total_hits": cap,
        "query": {"range": {ts_field: {"gte": start_iso, "lte": end_iso}}},
    }
    try:
        resp = client.search(index=index_pattern, body=body, request_timeout=OS_TIMEOUT)
        total = resp.get("hits", {}).get("total", 0)
        if isinstance(total, dict):
            return int(total.get("value", 0)), total.get("relation", "eq"), ""
        return int(total), "eq", ""
    except Exception as e:
        return 0, "eq", str(e)


@st.cache_data(ttl=30)
def fetch_counts_timeseries(index_pattern: str, interval_minutes: int, start_iso: str, end_iso: str, ts_field: str) -> pd.DataFrame:
    body = {
        "size": 0,
        "query": {"range": {ts_field: {"gte": start_iso, "lte": end_iso}}},
        "aggs": {
            "per_bucket": {
                "date_histogram": {
                    "field": ts_field,
                    "fixed_interval": f"{int(interval_minutes)}m",
                    "min_doc_count": 0,
                    "extended_bounds": {"min": start_iso, "max": end_iso},
                }
            }
        },
    }

    try:
        resp = os_search(index_pattern, body)
        buckets = resp.get("aggregations", {}).get("per_bucket", {}).get("buckets", []) or []
        rows = [{"ts": b.get("key_as_string"), "count": b.get("doc_count", 0)} for b in buckets]
    except Exception:
        rows = []

    df = pd.DataFrame(rows, columns=["ts", "count"])
    if df.empty:
        return pd.DataFrame(columns=["ts", "count"])

    df["ts"] = pd.to_datetime(df["ts"], utc=True, errors="coerce")
    df["count"] = pd.to_numeric(df["count"], errors="coerce").fillna(0).astype(int)
    return df


def merge_timeseries(raw_ts: pd.DataFrame, rba_ts: pd.DataFrame) -> pd.DataFrame:
    if raw_ts is None or raw_ts.empty:
        raw_ts = pd.DataFrame(columns=["ts", "count"])
    if rba_ts is None or rba_ts.empty:
        rba_ts = pd.DataFrame(columns=["ts", "count"])

    a = raw_ts.rename(columns={"count": "raw_alerts"})
    b = rba_ts.rename(columns={"count": "rba_alerts"})
    out = pd.merge(a, b, on="ts", how="outer").fillna(0)
    out["ts"] = pd.to_datetime(out["ts"], utc=True, errors="coerce")
    out["raw_alerts"] = pd.to_numeric(out["raw_alerts"], errors="coerce").fillna(0)
    out["rba_alerts"] = pd.to_numeric(out["rba_alerts"], errors="coerce").fillna(0)
    return out.sort_values("ts")


def _rank_sort_spec():
    # Sort state by a standardized metric so different entities are comparable
    if RBA_RANK_MODE == "z":
        return [{"z": {"order": "desc"}}, {"ratio": {"order": "desc"}}, {"risk": {"order": "desc"}}]
    if RBA_RANK_MODE == "risk":
        return [{"risk": {"order": "desc"}}, {"ratio": {"order": "desc"}}]
    # default: ratio
    return [{"ratio": {"order": "desc"}}, {"z": {"order": "desc"}}, {"risk": {"order": "desc"}}]


@st.cache_data(ttl=20)
def fetch_entity_state(limit: int) -> pd.DataFrame:
    body = {
        "size": int(limit),
        "sort": _rank_sort_spec(),
        "_source": [
            "entity.id",
            "entity.name",
            "risk",
            "threshold",
            "mu",
            "sigma",
            "sigma_capped",
            "k",
            "delta_risk",
            "z",
            "ratio",
            "last_event_ts",
        ],
        "query": {"match_all": {}},
    }
    try:
        resp = os_search(STATE_INDEX, body)
    except Exception:
        return pd.DataFrame()

    rows = []
    for h in resp.get("hits", {}).get("hits", []) or []:
        s = h.get("_source", {}) or {}
        ent = s.get("entity", {}) or {}
        rows.append(
            {
                "entity_id": ent.get("id"),
                "entity_name": ent.get("name"),
                "risk": _ffloat(s.get("risk")),
                "threshold": _ffloat(s.get("threshold")),
                "mu": _ffloat(s.get("mu"), default=None),
                "sigma": _ffloat(s.get("sigma"), default=None),
                "sigma_capped": _ffloat(s.get("sigma_capped"), default=None),
                "k": _ffloat(s.get("k"), default=None),
                "delta_risk": _ffloat(s.get("delta_risk")),
                "z": _ffloat(s.get("z"), default=None),
                "ratio": _ffloat(s.get("ratio"), default=None),
                "last_event_ts": s.get("last_event_ts"),
            }
        )
    df = pd.DataFrame(rows)
    return df


@st.cache_data(ttl=20)
def fetch_snapshots(entity_id: str, start_iso: str, end_iso: str, limit: int = 2000) -> pd.DataFrame:
    body = {
        "size": int(limit),
        "sort": [{RBA_SNAP_TS_FIELD: {"order": "asc"}}],
        "track_total_hits": False,
        "_source": [
            RBA_SNAP_TS_FIELD,
            "risk",
            "threshold",
            "mu",
            "sigma",
            "sigma_capped",
            "z",
            "ratio",
            "entity.id",
            "entity.name",
        ],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"entity.id": entity_id}},
                    {"range": {RBA_SNAP_TS_FIELD: {"gte": start_iso, "lte": end_iso}}},
                ]
            }
        },
    }

    try:
        resp = os_search(SNAP_INDEX, body)
    except Exception:
        return pd.DataFrame()

    rows = []
    for h in resp.get("hits", {}).get("hits", []) or []:
        s = h.get("_source", {}) or {}
        ent = s.get("entity", {}) or {}
        rows.append(
            {
                "ts": s.get(RBA_SNAP_TS_FIELD),
                "risk": _ffloat(s.get("risk")),
                "threshold": _ffloat(s.get("threshold")),
                "mu": _ffloat(s.get("mu"), default=None),
                "sigma": _ffloat(s.get("sigma"), default=None),
                "sigma_capped": _ffloat(s.get("sigma_capped"), default=None),
                "z": _ffloat(s.get("z"), default=None),
                "ratio": _ffloat(s.get("ratio"), default=None),
                "entity_id": ent.get("id"),
                "entity_name": ent.get("name"),
            }
        )

    df = pd.DataFrame(rows)
    if not df.empty:
        df["ts"] = pd.to_datetime(df["ts"], utc=True, errors="coerce")
    return df


@st.cache_data(ttl=15)
def fetch_rba_alerts(start_iso: str, end_iso: str, limit: int = 200) -> pd.DataFrame:
    body = {
        "size": int(limit),
        "sort": [{RBA_TS_FIELD: {"order": "desc"}}],
        "_source": [
            RBA_TS_FIELD,
            "entity.id",
            "entity.name",
            "risk",
            "threshold",
            "delta_risk",
            "mu",
            "sigma",
            "sigma_capped",
            "k",
            "z",
            "ratio",
            "time_window_hours",
            "baseline_window_hours",
            "half_life_minutes",
            "event_count_window",
            "top_contributors",
            "contributors_rules",
            "contributors_rules_window_hours",
        ],
        "query": {"range": {RBA_TS_FIELD: {"gte": start_iso, "lte": end_iso}}},
    }

    try:
        resp = os_search(ALERT_INDEX, body)
    except Exception:
        return pd.DataFrame()

    rows = []
    for h in resp.get("hits", {}).get("hits", []) or []:
        s = h.get("_source", {}) or {}
        ent = s.get("entity", {}) or {}
        rows.append(
            {
                "ts": s.get(RBA_TS_FIELD),
                "entity_id": ent.get("id"),
                "entity_name": ent.get("name"),
                "risk": _ffloat(s.get("risk")),
                "threshold": _ffloat(s.get("threshold")),
                "delta_risk": _ffloat(s.get("delta_risk")),
                "mu": _ffloat(s.get("mu"), default=None),
                "sigma": _ffloat(s.get("sigma"), default=None),
                "sigma_capped": _ffloat(s.get("sigma_capped"), default=None),
                "k": _ffloat(s.get("k"), default=None),
                "z": _ffloat(s.get("z"), default=None),
                "ratio": _ffloat(s.get("ratio"), default=None),
                "time_window_hours": s.get("time_window_hours"),
                "baseline_window_hours": s.get("baseline_window_hours"),
                "half_life_minutes": s.get("half_life_minutes"),
                "event_count_window": s.get("event_count_window", 0),
                "top_contributors": s.get("top_contributors", []),
                "contributors_rules": s.get("contributors_rules", []),
                "contributors_rules_window_hours": s.get("contributors_rules_window_hours"),
            }
        )

    df = pd.DataFrame(rows)
    if not df.empty:
        df["ts"] = pd.to_datetime(df["ts"], utc=True, errors="coerce")
    return df


def build_raw_events_query(start_iso: str, end_iso: str, query_text: str, min_rule_level: int, entity_id: str | None):
    filters = [{"range": {WAZUH_TS_FIELD: {"gte": start_iso, "lte": end_iso}}}]

    if min_rule_level is not None and int(min_rule_level) > 0:
        filters.append({"range": {"rule.level": {"gte": int(min_rule_level)}}})

    if entity_id:
        agent_id = entity_to_agent(entity_id)
        shoulds = []
        if agent_id:
            shoulds.append({"term": {"agent.id": str(agent_id)}})
        shoulds.append({"term": {"agent.name": str(entity_id)}})
        shoulds.append({"term": {"agent.name": str(entity_id).replace("host:", "")}})
        filters.append({"bool": {"should": shoulds, "minimum_should_match": 1}})

    must = []
    if query_text and query_text.strip():
        must.append(
            {
                "query_string": {
                    "query": query_text,
                    "default_field": "*",
                }
            }
        )

    q = {"bool": {"filter": filters}}
    if must:
        q["bool"]["must"] = must
    return q


@st.cache_data(ttl=15)
def fetch_raw_events(
    start_iso: str,
    end_iso: str,
    query_text: str = "",
    min_rule_level: int = 0,
    entity_id: str | None = None,
    limit: int = 500,
) -> pd.DataFrame:
    body = {
        "size": int(limit),
        "sort": [{WAZUH_TS_FIELD: {"order": "desc"}}],
        "_source": [
            "timestamp",
            "@timestamp",
            "rule.id",
            "rule.description",
            "rule.level",
            "rule.groups",
            "rule.mitre",
            "agent.id",
            "agent.name",
            "full_log",
            "location",
            "decoder.name",
            "data",
            "mitre",
        ],
        "query": build_raw_events_query(start_iso, end_iso, query_text, min_rule_level, entity_id),
    }

    try:
        resp = os_search(WAZUH_ALERTS, body)
    except Exception:
        return pd.DataFrame()

    rows = []
    for h in resp.get("hits", {}).get("hits", []) or []:
        s = h.get("_source", {}) or {}
        ts_value = s.get(WAZUH_TS_FIELD) or s.get("@timestamp") or s.get("timestamp")
        rows.append(
            {
                "ts": ts_value,
                "agent_id": safe_get(s, "agent.id"),
                "agent_name": safe_get(s, "agent.name"),
                "rule_id": safe_get(s, "rule.id"),
                "rule_level": safe_get(s, "rule.level"),
                "rule_desc": safe_get(s, "rule.description"),
                "rule_groups": safe_get(s, "rule.groups"),
                "location": s.get("location"),
                "decoder": safe_get(s, "decoder.name"),
                "has_mitre": bool(safe_get(s, "rule.mitre") or s.get("mitre") or safe_get(s, "data.mitre")),
                "raw": s,
            }
        )

    df = pd.DataFrame(rows)
    if df.empty:
        return df

    df["ts"] = pd.to_datetime(df["ts"], utc=True, errors="coerce")
    return df


def extract_mitre_items(event_source: dict):
    out = []
    candidates = []
    candidates.extend(_as_list(safe_get(event_source, "rule.mitre")))
    candidates.extend(_as_list(safe_get(event_source, "mitre")))
    candidates.extend(_as_list(safe_get(event_source, "data.mitre")))

    for c in candidates:
        if c is None:
            continue

        if isinstance(c, dict):
            ids = _as_list(c.get("id"))
            tactics = _as_list(c.get("tactic") or c.get("tactics"))
            techs = _as_list(c.get("technique") or c.get("techniques") or c.get("name"))

            if ids or tactics or techs:
                m = max(len(ids), len(tactics), len(techs), 1)
                for i in range(m):
                    out.append(
                        {
                            "tactic": tactics[i] if i < len(tactics) else (tactics[0] if tactics else None),
                            "technique_id": ids[i] if i < len(ids) else (ids[0] if ids else None),
                            "technique": techs[i] if i < len(techs) else (techs[0] if techs else None),
                        }
                    )

        elif isinstance(c, list):
            for item in c:
                if isinstance(item, dict):
                    out.append(
                        {
                            "tactic": item.get("tactic") or item.get("tactics"),
                            "technique_id": item.get("id"),
                            "technique": item.get("technique") or item.get("name"),
                        }
                    )

    cleaned = []
    for r in out:
        tactic = r.get("tactic")
        tid = r.get("technique_id")
        tech = r.get("technique")
        if tactic or tid or tech:
            cleaned.append({"tactic": tactic, "technique_id": tid, "technique": tech})
    return cleaned


def mitre_summaries(raw_events_df: pd.DataFrame):
    if raw_events_df is None or raw_events_df.empty:
        return pd.DataFrame(), pd.DataFrame()

    rows = []
    for _, row in raw_events_df.iterrows():
        ev = row.get("raw") or {}
        items = extract_mitre_items(ev)
        for it in items:
            rows.append(
                {
                    "tactic": it.get("tactic") or "Unknown",
                    "technique_id": it.get("technique_id") or "Unknown",
                    "technique": it.get("technique") or "Unknown",
                }
            )

    if not rows:
        return pd.DataFrame(), pd.DataFrame()

    d = pd.DataFrame(rows)
    by_tactic = d.groupby("tactic", as_index=False).size().rename(columns={"size": "count"}).sort_values("count", ascending=False)
    by_tech = (
        d.groupby(["technique_id", "technique"], as_index=False)
        .size()
        .rename(columns={"size": "count"})
        .sort_values("count", ascending=False)
    )
    return by_tactic, by_tech


# =========================
# Cases backend
# =========================
def _try_ensure_cases_index() -> bool:
    try:
        exists = client.indices.exists(index=CASES_INDEX)
        if exists:
            return True

        mapping = {
            "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
            "mappings": {
                "properties": {
                    "case_id": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "owner": {"type": "keyword"},
                    "tags": {"type": "keyword"},
                    "notes": {"type": "text"},
                    "entity_id": {"type": "keyword"},
                    "entity_name": {"type": "keyword"},
                    "alert_ts": {"type": "date"},
                    "created_at": {"type": "date"},
                    "updated_at": {"type": "date"},
                }
            },
        }
        client.indices.create(index=CASES_INDEX, body=mapping)
        return True
    except Exception:
        return False


def cases_backend() -> str:
    if "cases_backend" in st.session_state:
        return st.session_state["cases_backend"]
    ok = _try_ensure_cases_index()
    st.session_state["cases_backend"] = "opensearch" if ok else "local"
    return st.session_state["cases_backend"]


def load_cases_local() -> list[dict]:
    if not LOCAL_CASES_FILE.exists():
        return []
    try:
        return json.loads(LOCAL_CASES_FILE.read_text())
    except Exception:
        return []


def save_cases_local(cases: list[dict]):
    try:
        LOCAL_CASES_FILE.write_text(json.dumps(cases, indent=2, default=str))
    except Exception:
        pass


def list_cases() -> pd.DataFrame:
    be = cases_backend()
    if be == "local":
        data = load_cases_local()
        df = pd.DataFrame(data)
    else:
        try:
            resp = client.search(
                index=CASES_INDEX,
                body={"size": 500, "sort": [{"updated_at": {"order": "desc"}}], "query": {"match_all": {}}},
                request_timeout=OS_TIMEOUT,
            )
            rows = []
            for h in resp.get("hits", {}).get("hits", []) or []:
                s = h.get("_source", {}) or {}
                rows.append(s)
            df = pd.DataFrame(rows)
        except Exception:
            df = pd.DataFrame()

    if df.empty:
        return pd.DataFrame(
            columns=["case_id", "status", "owner", "tags", "notes", "entity_id", "entity_name", "alert_ts", "created_at", "updated_at"]
        )

    for c in ["created_at", "updated_at", "alert_ts"]:
        if c in df.columns:
            df[c] = pd.to_datetime(df[c], utc=True, errors="coerce")
    if "tags" in df.columns:
        df["tags"] = df["tags"].apply(lambda x: x if isinstance(x, list) else ([] if x is None else [x]))

    return ensure_unique_columns(df)


def upsert_case(case_doc: dict):
    be = cases_backend()
    case_doc = dict(case_doc)
    case_doc["updated_at"] = iso(utc_now())
    if not case_doc.get("created_at"):
        case_doc["created_at"] = case_doc["updated_at"]

    if be == "local":
        cases = load_cases_local()
        cid = case_doc["case_id"]
        cases = [c for c in cases if c.get("case_id") != cid]
        cases.insert(0, case_doc)
        save_cases_local(cases)
        return

    client.index(index=CASES_INDEX, id=case_doc["case_id"], body=case_doc, refresh=True)


def delete_case(case_id: str):
    be = cases_backend()
    if be == "local":
        cases = load_cases_local()
        cases = [c for c in cases if c.get("case_id") != case_id]
        save_cases_local(cases)
        return
    try:
        client.delete(index=CASES_INDEX, id=case_id, refresh=True)
    except Exception:
        pass


# =========================
# Global controls + Navigation
# =========================
PAGES = [
    ("overview", "📊 Overview"),
    ("risk", "🧭 Risk Posture"),
    ("alerts", "🚨 Alert Triage"),
    ("investigation", "🧪 Investigation"),
    ("raw", "🧾 Raw Events"),
    ("rules", "📚 Rule Lookup"),
    ("cases", "🗂️ Cases"),
]

DEFAULT_VIEW = "overview"
view = qp_get("view", DEFAULT_VIEW)
if view not in {p[0] for p in PAGES}:
    view = DEFAULT_VIEW

with st.sidebar:
    st.markdown("### 🛡️ RBA Control Center")

    default_hours = int(qp_get("hours", 24))
    default_topn = int(qp_get("topn", 10))
    default_autorefresh = str(qp_get("autorefresh", "0")) == "1"
    default_q = str(qp_get("q", "")) if qp_get("q", "") else ""
    default_minlvl = int(qp_get("minlvl", 0))

    with st.form("controls_form"):
        hours = st.slider("Time window (hours)", 1, 168, default_hours, 1)
        topn = st.selectbox("Top entities", [5, 10, 20, 50], index=[5, 10, 20, 50].index(default_topn) if default_topn in [5, 10, 20, 50] else 1)

        auto_refresh = st.checkbox("Auto-refresh", value=default_autorefresh)
        refresh_seconds = st.selectbox("Refresh every (seconds)", [5, 10, 30, 60], index=2, disabled=not auto_refresh)

        st.divider()
        st.markdown("### 🔎 Global filters")
        search_text = st.text_input("Search (entity / rule / text)", value=default_q)
        min_rule_level = st.slider("Min rule level (raw)", 0, 15, default_minlvl, 1)

        st.divider()
        st.markdown("### 🧭 Navigation")
        labels = [p[1] for p in PAGES]
        ids = [p[0] for p in PAGES]
        default_idx = ids.index(view)
        choice = st.radio("Navigation", labels, index=default_idx, label_visibility="collapsed")
        chosen_view = ids[labels.index(choice)]

        apply = st.form_submit_button("Apply")

    if apply:
        qp_set(
            view=chosen_view,
            hours=hours,
            topn=topn,
            autorefresh=int(auto_refresh),
            q=search_text,
            minlvl=min_rule_level,
        )
        _rerun()

if auto_refresh:
    st_autorefresh(interval=int(refresh_seconds) * 1000, key="rba_autorefresh")

start_dt, end_dt = get_time_range(hours)
start_iso, end_iso = iso(start_dt), iso(end_dt)

if "ctx_entity_id" not in st.session_state:
    st.session_state["ctx_entity_id"] = None
if "ctx_alert_ts" not in st.session_state:
    st.session_state["ctx_alert_ts"] = None


# =========================
# UI building blocks
# =========================
def pill_row(hours_: int, topn_: int):
    st.markdown(
        f"""
<span class="pill">Window: last {int(hours_)}h</span>
<span class="pill">Δ gate: δ={DELTA_MIN}</span>
<span class="pill">Top entities: {int(topn_)}</span>
<span class="pill">Ranking: {RBA_RANK_MODE}</span>
""",
        unsafe_allow_html=True,
    )


def kpi_card(title: str, value: str, sub: str, target_view: str, extra_params: dict | None = None):
    params = {
        "view": target_view,
        "hours": hours,
        "topn": topn,
        "autorefresh": int(auto_refresh),
        "q": search_text,
        "minlvl": min_rule_level,
    }
    if extra_params:
        params.update(extra_params)

    href = "?" + urlencode(params, doseq=True)
    st.markdown(
        f"""
<a class="kpi-link" href="{href}">
  <div class="kpi">
    <div class="kpi-title">{title}</div>
    <div class="kpi-value">{value}</div>
    <div class="kpi-sub">{sub}</div>
  </div>
</a>
""",
        unsafe_allow_html=True,
    )


def render_mitre_section(raw_df: pd.DataFrame, title="MITRE view"):
    st.subheader(title)
    by_tactic, by_tech = mitre_summaries(raw_df)

    if by_tactic.empty and by_tech.empty:
        st.info("MITRE mapping not found in current selection.")
        return

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Tactics**")
        fig = px.bar(by_tactic, x="tactic", y="count")
        fig.update_layout(height=320, margin=dict(l=10, r=10, t=20, b=10))
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        st.markdown("**Techniques**")
        top = by_tech.head(12).copy()
        top["label"] = top["technique_id"].astype(str) + " — " + top["technique"].astype(str)
        fig = px.bar(top, x="label", y="count")
        fig.update_layout(height=320, margin=dict(l=10, r=10, t=20, b=10))
        st.plotly_chart(fig, use_container_width=True)

    with st.expander("Technique table"):
        t = by_tech.copy()
        t = ensure_unique_columns(t)
        t["attack_url"] = t["technique_id"].apply(lambda x: f"https://attack.mitre.org/techniques/{x}/" if x and x != "Unknown" else "")
        st.dataframe(
            t,
            use_container_width=True,
            column_config={"attack_url": st.column_config.LinkColumn("MITRE ATT&CK", display_text="Open")},
        )


def _compute_ratio_from_row(r) -> float:
    thr = _ffloat(r.get("threshold"))
    if thr <= 0:
        return 0.0
    return _ffloat(r.get("risk")) / thr


def risk_cards(df_state: pd.DataFrame):
    if df_state.empty:
        st.warning("No entity state data found.")
        return

    df = df_state.copy()

    # Ensure ratio is always present (old state docs may not have it yet)
    if "ratio" not in df.columns or df["ratio"].isna().all():
        df["ratio"] = df.apply(_compute_ratio_from_row, axis=1)
    else:
        df["ratio"] = df["ratio"].fillna(df.apply(_compute_ratio_from_row, axis=1))

    df["above"] = df["ratio"] >= 1.0

    cols = st.columns(min(4, len(df)))
    for i, (_, r) in enumerate(df.head(4).iterrows()):
        with cols[i]:
            ratio_pct = float(r.get("ratio") or 0.0) * 100.0
            tag = "Above θ" if bool(r.get("above")) else "Below θ"

            # Choose the score label shown on the card depending on rank mode
            score_label = "ratio"
            score_value = ratio_pct
            score_suffix = "%"
            if RBA_RANK_MODE == "z":
                score_label = "z"
                score_value = _ffloat(r.get("z"), default=0.0)
                score_suffix = ""
            elif RBA_RANK_MODE == "risk":
                score_label = "risk"
                score_value = _ffloat(r.get("risk"), default=0.0)
                score_suffix = ""

            st.markdown(
                f"""
<div class="rba-card">
  <div style="opacity:0.85;font-size:12px;">{r.get("entity_name","—")} <span style="opacity:0.65">({r.get("entity_id","—")})</span></div>
  <div style="font-size:26px;font-weight:700;margin-top:6px;">{_ffloat(r.get("risk")):.2f}</div>
  <div style="opacity:0.75;font-size:12px;margin-top:2px;">
    θ {_ffloat(r.get("threshold")):.2f} • {tag} • {score_label} {score_value:.2f}{score_suffix}
  </div>
</div>
""",
                unsafe_allow_html=True,
            )


def risk_bucket_tables(df_state: pd.DataFrame):
    if df_state.empty:
        return

    df = df_state.copy()

    if "ratio" not in df.columns or df["ratio"].isna().all():
        df["ratio"] = df.apply(_compute_ratio_from_row, axis=1)
    else:
        df["ratio"] = df["ratio"].fillna(df.apply(_compute_ratio_from_row, axis=1))

    near = df[df["ratio"] >= 0.8].sort_values("ratio", ascending=False).head(10)
    fast = df.sort_values("delta_risk", ascending=False).head(10)
    above = df[df["ratio"] >= 1.0].sort_values("ratio", ascending=False).head(10)

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown("### Above θ")
        show = above[["entity_id", "entity_name", "risk", "threshold", "ratio", "delta_risk"]].copy()
        if not show.empty:
            show["ratio"] = (show["ratio"] * 100).round(1).astype(str) + "%"
        st.dataframe(ensure_unique_columns(show), use_container_width=True)

    with c2:
        st.markdown("### Near θ (≥ 80%)")
        show = near[["entity_id", "entity_name", "risk", "threshold", "ratio", "delta_risk"]].copy()
        if not show.empty:
            show["ratio"] = (show["ratio"] * 100).round(1).astype(str) + "%"
        st.dataframe(ensure_unique_columns(show), use_container_width=True)

    with c3:
        st.markdown("### Fast risers (ΔRisk)")
        show = fast[["entity_id", "entity_name", "risk", "threshold", "delta_risk"]].copy()
        st.dataframe(ensure_unique_columns(show), use_container_width=True)


def rule_lookup_from_raw(raw_df: pd.DataFrame, default_rule_id: str | None):
    st.subheader("Rule lookup (from your Wazuh events)")

    if raw_df is None or raw_df.empty:
        st.info("No raw events loaded for rule lookup.")
        return

    options = []
    if "rule_id" in raw_df.columns:
        options = [str(x) for x in raw_df["rule_id"].dropna().astype(str).unique().tolist()]
        options = sorted(options, key=lambda x: (len(x), x))

    c1, c2 = st.columns([1, 2])

    with c1:
        if options:
            idx = options.index(default_rule_id) if default_rule_id in options else 0
            rid_pick = st.selectbox("Pick a rule_id", options=options, index=idx)
        else:
            rid_pick = ""

    with c2:
        rid_manual = st.text_input("...or type rule_id", value=default_rule_id or "")

    rid = rid_manual.strip() if rid_manual.strip() else rid_pick.strip()
    if not rid:
        st.info("No rule_id selected.")
        return

    x = raw_df[raw_df["rule_id"].astype(str) == str(rid)].copy()
    if x.empty:
        st.info("No events for that rule_id in current filters/window.")
        return

    desc = x["rule_desc"].dropna().astype(str).value_counts().head(1)
    lvl = x["rule_level"].dropna().value_counts().head(1)

    groups = []
    try:
        g = x["rule_groups"].dropna().iloc[0]
        groups = g if isinstance(g, list) else ([g] if g else [])
    except Exception:
        groups = []

    st.markdown(
        f"""
<div class="rba-card">
  <div style="font-size:14px;opacity:0.8;">rule_id</div>
  <div style="font-size:22px;font-weight:700;">{rid}</div>
  <div style="opacity:0.8;margin-top:6px;">level: <b>{int(lvl.index[0]) if len(lvl) else "—"}</b></div>
  <div style="opacity:0.8;margin-top:6px;">description: <b>{desc.index[0] if len(desc) else "—"}</b></div>
  <div style="opacity:0.75;margin-top:6px;">groups: {", ".join([str(g) for g in groups]) if groups else "—"}</div>
  <div style="opacity:0.75;margin-top:6px;">events in window: <b>{len(x)}</b></div>
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("**Example events (latest 25)**")
    y = x.sort_values("ts", ascending=False).head(25)
    show = y[["ts", "agent_name", "agent_id", "rule_id", "rule_level", "rule_desc", "location", "decoder"]].copy()
    st.dataframe(ensure_unique_columns(show), use_container_width=True)

    with st.expander("Sample raw JSON (latest event)"):
        st.json(y.iloc[0]["raw"])


# =========================
# Health + pipeline freshness
# =========================
@st.cache_data(ttl=30)
def health_probe(index_pattern: str, ts_field: str):
    body = {
        "size": 1,
        "sort": [{ts_field: {"order": "desc"}}],
        "_source": [ts_field, "agent.name", "rule.id", "entity.id", "entity.name"],
        "query": {"match_all": {}},
    }
    try:
        resp = client.search(index=index_pattern, body=body, request_timeout=OS_TIMEOUT)
        hits = resp.get("hits", {}).get("hits", []) or []
        if not hits:
            return {"ok": True, "msg": "No docs found (pattern matched but empty?)", "sample": None}
        src = hits[0].get("_source", {}) or {}
        return {"ok": True, "msg": "OK", "sample": src}
    except Exception as e:
        return {"ok": False, "msg": str(e), "sample": None}


def pipeline_banner():
    # shows latest doc timestamps and age
    wazuh = health_probe(WAZUH_ALERTS, WAZUH_TS_FIELD)
    # Alerts can be legitimately 0 for long periods, so use snapshots for freshness
    rba = health_probe(SNAP_INDEX, RBA_SNAP_TS_FIELD)

    wazuh_latest = safe_get(wazuh.get("sample") or {}, WAZUH_TS_FIELD) or (wazuh.get("sample") or {}).get("@timestamp")
    rba_latest = safe_get(rba.get("sample") or {}, RBA_SNAP_TS_FIELD) or safe_get(rba.get("sample") or {}, "@timestamp")

    w_age = minutes_ago(wazuh_latest)
    r_age = minutes_ago(rba_latest)

    left, right = st.columns(2)

    with left:
        if wazuh.get("ok"):
            st.markdown(f"**Wazuh latest:** `{wazuh_latest}`" + (f" • **{w_age}m ago**" if w_age is not None else ""))
        else:
            st.error(f"Wazuh probe failed: {wazuh.get('msg')}")

    with right:
        if rba.get("ok"):
            st.markdown(f"**RBA latest:** `{rba_latest}`" + (f" • **{r_age}m ago**" if r_age is not None else ""))
        else:
            st.error(f"RBA probe failed: {rba.get('msg')}")

    # simple staleness hint
    if (w_age is not None and w_age <= 30) and (r_age is None or r_age > 180):
        st.warning("Wazuh is active, but RBA looks stale. If your window is recent, you’ll see Raw events > 0 and RBA alerts = 0.")


with st.expander("🩺 Data Health (click to debug)"):
    st.write("If KPIs are 0, this will tell you why (wrong index pattern / wrong timestamp field / auth / mapping).")
    wazuh_probe = health_probe(WAZUH_ALERTS, WAZUH_TS_FIELD)
    rba_probe = health_probe(SNAP_INDEX, RBA_SNAP_TS_FIELD)

    try:
        state_exists = client.indices.exists(index=STATE_INDEX)
    except Exception as e:
        state_exists = False
        st.error(f"State index exists() check failed: {e}")

    st.markdown(f"**WAZUH index:** `{WAZUH_ALERTS}`  | time field: `{WAZUH_TS_FIELD}`")
    st.write("Status:", "✅" if wazuh_probe["ok"] else "❌", wazuh_probe["msg"])
    if wazuh_probe["sample"] and RBA_DEBUG:
        st.json(wazuh_probe["sample"])

    st.markdown(f"**RBA snapshots index:** `{SNAP_INDEX}`  | time field: `{RBA_SNAP_TS_FIELD}`")
    st.write("Status:", "✅" if rba_probe["ok"] else "❌", rba_probe["msg"])
    if rba_probe["sample"] and RBA_DEBUG:
        st.json(rba_probe["sample"])

    st.markdown(f"**Entity state index:** `{STATE_INDEX}`")
    st.write("Exists:", "✅" if state_exists else "❌ (index not found)")


# =========================
# Pages
# =========================
def page_overview():
    st.title("Risk-Based Alerting (RBA) Dashboard")
    pill_row(hours, topn)

    pipeline_banner()
    st.divider()

    raw_count, raw_rel, raw_err = count_index_fast(WAZUH_ALERTS, start_iso, end_iso, WAZUH_TS_FIELD)
    rba_count, rba_rel, rba_err = count_index_fast(ALERT_INDEX, start_iso, end_iso, RBA_TS_FIELD)

    raw_count_label = f"{raw_count}+" if raw_rel == "gte" else f"{raw_count}"
    rba_count_label = f"{rba_count}+" if rba_rel == "gte" else f"{rba_count}"
    reduction = 0.0 if raw_count == 0 else (1.0 - (rba_count / raw_count)) * 100.0

    df_state = fetch_entity_state(limit=topn)
    above_theta = 0
    near_theta = 0
    if not df_state.empty:
        if "ratio" not in df_state.columns or df_state["ratio"].isna().all():
            ratio = df_state.apply(_compute_ratio_from_row, axis=1)
        else:
            ratio = df_state["ratio"].fillna(df_state.apply(_compute_ratio_from_row, axis=1))
        above_theta = int((ratio >= 1.0).sum())
        near_theta = int((ratio >= 0.8).sum())

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        kpi_card("Raw events", raw_count_label, "Wazuh alerts in window", "raw")
    with c2:
        kpi_card("RBA alerts", rba_count_label, "Alerts after risk filtering", "alerts")
    with c3:
        kpi_card("Reduction", f"{reduction:.1f}%", "Noise removed", "overview")
    with c4:
        kpi_card("Above θ", f"{above_theta}", "Entities exceeding threshold", "risk", {"bucket": "above"})
    with c5:
        kpi_card("Near θ", f"{near_theta}", "≥ 80% of threshold", "risk", {"bucket": "near"})

    if raw_err:
        st.warning(f"Wazuh count warning: {raw_err}")
    if rba_err:
        st.warning(f"RBA count warning: {rba_err}")

    st.divider()

    st.subheader("Alert volume over time (raw vs RBA)")
    interval = st.selectbox("Bucket size (minutes)", [1, 5, 10, 30], index=1)

    raw_ts = fetch_counts_timeseries(WAZUH_ALERTS, int(interval), start_iso, end_iso, WAZUH_TS_FIELD)
    rba_ts = fetch_counts_timeseries(ALERT_INDEX, int(interval), start_iso, end_iso, RBA_TS_FIELD)
    df_ts = merge_timeseries(raw_ts, rba_ts)

    if df_ts.empty or df_ts["ts"].isna().all():
        st.info("No data found for this time window.")
    else:
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=df_ts["ts"], y=df_ts["raw_alerts"], mode="lines+markers", name="Raw events"))
        fig.add_trace(go.Scatter(x=df_ts["ts"], y=df_ts["rba_alerts"], mode="lines+markers", name="RBA alerts"))
        fig.update_layout(height=380, margin=dict(l=10, r=10, t=30, b=10))
        st.plotly_chart(fig, use_container_width=True)

    st.divider()

    st.subheader("Top entities (standardized ranking)")
    if df_state.empty:
        st.info("No entity state data found.")
        return

    risk_cards(df_state.head(4))

    cA, cB = st.columns([1.2, 1])
    with cA:
        df_plot = df_state.copy()

        if "ratio" not in df_plot.columns or df_plot["ratio"].isna().all():
            df_plot["ratio"] = df_plot.apply(_compute_ratio_from_row, axis=1)
        else:
            df_plot["ratio"] = df_plot["ratio"].fillna(df_plot.apply(_compute_ratio_from_row, axis=1))

        fig = px.scatter(
            df_plot,
            x="threshold",
            y="risk",
            hover_data=["entity_name", "entity_id", "delta_risk", "z", "ratio"],
            size=df_plot["ratio"].clip(lower=0.1),
        )
        fig.update_layout(height=360, margin=dict(l=10, r=10, t=30, b=10), title="Risk vs Threshold")
        st.plotly_chart(fig, use_container_width=True)

    with cB:
        risk_bucket_tables(df_state)


def page_risk_posture():
    st.title("Risk Posture")
    pill_row(hours, topn)

    df_state = fetch_entity_state(limit=topn)
    if df_state.empty:
        st.info("No entity state data found.")
        return

    st.subheader("Top entities")
    risk_cards(df_state.head(4))
    st.divider()

    st.subheader("Risk buckets")
    risk_bucket_tables(df_state)
    st.divider()

    st.subheader("Entity timeline (risk + θ + standardized metrics)")
    opts = (df_state["entity_id"].astype(str) + " | " + df_state["entity_name"].astype(str)).tolist()
    if not opts:
        st.info("No entities available.")
        return

    default_id = st.session_state.get("ctx_entity_id") or df_state.iloc[0]["entity_id"]
    default_index = 0
    for i, o in enumerate(opts):
        if o.startswith(str(default_id) + " |"):
            default_index = i
            break

    selected = st.selectbox("Select entity", opts, index=default_index)
    selected_id = selected.split(" | ")[0].strip()

    df_snap = fetch_snapshots(selected_id, start_iso, end_iso)
    if df_snap.empty:
        st.info("No snapshots found for this entity in the selected window.")
        return

    fig = go.Figure()

    alert_entity_id = st.session_state.get("ctx_entity_id")
    alert_ts = st.session_state.get("ctx_alert_ts")
    if alert_entity_id == selected_id and alert_ts is not None:
        alert_ts_dt = pd.to_datetime(alert_ts, utc=True, errors="coerce")
        if pd.notna(alert_ts_dt):
            x_alert = alert_ts_dt.isoformat()
            fig.add_shape(type="line", x0=x_alert, x1=x_alert, y0=0, y1=1, xref="x", yref="paper", line=dict(dash="dash"))
            fig.add_annotation(x=x_alert, y=1, xref="x", yref="paper", text="RBA alert", showarrow=True, ax=0, ay=-40)

    fig.add_trace(go.Scatter(x=df_snap["ts"], y=df_snap["risk"], mode="lines+markers", name="Risk"))
    fig.add_trace(go.Scatter(x=df_snap["ts"], y=df_snap["threshold"], mode="lines", name="Threshold (θ)"))
    fig.update_layout(height=420, margin=dict(l=10, r=10, t=20, b=10))
    st.plotly_chart(fig, use_container_width=True)

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**z-score over time** (standardized anomaly)")
        if "z" in df_snap.columns and df_snap["z"].notna().any():
            figz = go.Figure()
            figz.add_trace(go.Scatter(x=df_snap["ts"], y=df_snap["z"], mode="lines+markers", name="z"))
            figz.update_layout(height=260, margin=dict(l=10, r=10, t=20, b=10))
            st.plotly_chart(figz, use_container_width=True)
        else:
            st.info("No z values in snapshots yet (new compute script will populate).")

    with c2:
        st.markdown("**ratio over time** (risk/θ)")
        if "ratio" in df_snap.columns and df_snap["ratio"].notna().any():
            figr = go.Figure()
            figr.add_trace(go.Scatter(x=df_snap["ts"], y=df_snap["ratio"], mode="lines+markers", name="ratio"))
            figr.add_hline(y=1.0, line_dash="dash")
            figr.update_layout(height=260, margin=dict(l=10, r=10, t=20, b=10))
            st.plotly_chart(figr, use_container_width=True)
        else:
            st.info("No ratio values in snapshots yet (new compute script will populate).")


def page_alert_triage():
    st.title("Alert Triage (RBA)")
    pill_row(hours, topn)

    df_alerts = fetch_rba_alerts(start_iso, end_iso, limit=200)
    if df_alerts.empty:
        st.info("No RBA alerts found in this time window.")
        return

    df_show = df_alerts[df_alerts["ts"].notna()].copy()
    if df_show.empty:
        st.info("Alerts exist but timestamps are invalid.")
        return

    df_show["ts_str"] = df_show["ts"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    df_show["label"] = df_show.apply(
        lambda r: (
            f'{r["ts_str"]} | {r.get("entity_name")} ({r.get("entity_id")}) | '
            f'risk {_ffloat(r.get("risk")):.2f} | θ {_ffloat(r.get("threshold")):.2f} | '
            f'ratio {_ffloat(r.get("ratio")):.2f} | z {_ffloat(r.get("z")):.2f}'
        ),
        axis=1,
    )

    sel_label = st.selectbox("Select RBA alert", df_show["label"].tolist(), index=0)
    sel = df_show[df_show["label"] == sel_label].iloc[0]

    st.session_state["ctx_entity_id"] = sel.get("entity_id")
    st.session_state["ctx_alert_ts"] = sel.get("ts")

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Risk", f'{_ffloat(sel.get("risk")):.2f}')
    m2.metric("Threshold (θ)", f'{_ffloat(sel.get("threshold")):.2f}')
    m3.metric("ΔRisk", f'{_ffloat(sel.get("delta_risk")):.2f}')
    m4.metric("ratio (R/θ)", f'{_ffloat(sel.get("ratio")):.2f}')
    m5.metric("z", f'{_ffloat(sel.get("z")):.2f}')

    st.markdown(f'**Entity:** {sel.get("entity_name")} (`{sel.get("entity_id")}`)')

    mu, sigma, sigma_capped, k = sel.get("mu"), sel.get("sigma"), sel.get("sigma_capped"), sel.get("k")
    c1, c2 = st.columns(2)
    with c1:
        if pd.notna(mu) and pd.notna(sigma) and pd.notna(k):
            st.markdown(
                f"**θ formula:** θ = μ + kσ (σ may be capped)  \n"
                f"μ={_ffloat(mu):.3f}, σ={_ffloat(sigma):.3f}, σ_capped={_ffloat(sigma_capped):.3f}, k={_ffloat(k):.3f}"
            )
        st.caption(f"Engine gates: R ≥ θ AND ΔR > δ, δ={DELTA_MIN}")

    with c2:
        gate_r = _ffloat(sel.get("risk")) >= _ffloat(sel.get("threshold"))
        gate_d = _ffloat(sel.get("delta_risk")) > DELTA_MIN
        st.markdown("**Gate checks:**")
        st.write(f"R ≥ θ : {'✅' if gate_r else '❌'}")
        st.write(f"ΔR > δ : {'✅' if gate_d else '❌'}")

        bw = sel.get("baseline_window_hours")
        tw = sel.get("time_window_hours")
        hl = sel.get("half_life_minutes")
        st.caption(f"Tw={tw if pd.notna(tw) else hours}h | Baseline={bw if pd.notna(bw) else '—'}h | Half-life={hl if pd.notna(hl) else '—'} min")

    st.divider()

    st.subheader("Alert contributors (rules)")
    contrib = sel.get("contributors_rules") or []
    if not contrib:
        st.info("contributors_rules missing/empty for this alert.")
    else:
        dfc = pd.DataFrame(contrib)
        if "rule_id" in dfc.columns:
            dfc["rule_lookup"] = dfc["rule_id"].astype(str).apply(
                lambda rid: "?" + urlencode(
                    {"view": "rules", "rule_id": rid, "hours": hours, "topn": topn, "autorefresh": int(auto_refresh), "q": search_text, "minlvl": min_rule_level},
                    doseq=True,
                )
            )

        cols = [c for c in ["rule_id", "count", "max_level", "score", "description", "groups", "agent_name"] if c in dfc.columns]
        show_df = dfc[cols + (["rule_lookup"] if "rule_lookup" in dfc.columns else [])] if cols else dfc
        show_df = ensure_unique_columns(show_df)

        st.dataframe(
            show_df,
            use_container_width=True,
            column_config={"rule_lookup": st.column_config.LinkColumn("Rule details", display_text="Open")} if "rule_lookup" in show_df.columns else None,
        )

        if "rule_id" in dfc.columns and "score" in dfc.columns:
            dfp = dfc.copy()
            dfp["rule_id"] = dfp["rule_id"].astype(str)
            dfp = dfp.sort_values("score", ascending=False).head(12)
            figc = go.Figure()
            figc.add_trace(go.Bar(x=dfp["rule_id"], y=dfp["score"]))
            figc.update_layout(height=320, margin=dict(l=10, r=10, t=30, b=10), title="Top contributing rules (score)")
            st.plotly_chart(figc, use_container_width=True)

    st.divider()

    b1, b2 = st.columns([1, 3])
    with b1:
        if st.button("Open Investigation", use_container_width=True):
            qp_set(view="investigation", hours=hours, topn=topn, autorefresh=int(auto_refresh), q=search_text, minlvl=min_rule_level)
            _rerun()
    with b2:
        st.caption("Investigation uses alert context → related raw events → MITRE summary → rule lookup.")

    st.divider()

    st.subheader("Related raw events (entity scope)")
    entity_id = sel.get("entity_id")
    alert_ts = pd.to_datetime(sel.get("ts"), utc=True, errors="coerce")
    if pd.isna(alert_ts):
        st.info("Alert timestamp invalid.")
        return

    explain_h = int(sel.get("contributors_rules_window_hours") or sel.get("time_window_hours") or hours)

    inv_end = alert_ts
    inv_start = alert_ts - timedelta(hours=int(explain_h))
    inv_start_iso, inv_end_iso = iso(inv_start.to_pydatetime()), iso(inv_end.to_pydatetime())

    raw_df = fetch_raw_events(inv_start_iso, inv_end_iso, query_text="", min_rule_level=0, entity_id=entity_id, limit=400)
    if raw_df.empty:
        st.info("No raw events found for this entity in the explain window.")
        return

    show = raw_df[["ts", "agent_name", "rule_id", "rule_level", "rule_desc", "location", "decoder", "has_mitre"]].copy()
    st.dataframe(ensure_unique_columns(show), use_container_width=True)
    render_mitre_section(raw_df, title="MITRE view (for related raw events)")


def page_investigation():
    st.title("Investigation")
    pill_row(hours, topn)

    ctx_entity = st.session_state.get("ctx_entity_id")
    ctx_ts = st.session_state.get("ctx_alert_ts")

    st.subheader("Investigation context")
    c1, c2, c3 = st.columns([1.3, 1, 1])
    with c1:
        entity_override = st.text_input("Entity id (optional)", value=str(ctx_entity) if ctx_entity else "")
    with c2:
        inv_hours = st.selectbox("Investigation window (hours)", [1, 6, 12, 24, 48], index=3)
    with c3:
        minlvl_local = st.slider("Min rule level", 0, 15, int(min_rule_level), 1)

    entity_id = entity_override.strip() if entity_override.strip() else None

    if ctx_ts is not None:
        anchor = pd.to_datetime(ctx_ts, utc=True, errors="coerce")
        if pd.notna(anchor):
            inv_end = anchor
            inv_start = anchor - timedelta(hours=int(inv_hours))
        else:
            inv_start, inv_end = get_time_range(inv_hours)
    else:
        inv_start, inv_end = get_time_range(inv_hours)

    inv_start_iso = iso(inv_start if isinstance(inv_start, datetime) else inv_start.to_pydatetime())
    inv_end_iso = iso(inv_end if isinstance(inv_end, datetime) else inv_end.to_pydatetime())

    raw_df = fetch_raw_events(inv_start_iso, inv_end_iso, query_text=search_text, min_rule_level=minlvl_local, entity_id=entity_id, limit=700)

    st.divider()

    cA, cB = st.columns([1.2, 1])
    with cA:
        st.subheader("Raw events timeline")
        if raw_df.empty:
            st.info("No raw events with current filters.")
        else:
            df_t = raw_df.copy()
            df_t["bucket"] = df_t["ts"].dt.floor("5min")
            counts = df_t.groupby("bucket", as_index=False).size().rename(columns={"size": "count"})
            fig = px.line(counts, x="bucket", y="count")
            fig.update_layout(height=320, margin=dict(l=10, r=10, t=20, b=10))
            st.plotly_chart(fig, use_container_width=True)

    with cB:
        render_mitre_section(raw_df, title="MITRE view (if present)")

    st.divider()

    selected_rule_id = None
    if raw_df is not None and not raw_df.empty and "rule_id" in raw_df.columns:
        vc = raw_df["rule_id"].dropna().astype(str).value_counts()
        if len(vc):
            selected_rule_id = str(vc.index[0])

    rule_lookup_from_raw(raw_df, selected_rule_id)

    st.divider()

    st.subheader("Raw events (filtered)")
    if raw_df.empty:
        st.info("No events for the selected window/filters.")
        return

    show = raw_df[["ts", "agent_name", "agent_id", "rule_id", "rule_level", "rule_desc", "location", "decoder", "has_mitre"]].copy()
    st.dataframe(ensure_unique_columns(show), use_container_width=True)

    download_df = raw_df.copy()
    download_df["raw"] = download_df["raw"].apply(lambda x: json.dumps(x, default=str))
    st.download_button(
        "Download filtered raw events (CSV)",
        data=download_df.to_csv(index=False).encode("utf-8"),
        file_name="raw_events_filtered.csv",
        mime="text/csv",
    )

    with st.expander("Sample raw JSON (latest event)"):
        st.json(raw_df.iloc[0]["raw"])


def page_raw_events():
    st.title("Raw Events")
    pill_row(hours, topn)

    entity_qp = qp_get("entity", "")
    entity_id = entity_qp if entity_qp else st.session_state.get("ctx_entity_id")

    c1, c2, c3 = st.columns([1.2, 1, 1])
    with c1:
        entity_override = st.text_input("Entity filter (optional)", value=str(entity_id) if entity_id else "")
    with c2:
        limit = st.selectbox("Rows", [200, 500, 1000], index=1)
    with c3:
        st.caption("Applies global sidebar filters")

    entity_id_final = entity_override.strip() if entity_override.strip() else None
    raw_df = fetch_raw_events(start_iso, end_iso, query_text=search_text, min_rule_level=int(min_rule_level), entity_id=entity_id_final, limit=int(limit))

    if raw_df.empty:
        st.info("No raw events found for this time window/filters.")
        return

    total = len(raw_df)
    mitre_pct = (raw_df["has_mitre"].sum() / total * 100.0) if total else 0.0

    a1, a2, a3, a4 = st.columns(4)
    a1.metric("Events loaded", f"{total}")
    a2.metric("MITRE coverage", f"{mitre_pct:.1f}%")

    top_rule = "—"
    if raw_df["rule_id"].notna().any():
        top_rule = str(raw_df["rule_id"].dropna().astype(str).value_counts().index[0])
    a3.metric("Top rule_id", top_rule)

    top_agent = "—"
    if raw_df["agent_name"].notna().any():
        top_agent = str(raw_df["agent_name"].dropna().astype(str).value_counts().index[0])
    a4.metric("Top agent", top_agent)

    st.divider()

    cA, cB = st.columns(2)
    with cA:
        st.subheader("Top rules")
        top_rules = raw_df["rule_id"].dropna().astype(str).value_counts().head(12).reset_index()
        top_rules.columns = ["rule_id", "count"]
        fig = px.bar(top_rules, x="rule_id", y="count")
        fig.update_layout(height=320, margin=dict(l=10, r=10, t=20, b=10))
        st.plotly_chart(fig, use_container_width=True)

    with cB:
        st.subheader("Top agents")
        top_agents = raw_df["agent_name"].dropna().astype(str).value_counts().head(12).reset_index()
        top_agents.columns = ["agent_name", "count"]
        fig = px.bar(top_agents, x="agent_name", y="count")
        fig.update_layout(height=320, margin=dict(l=10, r=10, t=20, b=10))
        st.plotly_chart(fig, use_container_width=True)

    st.divider()
    render_mitre_section(raw_df, title="MITRE view (raw events)")

    st.divider()
    st.subheader("Event list")
    show = raw_df[["ts", "agent_name", "rule_id", "rule_level", "rule_desc", "location", "decoder", "has_mitre"]].copy()
    st.dataframe(ensure_unique_columns(show), use_container_width=True)

    with st.expander("Sample raw JSON"):
        st.json(raw_df.iloc[0]["raw"])


def page_rule_lookup():
    st.title("Rule Lookup")
    pill_row(hours, topn)

    rid = st.text_input("Enter rule_id", value=str(qp_get("rule_id", "")) if qp_get("rule_id", "") else "")
    inv_hours = st.selectbox("Lookup window (hours)", [1, 6, 12, 24, 48], index=3)
    s, e = get_time_range(inv_hours)
    s_iso, e_iso = iso(s), iso(e)

    raw_df = fetch_raw_events(s_iso, e_iso, query_text="", min_rule_level=0, entity_id=None, limit=1200)
    if raw_df.empty:
        st.info("No raw events loaded for lookup window.")
        return

    if rid.strip():
        rule_lookup_from_raw(raw_df, rid.strip())
    else:
        top = raw_df["rule_id"].dropna().astype(str).value_counts().head(25).reset_index()
        top.columns = ["rule_id", "count"]
        st.dataframe(ensure_unique_columns(top), use_container_width=True)
        pick = st.selectbox("Pick a rule_id to inspect", options=top["rule_id"].tolist(), index=0)
        rule_lookup_from_raw(raw_df, pick)


def page_cases():
    st.title("Cases")
    pill_row(hours, topn)

    be = cases_backend()
    st.caption(f"Backend: **{be}**")

    df_cases = list_cases()

    st.subheader("Create / Link a case")
    c1, c2, c3 = st.columns([1.2, 1, 1])
    with c1:
        entity_id = st.text_input("Entity id", value=str(st.session_state.get("ctx_entity_id") or ""))
    with c2:
        owner = st.text_input("Owner", value="Admin")
    with c3:
        status = st.selectbox("Status", ["New", "Investigating", "Benign", "Escalated", "Closed"], index=0)

    notes = st.text_area("Notes", value="", height=80)
    tags_txt = st.text_input("Tags (comma-separated)", value="")

    alert_ts = st.session_state.get("ctx_alert_ts")
    entity_name = ""
    try:
        st_state = fetch_entity_state(limit=200)
        if not st_state.empty and entity_id:
            x = st_state[st_state["entity_id"].astype(str) == str(entity_id)]
            if not x.empty:
                entity_name = str(x.iloc[0].get("entity_name") or "")
    except Exception:
        entity_name = ""

    if st.button("Create case", use_container_width=True):
        if not entity_id.strip():
            st.warning("Entity id required.")
        else:
            cid = str(uuid.uuid4())
            doc = {
                "case_id": cid,
                "status": status,
                "owner": owner.strip(),
                "tags": [t.strip() for t in tags_txt.split(",") if t.strip()],
                "notes": notes.strip(),
                "entity_id": entity_id.strip(),
                "entity_name": entity_name,
                "alert_ts": iso(pd.to_datetime(alert_ts, utc=True).to_pydatetime()) if alert_ts is not None else None,
                "created_at": iso(utc_now()),
                "updated_at": iso(utc_now()),
            }
            upsert_case(doc)
            st.success("Case created.")
            _rerun()

    st.divider()

    st.subheader("Case board")
    statuses = ["New", "Investigating", "Benign", "Escalated", "Closed"]

    if df_cases.empty:
        st.info("No cases yet.")
        return

    if "selected_case_id" not in st.session_state:
        st.session_state["selected_case_id"] = None

    cols = st.columns(len(statuses))
    for i, s in enumerate(statuses):
        with cols[i]:
            st.markdown(f"**{s}**")
            chunk = df_cases[df_cases["status"].astype(str) == s].copy()
            if chunk.empty:
                st.caption("—")
            else:
                for _, r in chunk.head(15).iterrows():
                    title = r.get("entity_name") or r.get("entity_id") or "Case"
                    cid = r.get("case_id")
                    ts = r.get("alert_ts")
                    ts_s = ts.strftime("%Y-%m-%d %H:%M") if pd.notna(ts) else ""
                    st.markdown(
                        f"""
<div class="rba-card" style="margin-bottom:10px;">
  <div style="font-weight:700;">{title}</div>
  <div style="opacity:0.75;font-size:12px;">{r.get("entity_id","")} • {ts_s}</div>
  <div style="opacity:0.7;font-size:12px;margin-top:6px;">Owner: {r.get("owner","")}</div>
</div>
""",
                        unsafe_allow_html=True,
                    )
                    if st.button("Open", key=f"open_{cid}", use_container_width=True):
                        st.session_state["selected_case_id"] = cid
                        _rerun()

    st.divider()

    st.subheader("Edit case")
    cid = st.session_state.get("selected_case_id")
    if not cid:
        st.info("Select a case from the board.")
        return

    row = df_cases[df_cases["case_id"].astype(str) == str(cid)]
    if row.empty:
        st.info("Case not found.")
        return
    r = row.iloc[0].to_dict()

    e1, e2, e3 = st.columns([1.2, 1, 1])
    with e1:
        st.text_input("Case id", value=str(r.get("case_id")), disabled=True)
        entity_id = st.text_input("Entity id", value=str(r.get("entity_id") or ""))
        entity_name = st.text_input("Entity name", value=str(r.get("entity_name") or ""))
    with e2:
        status = st.selectbox("Status", statuses, index=statuses.index(str(r.get("status") or "New")))
        owner = st.text_input("Owner", value=str(r.get("owner") or ""))
    with e3:
        tags_txt = st.text_input("Tags (comma-separated)", value=",".join([str(t) for t in (r.get("tags") or [])]))
        alert_ts = r.get("alert_ts")
        st.text_input("Alert ts", value=alert_ts.strftime("%Y-%m-%d %H:%M:%S UTC") if pd.notna(alert_ts) else "", disabled=True)

    notes = st.text_area("Notes", value=str(r.get("notes") or ""), height=120)

    b1, b2, b3 = st.columns([1, 1, 2])
    with b1:
        if st.button("Save changes", use_container_width=True):
            doc = {
                "case_id": str(r.get("case_id")),
                "status": status,
                "owner": owner.strip(),
                "tags": [t.strip() for t in tags_txt.split(",") if t.strip()],
                "notes": notes.strip(),
                "entity_id": entity_id.strip(),
                "entity_name": entity_name.strip(),
                "alert_ts": iso(alert_ts.to_pydatetime()) if pd.notna(alert_ts) else None,
                "created_at": iso(pd.to_datetime(r.get("created_at"), utc=True).to_pydatetime()) if pd.notna(pd.to_datetime(r.get("created_at"), utc=True, errors="coerce")) else iso(utc_now()),
                "updated_at": iso(utc_now()),
            }
            upsert_case(doc)
            st.success("Saved.")
            _rerun()

    with b2:
        if st.button("Delete case", use_container_width=True):
            delete_case(str(r.get("case_id")))
            st.session_state["selected_case_id"] = None
            st.success("Deleted.")
            _rerun()

    with b3:
        st.download_button(
            "Download cases JSON",
            data=df_cases.to_json(orient="records", date_format="iso").encode("utf-8"),
            file_name="rba_cases.json",
            mime="application/json",
        )

    st.divider()
    st.subheader("All cases")
    show = ensure_unique_columns(df_cases.copy())
    st.dataframe(show, use_container_width=True)


# =========================
# Route
# =========================
if view == "overview":
    page_overview()
elif view == "risk":
    page_risk_posture()
elif view == "alerts":
    page_alert_triage()
elif view == "investigation":
    page_investigation()
elif view == "raw":
    page_raw_events()
elif view == "rules":
    page_rule_lookup()
elif view == "cases":
    page_cases()
else:
    page_overview()

st.caption("RBA = entity-centric risk aggregation + exponential decay + adaptive thresholding + standardized scoring (ratio/z) + risk-velocity gating.")
