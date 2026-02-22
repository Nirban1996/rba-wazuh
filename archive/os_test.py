import os
from dotenv import load_dotenv
from opensearchpy import OpenSearch

load_dotenv()

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

# 1) Cluster info
info = client.info()
print("Connected OK")
print("Cluster:", info.get("cluster_name"))
print("Version:", info.get("version", {}).get("number"))

# 2) Pull 1 latest alert
resp = client.search(
    index="wazuh-alerts-*",
    body={
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp", "agent.id", "agent.name", "rule.id", "rule.level", "rule.groups", "rule.description"],
        "query": {"match_all": {}},
    },
)

hit = resp["hits"]["hits"][0]["_source"]
print("\nLatest alert:")
print("ts:", hit.get("@timestamp"))
print("agent:", hit.get("agent", {}))
print("rule:", hit.get("rule", {}))
