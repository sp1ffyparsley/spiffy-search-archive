"""Read-only summary of existing Spiffy Search activation and indexing scope.

Reads only configuration booleans and SQLite source-root counts. No actual
file paths, tokens, titles, content or queries are logged or printed.
"""
from __future__ import annotations
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3

ROOT=Path(os.environ.get("LOCALAPPDATA",""))/"SpiffySearch"
REPORT=Path(os.environ.get("SPIFFY_SEARCH_AUDIT_DIR", str(Path.home()/".spiffy-search-audit")))/"20261115_spiffy_search_profile_activation_audit.json"
def main():
    configfile=ROOT/"search-config.json"
    database=ROOT/"search.db"
    result={"schema":"spiffy_search_current_profile_readonly_v1",
        "utc":datetime.now(timezone.utc).isoformat(),
        "read_only":True,
        "configuration_present":configfile.is_file(),
        "database_present":database.is_file(),
        "endpoint_present":(ROOT/"ipc-endpoint.json").is_file(),
        "secrets_or_paths_reported":False}
    if result["configuration_present"]:
        config=json.loads(configfile.read_text(encoding="utf-8-sig"))
        for key in ("initial_scan_on_start","start_hidden","include_hidden","include_system"):
            if key in config:result[key]=config[key]
        result["workspace_catalog_enabled"]=bool(config.get("workspace_catalog_path"))
        result["content_index_enabled"]=bool((config.get("content") or {}).get("enabled"))
        result["local_api_enabled"]=bool((config.get("local_api") or {}).get("enabled"))
        result["browser_history_enabled"]=any(
            x is True for k,x in (config.get("browsers") or {}).items()
            if k in ("chrome","edge","firefox","safari"))
    if result["database_present"]:
        uri=database.as_uri()+"?mode=ro&immutable=1"
        with sqlite3.connect(uri,uri=True,timeout=1) as db:
            db.execute("pragma query_only=on")
            tables={v[0] for v in db.execute(
              "select name from sqlite_master where type='table'")}
            if "source_roots" in tables:
                total,enabled=db.execute("select count(*),sum(case when enabled=1 then 1 else 0 end) from source_roots").fetchone()
                result["root_count"]=total
                result["enabled_root_count"]=enabled or 0
            if "index_state" in tables:
                fields={v[1] for v in db.execute("pragma table_info(index_state)")}
                if "indexed_documents" in fields:
                    value=db.execute("select indexed_documents from index_state limit 1").fetchone()
                    result["indexed_documents_recorded"]=value[0] if value else 0
    REPORT.parent.mkdir(parents=True,exist_ok=True)
    REPORT.write_text(json.dumps(result,indent=2)+"\n",encoding="utf8")
    print(json.dumps(result,indent=2))
if __name__=="__main__":
    main()
