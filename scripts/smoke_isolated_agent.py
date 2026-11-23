"""Native search-index smoke with a synthetic D: profile only.

Starts/stops the already installed Search binaries under private D: synthetic
LOCALAPPDATA/APPDATA. Never touches real Search config, root list, clipboard,
MemoryCore or Voice Archive. Reports only timings and fixture metadata.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import time
from datetime import datetime, timezone
import uuid

OUT=Path(os.environ.get("SPIFFY_SEARCH_AUDIT_DIR", str(Path.home()/".spiffy-search-audit")))/"20261115_spiffy_search_native_synthetic_smoke.json"
EXE=Path(os.environ.get("SPIFFY_SEARCH_CLI", str(Path(os.environ.get("LOCALAPPDATA",""))/"Programs"/"SpiffySearch"/"spiffy-searchctl.exe")))
ROOT=Path(os.environ.get("SPIFFY_SEARCH_SMOKE_DIR", str(Path(os.environ.get("TEMP","."))/"Spiffy Search QA")))
RUN=ROOT/("synthetic-"+uuid.uuid4().hex[:8])
PROFILE=RUN/"profile"
LOCAL=PROFILE/"local"
ROAM=PROFILE/"roaming"
FILES=RUN/"fake-files"
ENV=os.environ.copy()
ENV.update({"LOCALAPPDATA":str(LOCAL),"APPDATA":str(ROAM),
            "SPIFFY_SEARCH_LOG_LEVEL":"error"})
RPT={"schema":"spiffy_search_synthetic_agent_smoke_v1",
     "started_utc":datetime.now(timezone.utc).isoformat(),
     "profile_isolated":True,"real_user_index_touched":False,
     "fixture_files":0,"checks":[],"complete":False}
def command(args,timeout=12):
    begin=time.perf_counter()
    proc=subprocess.run([str(EXE),"--json",*args],stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE,env=ENV,cwd=PROFILE,
                       timeout=timeout,check=False,
                       creationflags=subprocess.CREATE_NO_WINDOW)
    ms=round((time.perf_counter()-begin)*1000,2)
    try:
        data=json.loads(proc.stdout.decode("utf-8-sig"))
    except (UnicodeError,ValueError):
        data={"ok":False}
    return proc.returncode,data,ms
def check(op,args,timeout=12):
    code,data,elapsed=command(args,timeout)
    success=(code==0 and data.get("ok") is True)
    RPT["checks"].append({"op":op,"ok":success,"exit_code":code,"elapsed_ms":elapsed,
                          "error_code":None if success else data.get("code","malformed")})
    return success,data,elapsed

def main():
    if not EXE.is_file():raise RuntimeError("Installed Search CLI missing")
    if RUN.exists():raise RuntimeError("Unexpected fixture collision")
    for p in (PROFILE,LOCAL,ROAM,FILES):
        p.mkdir(parents=True,exist_ok=True)
    for i in range(240):
        sub=FILES/("shots" if i%2 else "audio")
        sub.mkdir(exist_ok=True)
        path=sub/f"snowfall-scene-{i:04d}-s01e01.txt"
        path.write_text(f"synthetic file only {i:04d}",encoding="utf8")
    RPT["fixture_files"]=240
    try:
        passed,build,elapsed=check("build-info",["build-info"])
        if not passed:raise RuntimeError("Synthetic installed binary build-info failed")
        passed,start,elapsed=check("start",["start"],timeout=30)
        if not passed:raise RuntimeError("Synthetic agent start failed")
        passed,roots,elapsed=check("add-root",["root","add",str(FILES)])
        if not passed:raise RuntimeError("Synthetic add root failed")
        # Adding a root may already start background reconciliation.
        # Issuing an extra reindex during that job truthfully returns
        # indexing_busy; it is not an indexing failure.
        RPT["index_owner"] = "root-add automatic reconciliation"
        deadline=time.monotonic()+35
        state={}
        while time.monotonic()<deadline:
            passed,state,elapsed=check("status",["status"])
            info=state.get("data",{})
            if passed and isinstance(info,dict) and info.get("indexed_documents",0)>=240:
                break
            time.sleep(0.6)
        else:
            raise RuntimeError("Synthetic index did not admit 240 files before deadline")
        query_ms=[]
        rows=[]
        for j in range(30):
            passed,reply,elapsed=check("query",["search","snowfall-scene","--limit","10"])
            if not passed:raise RuntimeError("Synthetic search failed")
            hits=reply.get("data",{}).get("hits",[])
            query_ms.append(elapsed)
            rows.append(len(hits))
        query_ms.sort()
        RPT["query"]={"runs":len(query_ms),
                      "median_ms":statistics.median(query_ms),
                      "p95_ms":query_ms[int(0.95*(len(query_ms)-1))],
                      "max_ms":max(query_ms),
                      "min_hits":min(rows),"max_hits":max(rows)}
        RPT["complete"]=True
    finally:
        try:
            passed,_,ms=check("stop",["stop"],timeout=18)
            RPT["graceful_stop"]=passed
        except Exception:
            RPT["graceful_stop"]=False
        # Synthetic-only cleanup. A failed stop means retain fixture/profile
        # and report it; never remove a running agent's state from underneath.
        if RPT.get("graceful_stop"):
            try:
                shutil.rmtree(RUN)
                RPT["fixture_cleaned"]=not RUN.exists()
            except Exception as err:
                RPT["fixture_cleaned"]=False
                RPT["cleanup_failure_type"]=type(err).__name__
        else:
            RPT["fixture_cleaned"]=False
        RPT["finished_utc"]=datetime.now(timezone.utc).isoformat()
        OUT.parent.mkdir(parents=True,exist_ok=True)
        OUT.write_text(json.dumps(RPT,indent=2,ensure_ascii=False)+"\n",encoding="utf8")
    print(json.dumps({"complete":RPT["complete"],
                     "query":RPT.get("query"),
                     "graceful_stop":RPT.get("graceful_stop"),
                     "fixture_cleaned":RPT.get("fixture_cleaned"),
                     "check_counts":len(RPT["checks"]),
                     "profile_isolated":True,
                     "report":str(OUT)},indent=2))

if __name__=="__main__":
    main()
