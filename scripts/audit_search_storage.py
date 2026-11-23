"""Read-only post-cleanup Spiffy Search / connected-service storage inventory.

Confines walking to Search target and old generated artifacts. Never traverses
symlinks or junctions, never touches Telegram, MemoryCore/Voice databases,
installed application state or original user assets.
"""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import time

SS=Path(__file__).resolve().parents[2]
SEARCH=SS/"Spiffy Search"
R=SS/"_reports"/"ss-scripts-cleanup"
REPORT=R/"20261115_spiffy_search_storage_post_audit.json"
LOCAL=Path(os.environ.get("LOCALAPPDATA",""))
ROOTS={
 "search_target":SEARCH/"target",
 "search_artifacts":SEARCH/"artifacts",
 "search_tests":SEARCH/"tests",
 "search_runtime":LOCAL/"SpiffySearch",
 "search_install":LOCAL/"Programs"/"SpiffySearch",
 "shelf_installed_logs":LOCAL/"SpiffyShelf"/"logs",
}
BUDGET=60
start=time.monotonic()
result={
 "schema":"spiffy_search_followup_storage_audit_v1",
 "created_utc":datetime.now(timezone.utc).isoformat(),
 "read_only":True,
 "protected":"Installed apps, profiles, active indexes, logs, Voice Archive, MemoryCore, Clipboard and all Telegram are immutable in this audit.",
 "free_bytes":{name:shutil.disk_usage(name+":\\").free for name in ("C","D","H")},
 "roots":{},
}
def measure(root):
    data={"files":0,"logical_bytes":0,"folders":0,
          "state":"complete","junctions":0,"errors":[],
          "newest_mtime_utc":None,"oldest_mtime_utc":None,
          "big_files":[],"extensions":{}}
    sizes=[]; oldest=time.time(); latest=0; ex=Counter()
    stack=[root]
    while stack:
        if time.monotonic()-start>BUDGET:
            data["state"]="partial_budget"
            data["unscanned_folders"]=len(stack)
            break
        folder=stack.pop()
        try:
            with os.scandir(folder) as entries:
                for item in entries:
                    try:
                        s=item.stat(follow_symlinks=False)
                        if item.is_symlink() or getattr(s,"st_file_attributes",0)&0x400:
                            data["junctions"]+=1
                        elif item.is_dir(follow_symlinks=False):
                            data["folders"]+=1
                            stack.append(item.path)
                        elif item.is_file(follow_symlinks=False):
                            data["files"]+=1
                            data["logical_bytes"]+=s.st_size
                            ex[Path(item.name).suffix.lower()]+=1
                            oldest=min(oldest,s.st_mtime)
                            latest=max(latest,s.st_mtime)
                            if s.st_size>64*1024**2:
                                sizes.append((s.st_size,str(Path(item.path).relative_to(root))))
                    except OSError as e:
                        if len(data["errors"])<4:data["errors"].append(str(e))
        except OSError as e:
            if len(data["errors"])<4:data["errors"].append(str(e))
    if data["files"]:
        data["newest_mtime_utc"]=datetime.fromtimestamp(latest,timezone.utc).isoformat()
        data["oldest_mtime_utc"]=datetime.fromtimestamp(oldest,timezone.utc).isoformat()
    data["big_files"]=sorted(sizes,reverse=True)[:6]
    data["extensions"]=ex.most_common(12)
    return data

for name,root in ROOTS.items():
    if not root.exists():
        result["roots"][name]={"state":"absent","root":str(root)}
        continue
    row={"root":str(root),"state":"inprogress","children":{}}
    result["roots"][name]=row
    for child in root.iterdir():
        try:
            s=child.stat(follow_symlinks=False)
            if child.is_symlink() or getattr(s,"st_file_attributes",0)&0x400:
                row["children"][child.name]={"state":"junction_skipped","logical_bytes":0}
            elif child.is_dir():
                row["children"][child.name]=measure(child)
            elif child.is_file():
                row["children"][child.name]={"state":"file","files":1,"logical_bytes":s.st_size}
        except OSError as e:
            row["children"][child.name]={"state":"error","error":str(e),"logical_bytes":0}
    row["state"]="complete" if time.monotonic()-start<=BUDGET else "partial_budget"
    row["logical_bytes"]=sum(v.get("logical_bytes",0) for v in row["children"].values())
result["finished_utc"]=datetime.now(timezone.utc).isoformat()
result["elapsed_seconds"]=round(time.monotonic()-start,2)
REPORT.parent.mkdir(parents=True,exist_ok=True)
REPORT.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf8")
print(json.dumps({
 "schema":result["schema"],
 "elapsed_seconds":result["elapsed_seconds"],
 "roots":{name:{"GiB":round(item.get("logical_bytes",0)/2**30,3),
               "state":item["state"],
               "top":[{"name":subname,"GiB":round(data.get("logical_bytes",0)/2**30,3),
                       "files":data.get("files",0),
                       "junctions":data.get("junctions",0),
                       "state":data["state"]}
                      for subname,data in sorted(item.get("children",{}).items(),
                                                key=lambda x:x[1].get("logical_bytes",0),
                                                reverse=True)[:7]]}
          for name,item in result["roots"].items()},
 "report":str(REPORT)},indent=2))
