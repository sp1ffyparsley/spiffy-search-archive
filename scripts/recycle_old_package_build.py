"""Recycle obsolete Spiffy Search Cargo package-build *cache*, never its ZIP.

Only the fixed target/package-build directory qualifies, after a fresh
no-reparse / NTFS hardlink / age / artifact-integrity check. The final
operation uses Windows Recycle Bin, not permanent deletion. It does not
modify the source, live Search indexes or installed programs.
"""
from __future__ import annotations
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import zipfile

R=Path(os.environ.get("SPIFFY_SEARCH_AUDIT_DIR", str(Path.home()/".spiffy-search-audit")))
SEARCH=Path(__file__).resolve().parents[1]
TARGET=SEARCH/"target"/"package-build"
ART=SEARCH/"artifacts"/"x86_64-pc-windows-msvc"
ZIP=ART/"SpiffySearch-x86_64-pc-windows-msvc-portable.zip"
CHECKSUM=ART/"SHA256SUMS.txt"
SAMPLE=R/"20261115_followup_build_subtree_scan.json"
RECEIPT=R/"20261115_spiffy_search_package_build_recycle.json"
EXPECTED_BINARIES={
 "spiffy-search-agent.exe","spiffy-searchctl.exe",
 "spiffy-search-content-worker.exe","spiffy-search-mcp.exe",
 "spiffy-file-dialog-bridge.exe"}
TYPE_BLOCK={".sqlite",".sqlite3",".db",".db-wal",".mkv",".mov",".mp4",
            ".wav",".flac",".mp3",".safetensors",".gguf",".pt",".pth",
            ".prproj",".aep",".aepx",".psd",".psb"}
ROOT_BLOCK={".git",".venv","models","media","originals","projects"}
class HandleInformation(ctypes.Structure):
    _fields_=[("file_attributes",ctypes.c_uint32),("created",ctypes.c_ulonglong),
    ("accessed",ctypes.c_ulonglong),("modified",ctypes.c_ulonglong),
    ("volume",ctypes.c_uint32),("size_hi",ctypes.c_uint32),("size_lo",ctypes.c_uint32),
    ("links",ctypes.c_uint32),("index_hi",ctypes.c_uint32),("index_lo",ctypes.c_uint32)]
kernel=ctypes.WinDLL("kernel32",use_last_error=True)
kernel.CreateFileW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p]
kernel.CreateFileW.restype=ctypes.c_void_p
kernel.GetFileInformationByHandle.argtypes=[ctypes.c_void_p,ctypes.POINTER(HandleInformation)]
kernel.CloseHandle.argtypes=[ctypes.c_void_p]
def native_id(path):
    h=kernel.CreateFileW(str(path),0,7,None,3,0,None)
    if h in (None,ctypes.c_void_p(-1).value):
        raise RuntimeError("Could not inspect NTFS hardlink identity")
    try:
        info=HandleInformation()
        if not kernel.GetFileInformationByHandle(h,ctypes.byref(info)):
            raise RuntimeError("Could not query native NTFS file ID")
        if not info.links or not (info.index_hi or info.index_lo):
            raise RuntimeError("Unknown native NTFS file identity")
        return (info.volume,info.index_hi,info.index_lo),info.links
    finally:
        kernel.CloseHandle(h)

def verify_checksum():
    if not ZIP.is_file() or not CHECKSUM.is_file():
        raise RuntimeError("Packaged portable ZIP/checksums absent")
    line=CHECKSUM.read_text(encoding="utf8").strip()
    if ZIP.name not in line:
        raise RuntimeError("Checksum file lacks expected package")
    sha=line.split()[0].lower()
    h=hashlib.sha256()
    with ZIP.open("rb") as file:
        for part in iter(lambda:file.read(2**20),b""):
            h.update(part)
    if sha!=h.hexdigest():
        raise RuntimeError("Release portable ZIP checksum mismatch")
    with zipfile.ZipFile(ZIP,"r") as z:
        names={Path(item.filename).name for item in z.infolist() if not item.is_dir()}
        if not EXPECTED_BINARIES.issubset(names):
            raise RuntimeError("Release portable archive lacks expected binaries")
        if "PACKAGE_MANIFEST.txt" not in names:
            raise RuntimeError("Release portable manifest missing")
    return sha

def scan():
    if not (SEARCH/"Cargo.toml").is_file() or not (SEARCH/".git").is_dir():
        raise RuntimeError("Source Git and Cargo identity unavailable")
    if not TARGET.is_dir() or TARGET.is_symlink() or TARGET.resolve().parent!=(SEARCH/"target").resolve():
        raise RuntimeError("Expected package-build cache path unavailable")
    cache=TARGET/"x86_64-pc-windows-msvc"/"qualified-source.sha256"
    if not cache.is_file():
        raise RuntimeError("Recognized package-build cache identity missing")
    age=time.time()-TARGET.stat().st_ctime
    if age<30*24*3600:
        raise RuntimeError("Cache created less than 30 days ago")
    rows=json.loads(SAMPLE.read_text(encoding="utf8"))
    prior=rows["roots"]["search_target"]["groups"]["package-build"]
    if prior["state"]!="complete" or prior["errors"] or prior["reparse"]:
        raise RuntimeError("Independent cache scan not complete")
    cmd=subprocess.run(["tasklist","/fo","csv","/nh"],capture_output=True,
                       text=True,encoding="utf8",errors="replace",timeout=20,check=True)
    import csv
    for row in csv.reader(cmd.stdout.splitlines()):
        if row and row[0].casefold() in {
             "cargo.exe","rustc.exe","spiffy-search-agent.exe","spiffy-searchctl.exe",
             "spiffy-search-content-worker.exe","spiffy-search-mcp.exe"}:
            raise RuntimeError("Compiler or Search executable currently running: "+row[0])
    total=0;count=0;seen={};latest=0
    stack=[TARGET]
    while stack:
        directory=stack.pop()
        with os.scandir(directory) as files:
            for f in files:
                stat=f.stat(follow_symlinks=False)
                if f.is_symlink() or getattr(stat,"st_file_attributes",0)&0x400:
                    raise RuntimeError("Junction/symlink in old cache")
                if f.is_dir(follow_symlinks=False):
                    if f.name.lower() in ROOT_BLOCK:
                        raise RuntimeError("Unexpected protected source/user folder")
                    stack.append(Path(f.path))
                elif f.is_file(follow_symlinks=False):
                    if Path(f.name).suffix.casefold() in TYPE_BLOCK:
                        raise RuntimeError("User media/project/model data inside package cache")
                    if time.time()-max(stat.st_ctime,stat.st_mtime)<30*24*3600:
                        raise RuntimeError("Package compiler file was recently modified")
                    key,nlinks=native_id(f.path)
                    old=seen.get(key,(0,nlinks))
                    if old[1]!=nlinks:raise RuntimeError("Native hardlink identity changed")
                    seen[key]=(old[0]+1,nlinks)
                    total+=stat.st_size
                    count+=1
                    latest=max(latest,stat.st_mtime)
    if any(count!=links for count,links in seen.values()):
        raise RuntimeError("Package-build files have external NTFS hardlinks")
    if count!=prior["files"] or total!=prior["bytes"]:
        raise RuntimeError("Package cache changed from independent scan")
    return {"file_count":count,"logical_bytes":total,
            "latest_mtime":latest,"release_zip_sha256":verify_checksum()}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--apply",action="store_true")
    args=parser.parse_args()
    evidence={"schema":"spiffy_search_old_package_build_recycle_v1",
              "operation":"recycle" if args.apply else "preflight",
              "started_utc":datetime.now(timezone.utc).isoformat(),
              "target":str(TARGET),"preserved":str(ART),
              "status":"PREFLIGHT",
              "before_C_free":shutil.disk_usage("C:\\").free}
    try:
        data=scan()
        evidence.update(data)
        evidence["status"]="VERIFIED_FOR_RECYCLE"
        if args.apply:
            # Use actual Windows shell recycle, not shutil.rmtree or force
            # delete. Noninteractive and exact path; failures are surfaced.
            ps = r"""
Add-Type -AssemblyName Microsoft.VisualBasic
$p=$args[0]
[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory(
  $p,
  [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,
  [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin,
  [Microsoft.VisualBasic.FileIO.UICancelOption]::ThrowException
)
"""
            invocation=subprocess.run(["powershell.exe","-NoProfile",
             "-ExecutionPolicy","Bypass","-Command",ps,str(TARGET)],
             stdout=subprocess.PIPE,stderr=subprocess.PIPE,
             timeout=180,creationflags=subprocess.CREATE_NO_WINDOW)
            if invocation.returncode:
                raise RuntimeError("Windows Recycle Bin operation was unsuccessful")
            if TARGET.exists():
                raise RuntimeError("Old cache remains at its original path after recycling")
            evidence["status"]="RECYCLED"
        evidence["after_C_free"]=shutil.disk_usage("C:\\").free
    except BaseException as e:
        evidence["status"]="HOLD"
        evidence["error_type"]=type(e).__name__
        evidence["reason"]=str(e)
    evidence["finished_utc"]=datetime.now(timezone.utc).isoformat()
    RECEIPT.write_text(json.dumps(evidence,indent=2,ensure_ascii=False)+"\n",encoding="utf8")
    print(json.dumps(evidence,ensure_ascii=False,indent=2))
    return 0 if evidence["status"] in ("VERIFIED_FOR_RECYCLE","RECYCLED") else 2
if __name__=="__main__":
    raise SystemExit(main())
