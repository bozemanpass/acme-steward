#!/usr/bin/python3
"""Verify a delivered certificate directory meets the node-side contract.

usage: check-contract ROOT NAME [--version V] [--max-versions N]

Prints the current version on success; exits 1 with reasons otherwise.
"""
import argparse, hashlib, json, os, pwd, stat, sys

p = argparse.ArgumentParser()
p.add_argument("root")
p.add_argument("name")
p.add_argument("--version")
p.add_argument("--max-versions", type=int)
p.add_argument("--owner", default="certdeploy")
a = p.parse_args()

errors = []
d = os.path.join(a.root, a.name)
cur = os.path.join(d, "current")
if not os.path.islink(cur):
    sys.exit(f"FAIL {cur} is not a symlink")
target = os.readlink(cur)
if "/" in target:
    errors.append(f"current -> {target} is not a sibling directory")
vdir = os.path.join(d, target)
if not os.path.isdir(vdir):
    sys.exit(f"FAIL current -> {target} does not exist")

with open(os.path.join(vdir, "manifest.json")) as f:
    m = json.load(f)
if m["version"] != target:
    errors.append(f"manifest version {m['version']} != current {target}")
if m["name"] != a.name:
    errors.append(f"manifest name {m['name']} != {a.name}")
if a.version and target != a.version:
    errors.append(f"current is {target}, expected {a.version}")

for fn, want in m["sha256"].items():
    path = os.path.join(vdir, fn)
    with open(path, "rb") as f:
        got = hashlib.sha256(f.read()).hexdigest()
    if got != want:
        errors.append(f"{fn}: sha256 mismatch")

with open(os.path.join(vdir, "fullchain.pem"), "rb") as f:
    full = f.read()
with open(os.path.join(vdir, "cert.pem"), "rb") as f:
    leaf = f.read()
if not full.startswith(leaf):
    errors.append("fullchain.pem does not start with cert.pem")

st = os.stat(os.path.join(vdir, "privkey.pem"))
if stat.S_IMODE(st.st_mode) & 0o077:
    errors.append(f"privkey.pem mode {oct(stat.S_IMODE(st.st_mode))} is group/world accessible")

uid = pwd.getpwnam(a.owner).pw_uid
for dirpath, dirnames, filenames in os.walk(d):
    for n in dirnames + filenames:
        path = os.path.join(dirpath, n)
        if n.startswith(".tmp") or n.endswith(".tmp"):
            errors.append(f"leftover temporary {path}")
        if os.lstat(path).st_uid != uid:
            errors.append(f"{path} not owned by {a.owner}")

versions = [e for e in os.listdir(d) if os.path.isdir(os.path.join(d, e)) and not os.path.islink(os.path.join(d, e))]
if a.max_versions is not None and len(versions) > a.max_versions:
    errors.append(f"{len(versions)} versions present, max {a.max_versions}: {sorted(versions)}")

if errors:
    print("FAIL " + a.name + ":\n  " + "\n  ".join(errors))
    sys.exit(1)
print(target)
