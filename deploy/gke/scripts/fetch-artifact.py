#!/usr/bin/env python3
"""Extract a day2 artifact from an app image's top layer (images/app puts it
there), verified by digest, into OUTPUT/<artifact_id>. No Docker needed.

  fetch-artifact.py IMAGE@sha256:... ARTIFACT_ID OUTPUT   (token: $REGISTRY_TOKEN)
"""
import hashlib, io, json, os, sys, tarfile, urllib.request

image, artifact_id, output = sys.argv[1:]
token = os.environ["REGISTRY_TOKEN"]
host, rest = image.split("/", 1)
repo, digest = rest.split("@")
assert digest.startswith("sha256:") and len(digest) == 71, "image must be pinned by digest"

def get(path, accept):
    req = urllib.request.Request(f"https://{host}/v2/{repo}/{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": accept})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()

def verified(data, want):
    got = "sha256:" + hashlib.sha256(data).hexdigest()
    assert got == want, f"digest mismatch {got} != {want}"
    return data

INDEX = "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"
doc = json.loads(verified(get(f"manifests/{digest}", INDEX + "," + MANIFEST), digest))
if "manifests" in doc:
    amd = [m for m in doc["manifests"] if m.get("platform", {}).get("architecture") == "amd64" and m.get("platform", {}).get("os") == "linux"]
    assert len(amd) == 1, "expected exactly one linux/amd64 manifest"
    doc = json.loads(verified(get(f"manifests/{amd[0]['digest']}", MANIFEST), amd[0]["digest"]))
top = doc["layers"][-1]
blob = verified(get(f"blobs/{top['digest']}", "*/*"), top["digest"])
prefix = f"srv/day2/artifacts/{artifact_id}/"
with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tar:
    members = [m for m in tar.getmembers() if m.name.lstrip("./").startswith(prefix)]
    assert members, f"top layer holds no {prefix}"
    for m in members:
        assert not (m.issym() or m.islnk() or m.isdev()), f"refusing {m.name}"
        m.name = m.name.lstrip("./")[len("srv/day2/artifacts/"):]
    tar.extractall(output, members=members, filter="tar")
meta = json.load(open(os.path.join(output, artifact_id, "artifact.json")))
print(json.dumps({"artifact_dir": os.path.join(output, artifact_id), "files": len(members), "layer": top["digest"]}))
