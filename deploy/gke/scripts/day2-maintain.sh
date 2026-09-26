#!/usr/bin/env bash
# Run one day2 operation against a stopped app on GKE, from the qualified
# tooling image with the app's state volume mounted.
#
#   day2-maintain.sh [options] inspect
#   day2-maintain.sh [options] backup
#   day2-maintain.sh [options] authority-apply REQUEST_ID
#   day2-maintain.sh [options] activate NEW_INSTANCE_JSON NEW_APP_IMAGE NEW_ARTIFACT_ID REQUEST_ID
#
# Options (all required unless noted):
#   --namespace NS            app namespace
#   --statefulset NAME        the app's StatefulSet (one replica)
#   --configmap NAME          the app's instance ConfigMap (key instance.json)
#   --app ID                  the day2 app name inside instance.json
#   --app-image IMG@sha256:   the image the StatefulSet runs now
#   --artifact-id HEX         the artifact that image carries
#   --tooling-image IMG@sha256:  tooling of the same platform build
#   --pvc NAME                the app's state PVC
#   --operator NAME           recorded as the local operator (e.g. your email)
#   --backup-dir DIR          local private directory for backups (optional;
#                             default ~/day2-backups/<namespace>)
#   --yes                     do not ask before activation (optional)
#
# Every operation except inspect first takes and verifies a day2 backup and
# copies it to --backup-dir. The app is stopped for the whole run: the
# maintenance pod is the only process opening the volume. The pod is always
# removed. inspect, backup and authority-apply restore the StatefulSet's
# replicas at the end. activate does NOT: the old image cannot serve the
# newly activated artifact, so apply the day2-app plan for the new image next,
# which restores the replica.
#
# Needs kubectl (context set by KUBECONFIG), gcloud (registry token), jq,
# python3. Reads only the app's own namespace.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
template="$here/../k8s/maintenance-pod.yaml"
namespace="" statefulset="" configmap="" app="" app_image="" artifact_id=""
tooling_image="" pvc="" operator="" backup_root="" yes=0
while [[ $# -gt 0 && "$1" == --* ]]; do
  case "$1" in
    --namespace) namespace="$2"; shift 2 ;;
    --statefulset) statefulset="$2"; shift 2 ;;
    --configmap) configmap="$2"; shift 2 ;;
    --app) app="$2"; shift 2 ;;
    --app-image) app_image="$2"; shift 2 ;;
    --artifact-id) artifact_id="$2"; shift 2 ;;
    --tooling-image) tooling_image="$2"; shift 2 ;;
    --pvc) pvc="$2"; shift 2 ;;
    --operator) operator="$2"; shift 2 ;;
    --backup-dir) backup_root="$2"; shift 2 ;;
    --yes) yes=1; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
operation="${1:?operation: inspect | backup | authority-apply | activate}"
shift
for v in namespace statefulset configmap app app_image artifact_id tooling_image pvc operator; do
  [[ -n "${!v}" ]] || { echo "--${v//_/-} is required" >&2; exit 2; }
done
for image in "$app_image" "$tooling_image"; do
  [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || { echo "$image must be pinned by digest" >&2; exit 2; }
done
[[ "$artifact_id" =~ ^[0-9a-f]{64}$ ]] || { echo "--artifact-id must be 64 hex" >&2; exit 2; }
case "$operation" in
  inspect | backup) [[ $# -eq 0 ]] || { echo "$operation takes no arguments" >&2; exit 2; } ;;
  authority-apply) [[ $# -eq 1 ]] || { echo "authority-apply REQUEST_ID" >&2; exit 2; } ;;
  activate)
    [[ $# -eq 4 ]] || { echo "activate NEW_INSTANCE_JSON NEW_APP_IMAGE NEW_ARTIFACT_ID REQUEST_ID" >&2; exit 2; }
    [[ -f "$1" ]] || { echo "new instance $1 not found" >&2; exit 2; }
    [[ "$2" =~ @sha256:[0-9a-f]{64}$ && "$3" =~ ^[0-9a-f]{64}$ ]] || { echo "new image must be pinned; new artifact 64 hex" >&2; exit 2; }
    ;;
  *) echo "unknown operation $operation" >&2; exit 2 ;;
esac

k() { kubectl -n "$namespace" "$@"; }
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
pod="day2-maintenance-$(printf %s "$stamp" | tr "[:upper:]" "[:lower:]")"
work="$(mktemp -d)"
chmod 700 "$work"
backup_root="${backup_root:-$HOME/day2-backups/$namespace}"
install -d -m 0700 "$backup_root"

replicas="$(k get statefulset "$statefulset" -o jsonpath='{.spec.replicas}')"
running_image="$(k get statefulset "$statefulset" -o jsonpath='{.spec.template.spec.containers[0].image}')"
[[ "$running_image" == "$app_image" ]] ||
  { echo "the StatefulSet runs $running_image, not --app-image $app_image" >&2; exit 1; }

echo "== artifacts from the app images (digest-verified)"
token="$(gcloud auth print-access-token)"
REGISTRY_TOKEN="$token" python3 "$here/fetch-artifact.py" "$app_image" "$artifact_id" "$work/artifacts" >/dev/null
if [[ "$operation" == activate ]]; then
  REGISTRY_TOKEN="$token" python3 "$here/fetch-artifact.py" "$2" "$3" "$work/artifacts" >/dev/null
fi
unset token
k get configmap "$configmap" -o jsonpath='{.data.instance\.json}' >"$work/current-instance.json"
[[ -s "$work/current-instance.json" ]] || { echo "ConfigMap $configmap has no instance.json" >&2; exit 1; }

restore_replicas=1
cleanup() {
  local status=$?
  k delete pod "$pod" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  if [[ $restore_replicas -eq 1 && "$replicas" != 0 ]]; then
    echo "== restoring $statefulset to $replicas replica(s)"
    k scale statefulset "$statefulset" --replicas="$replicas" >/dev/null
    k rollout status statefulset "$statefulset" --timeout=300s >/dev/null || echo "WARNING: $statefulset is not ready yet" >&2
  fi
  # Extracted artifacts are write-protected (day2 requires it).
  chmod -R u+w "$work" 2>/dev/null || true
  rm -rf "$work"
  exit $status
}
trap cleanup EXIT

echo "== stopping $statefulset (was $replicas replica(s))"
k scale statefulset "$statefulset" --replicas=0 >/dev/null
k wait --for=delete "pod/${statefulset}-0" --timeout=300s >/dev/null 2>&1 || true
[[ -z "$(k get pods -l "app.kubernetes.io/name=$statefulset" -o name 2>/dev/null)" ]] ||
  { echo "a pod of $statefulset is still running" >&2; exit 1; }

echo "== maintenance pod $pod"
DAY2_MAINT_NAMESPACE="$namespace" DAY2_MAINT_POD="$pod" DAY2_MAINT_TOOLING_IMAGE="$tooling_image" \
DAY2_MAINT_PVC="$pvc" DAY2_MAINT_SERVICE_LABEL_KEY="internal-tools.wonderly.io/service" \
DAY2_MAINT_SERVICE_LABEL_VALUE="background" DAY2_MAINT_DEADLINE_SECONDS=3600 \
  perl -pe 's/\$\{(DAY2_MAINT_[A-Z_]+)\}/exists $ENV{$1} ? $ENV{$1} : die "unset $1\n"/ge' "$template" | k apply -f - >/dev/null
k wait --for=condition=Ready "pod/$pod" --timeout=600s >/dev/null
k exec "$pod" -- mkdir -p /srv/day2/artifacts
for dir in "$work/artifacts"/*; do
  k cp "$dir" "$pod:/srv/day2/artifacts/$(basename "$dir")" >/dev/null
done
k cp "$work/current-instance.json" "$pod:/srv/day2/current-instance.json" >/dev/null

# day2-host exits 0 even when a workflow fails: always check .ok.
workflow() {
  local request
  request="$(python3 -c 'import json,sys; print(json.dumps({"protocol":1,"action":"workflow","input":json.dumps(sys.argv[1:])}))' "$@")"
  k exec "$pod" -- /workspace/platform/cli/day2-host "$request" | python3 -c '
import json, sys
v = json.load(sys.stdin)
if v.get("ok") is not True:
    sys.exit("day2-host: " + str(v.get("error")))
print(v["result"])'
}
current_stamp() { # instance -> JSON {epoch, revision}
  workflow authority inspect "$1" "$app" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["active"]["stamp"]))'
}

if [[ "$operation" != inspect ]]; then
  echo "== backup (current instance)"
  workflow backup /srv/day2/current-instance.json "$app" "/srv/day2/backup-$stamp" >/dev/null
  # kubectl cp creates the destination directory (an existing one would nest).
  k cp "$pod:/srv/day2/backup-$stamp" "$backup_root/$stamp" >/dev/null
  cp "$work/current-instance.json" "$backup_root/$stamp/instance.json"
  chmod -R go-rwx "$backup_root/$stamp"
  echo "   verified backup copied to $backup_root/$stamp"
fi

case "$operation" in
  inspect)
    workflow authority inspect /srv/day2/current-instance.json "$app" | python3 -c '
import json, sys
a = json.load(sys.stdin)
act = a.get("active") or {}
doc = act.get("document", {})
print(json.dumps({"scope": a.get("scope"), "stamp": act.get("stamp"), "artifact": act.get("artifact_id"),
  "readers": len(doc.get("readers", [])), "writers": len(doc.get("writers", [])),
  "operations": len((doc.get("policy") or {}).get("operations", {}))}, indent=1))'
    ;;
  backup) ;;
  authority-apply)
    expected="$(current_stamp /srv/day2/current-instance.json)"
    echo "== authority apply (expected $expected)"
    workflow authority apply /srv/day2/current-instance.json "$app" "$operator" "$expected" "$1"
    ;;
  activate)
    new_instance="$1" new_artifact="$3" request_id="$4"
    k cp "$new_instance" "$pod:/srv/day2/instance.json" >/dev/null
    echo "== migration plan to $new_artifact"
    k exec "$pod" -- /workspace/platform/target/debug/day2 migration-plan /srv/day2/instance.json "$app" \
      "/srv/day2/artifacts/$new_artifact" /srv/day2/migration-plan.json >/dev/null
    k exec "$pod" -- cat /srv/day2/migration-plan.json | tee "$backup_root/$stamp/migration-plan.json"
    if [[ $yes -ne 1 ]]; then
      read -r -p "Type 'activate' to apply this migration and activate $new_artifact: " answer
      [[ "$answer" == activate ]] || { echo "not activated"; exit 1; }
    fi
    k exec "$pod" -- /workspace/platform/target/debug/day2 migration-apply /srv/day2/instance.json "$app" \
      "/srv/day2/artifacts/$new_artifact" /srv/day2/migration-plan.json
    expected="$(current_stamp /srv/day2/current-instance.json)"
    echo "== authority activate (expected $expected)"
    workflow authority activate /srv/day2/instance.json "$app" "/srv/day2/artifacts/$new_artifact" \
      "$operator" "$expected" "$request_id"
    # The old image cannot serve the new artifact: leave the app stopped.
    restore_replicas=0
    echo
    echo "Activated. $statefulset stays at 0 replicas: apply the day2-app plan for"
    echo "the new image now (a fresh plan shows replicas 0 -> 1)."
    ;;
esac
