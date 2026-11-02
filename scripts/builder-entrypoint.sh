#!/bin/sh
# Builds one commit through BuildKit and pushes it to the cluster registry.
# Sentinel validates every argument before it starts this container. The
# script never evaluates an argument as shell code.
#
# Arguments: --repository URL --commit SHA --type dockerfile|railpack
#            --base-directory DIR --dockerfile PATH --image REF
# The last line of a successful build is:
#   COOLIFY_BUILD_RESULT {"digest":"sha256:..."}
set -eu

repository='' commit='' type='' base_directory='' dockerfile='' image=''
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || { echo "error: $1 needs a value" >&2; exit 2; }
  case "$1" in
    --repository) repository=$2 ;;
    --commit) commit=$2 ;;
    --type) type=$2 ;;
    --base-directory) base_directory=$2 ;;
    --dockerfile) dockerfile=$2 ;;
    --image) image=$2 ;;
    *) echo "error: unknown argument $1" >&2; exit 2 ;;
  esac
  shift 2
done
[ -n "$repository" ] && [ -n "$commit" ] && [ -n "$type" ] && [ -n "$image" ] ||
  { echo "error: --repository, --commit, --type, and --image are required" >&2; exit 2; }

step() { printf '==> %s\n' "$*"; }

source_dir=/home/build/source
step "Fetching commit $commit"
git init --quiet "$source_dir"
git -C "$source_dir" remote add origin "$repository"
git -C "$source_dir" -c protocol.file.allow=never fetch --quiet --depth=1 origin "$commit"
git -C "$source_dir" checkout --quiet FETCH_HEAD
if [ -f "$source_dir/.gitmodules" ]; then
  step "Fetching submodules"
  git -C "$source_dir" -c protocol.file.allow=never submodule update --quiet --init --recursive --depth=1
fi
git -C "$source_dir" lfs pull 2>/dev/null || true

context=$source_dir/${base_directory:-.}
[ -d "$context" ] || { echo "error: the base directory ${base_directory:-.} does not exist" >&2; exit 1; }

metadata=/home/build/metadata.json
output="type=image,name=$image,push=true"
case "$type" in
  dockerfile)
    dockerfile=${dockerfile:-Dockerfile}
    [ -f "$context/$dockerfile" ] || { echo "error: $dockerfile does not exist in ${base_directory:-.}" >&2; exit 1; }
    step "Building with $dockerfile"
    buildctl build --progress plain --frontend dockerfile.v0 \
      --local context="$context" \
      --local dockerfile="$(dirname "$context/$dockerfile")" \
      --opt filename="$(basename "$dockerfile")" \
      --output "$output" --metadata-file "$metadata"
    ;;
  railpack)
    plan_dir=/home/build/plan
    mkdir -p "$plan_dir"
    step "Preparing the Railpack plan"
    railpack prepare "$context" --plan-out "$plan_dir/railpack-plan.json" --info-out "$plan_dir/info.json"
    step "Building with Railpack"
    buildctl build --progress plain --frontend gateway.v0 \
      --opt source="$RAILPACK_FRONTEND" \
      --local context="$context" \
      --local dockerfile="$plan_dir" \
      --opt filename=railpack-plan.json \
      --output "$output" --metadata-file "$metadata"
    ;;
  *)
    echo "error: unknown build type $type" >&2; exit 2 ;;
esac

digest=$(jq -r '."containerimage.digest" // empty' "$metadata")
case "$digest" in
  sha256:*) ;;
  *) echo "error: BuildKit returned no image digest" >&2; exit 1 ;;
esac
step "Pushed $image"
printf 'COOLIFY_BUILD_RESULT {"digest":"%s"}\n' "$digest"
