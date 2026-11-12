#!/bin/sh
# Builds one commit through BuildKit and pushes it to the cluster registry.
# A localhost/ image is not pushed: the build writes a docker archive to
# /coolify/out/image.tar, and Sentinel loads it into the Podman store.
# Sentinel validates every argument before it starts this container. The
# script never evaluates an argument as shell code.
#
# Arguments: --repository URL --commit SHA --type dockerfile|railpack
#            --base-directory DIR --dockerfile PATH --image REF
#            [--push-image REF]
# With --push-image, a second BuildKit run from the cache pushes the same
# build to that external image. Its login, if any, is the read-only Docker
# config /run/coolify-push/config.json, used only for that push.
# The last line of a successful build is:
#   COOLIFY_BUILD_RESULT {"digest":"sha256:..."}
set -eu

repository='' commit='' type='' base_directory='' dockerfile='' image='' push_image=''
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || { echo "error: $1 needs a value" >&2; exit 2; }
  case "$1" in
    --repository) repository=$2 ;;
    --commit) commit=$2 ;;
    --type) type=$2 ;;
    --base-directory) base_directory=$2 ;;
    --dockerfile) dockerfile=$2 ;;
    --image) image=$2 ;;
    --push-image) push_image=$2 ;;
    *) echo "error: unknown argument $1" >&2; exit 2 ;;
  esac
  shift 2
done
[ -n "$repository" ] && [ -n "$commit" ] && [ -n "$type" ] && [ -n "$image" ] ||
  { echo "error: --repository, --commit, --type, and --image are required" >&2; exit 2; }

step() { printf '==> %s\n' "$*"; }

# A private repository comes with one read-only file from Sentinel. The
# credential stays in it: never in a URL, an argument, or the environment, so
# Git output cannot show it. The helper answers only for the repository host,
# so a submodule or redirect to another host never gets the token.
if [ -f /run/coolify-git/token ]; then
  host=${repository#https://}
  host=${host%%/*}
  git config --global "credential.https://$host.helper" \
    '!f() { test "$1" = get || return 0; echo username=x-access-token; echo "password=$(cat /run/coolify-git/token)"; }; f'
elif [ -f /run/coolify-git/ssh-key ]; then
  export GIT_SSH_COMMAND='ssh -i /run/coolify-git/ssh-key -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
fi

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
case "$image" in
  localhost/*) output="type=docker,name=$image,dest=/coolify/out/image.tar" ;;
  *) output="type=image,name=$image,push=true" ;;
esac
# build OUTPUT METADATA runs BuildKit with the frontend of the build type.
case "$type" in
  dockerfile)
    dockerfile=${dockerfile:-Dockerfile}
    [ -f "$context/$dockerfile" ] || { echo "error: $dockerfile does not exist in ${base_directory:-.}" >&2; exit 1; }
    step "Building with $dockerfile"
    build() {
      buildctl build --progress plain --frontend dockerfile.v0 \
        --local context="$context" \
        --local dockerfile="$(dirname "$context/$dockerfile")" \
        --opt filename="$(basename "$dockerfile")" \
        --output "$1" --metadata-file "$2"
    }
    ;;
  railpack)
    plan_dir=/home/build/plan
    mkdir -p "$plan_dir"
    step "Preparing the Railpack plan"
    railpack prepare "$context" --plan-out "$plan_dir/railpack-plan.json" --info-out "$plan_dir/info.json"
    step "Building with Railpack"
    build() {
      buildctl build --progress plain --frontend gateway.v0 \
        --opt source="$RAILPACK_FRONTEND" \
        --local context="$context" \
        --local dockerfile="$plan_dir" \
        --opt filename=railpack-plan.json \
        --output "$1" --metadata-file "$2"
    }
    ;;
  *)
    echo "error: unknown build type $type" >&2; exit 2 ;;
esac
build "$output" "$metadata"

if [ -n "$push_image" ]; then
  step "Pushing $push_image"
  push_config=$DOCKER_CONFIG
  [ -f /run/coolify-push/config.json ] && push_config=/run/coolify-push
  (export DOCKER_CONFIG="$push_config"; build "type=image,name=$push_image,push=true" /home/build/push-metadata.json) || {
    echo "error: the push to $push_image failed. Check the image name and the registry credential of the application." >&2
    exit 1
  }
fi

digest=$(jq -r '."containerimage.digest" // empty' "$metadata")
case "$digest" in
  sha256:*) ;;
  *) echo "error: BuildKit returned no image digest" >&2; exit 1 ;;
esac
case "$image" in
  localhost/*) step "Built $image" ;;
  *) step "Pushed $image" ;;
esac
printf 'COOLIFY_BUILD_RESULT {"digest":"%s"}\n' "$digest"
