#!/bin/sh
# Builds one commit, or a Dockerfile that Coolify sent, through BuildKit and
# pushes it to the external registry of the cluster, with the read-only
# Docker config /run/coolify-image/config.json when the registry needs a login.
# A localhost/ image is not pushed: the build writes a docker archive to
# /coolify/out/image.tar, and Sentinel loads it into the Podman store.
# Sentinel validates every argument before it starts this container. The
# script never evaluates an argument as shell code.
#
# Arguments: --repository URL --commit SHA --type dockerfile|railpack
#            --base-directory DIR --dockerfile PATH --image REF
#            [--push-image REF] [--target STAGE] [--static-root DIR]
#            [--untrusted-source] [--skip-submodules] [--skip-lfs]
#            [--full-history]
# Without --repository, the build uses /run/coolify-build/dockerfile/Dockerfile
# with an empty context. Build-time variables are read-only files from
# Sentinel: /run/coolify-build/args/<KEY> become build args, and
# /run/coolify-build/secrets/<KEY> become BuildKit secret mounts, never build
# args. Their values are never in an argument of this container or in its
# environment. Railpack takes both as secrets.
# With --static-root, a Railpack build serves only the files of DIR (relative
# to the base directory) with the Railpack staticfile provider, also when the
# source has a package.json.
# With --push-image, a second BuildKit run from the cache pushes the same
# build to that external image. Its login, if any, is the read-only Docker
# config /run/coolify-push/config.json, used only for that push.
# With --untrusted-source (a pull request from a fork), the Git credential
# opens only the repository of --repository: an HTTPS token answers only for
# its path, and an SSH key fetches only the commit. Submodules and Git LFS
# objects of other repositories get no credential. The Git LFS objects of an
# untrusted SSH repository are not pulled, because the key fetches only the
# commit.
# Git options (decision 0033 of Coolify): --skip-submodules skips the
# submodules, --skip-lfs keeps the Git LFS pointer files, and --full-history
# fetches the commit and the submodules without --depth=1. Submodules accept
# only https and ssh URLs. A failed Git LFS pull fails the build.
# The last line of a successful build is:
#   COOLIFY_BUILD_RESULT {"digest":"sha256:..."}
set -eu

repository='' commit='' type='' base_directory='' dockerfile='' image='' push_image='' target='' static_root='' untrusted=''
skip_submodules='' skip_lfs='' full_history=''
while [ $# -gt 0 ]; do
  case "$1" in
    --untrusted-source) untrusted=1; shift; continue ;;
    --skip-submodules) skip_submodules=1; shift; continue ;;
    --skip-lfs) skip_lfs=1; shift; continue ;;
    --full-history) full_history=1; shift; continue ;;
  esac
  [ $# -ge 2 ] || { echo "error: $1 needs a value" >&2; exit 2; }
  case "$1" in
    --repository) repository=$2 ;;
    --commit) commit=$2 ;;
    --type) type=$2 ;;
    --base-directory) base_directory=$2 ;;
    --dockerfile) dockerfile=$2 ;;
    --image) image=$2 ;;
    --push-image) push_image=$2 ;;
    --target) target=$2 ;;
    --static-root) static_root=$2 ;;
    *) echo "error: unknown argument $1" >&2; exit 2 ;;
  esac
  shift 2
done
inline_dockerfile=/run/coolify-build/dockerfile
args_dir=/run/coolify-build/args
secrets_dir=/run/coolify-build/secrets
[ -n "$type" ] && [ -n "$image" ] || { echo "error: --type and --image are required" >&2; exit 2; }
[ -n "$repository" ] && [ -n "$commit" ] || [ -f "$inline_dockerfile/Dockerfile" ] ||
  { echo "error: --repository and --commit are required without an inline Dockerfile" >&2; exit 2; }

step() { printf '==> %s\n' "$*"; }

# A private repository comes with one read-only file from Sentinel. The
# credential stays in it: never in a URL, an argument, or the environment, so
# Git output cannot show it. The helper answers only for the repository host,
# so a submodule or redirect to another host never gets the token. For an
# untrusted source, it answers only for the path of the repository (Git
# selects credential.<url> by path prefix), with and without `.git`, which
# also covers its LFS endpoint `<path>.git/info/lfs`.
# Sentinel mounts the credential at /run/coolify-git; the unit tests set another directory.
git_credentials=${COOLIFY_GIT_CREDENTIALS:-/run/coolify-git}
ssh_options='-o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
key_ssh="ssh -i $git_credentials/ssh-key $ssh_options"
if [ -f "$git_credentials/token" ]; then
  helper="!f() { test \"\$1\" = get || return 0; echo username=x-access-token; echo \"password=\$(cat '$git_credentials/token')\"; }; f"
  if [ -n "$untrusted" ]; then
    path=${repository%/}
    path=${path%.git}
    git config --global "credential.$path.helper" "$helper"
    git config --global "credential.$path.git.helper" "$helper"
  else
    host=${repository#https://}
    host=${host%%/*}
    git config --global "credential.https://$host.helper" "$helper"
  fi
elif [ -f "$git_credentials/ssh-key" ]; then
  # An untrusted source uses the key only for the fetch of the commit below.
  if [ -n "$untrusted" ]; then
    export GIT_SSH_COMMAND="ssh -o IdentityFile=none $ssh_options"
  else
    export GIT_SSH_COMMAND="$key_ssh"
  fi
fi

# The unit tests set another source directory.
source_dir=${COOLIFY_BUILD_SOURCE:-/home/build/source}
if [ -n "$repository" ]; then
  # Only https and ssh: no local paths, git://, http://, or ext:: URLs, also
  # not in a .gitmodules of the source.
  set -- -c protocol.allow=never -c protocol.https.allow=always -c protocol.ssh.allow=always
  if [ -n "$full_history" ]; then
    depth='' depth_text='full history'
  else
    depth=--depth=1 depth_text='depth 1'
  fi
  # The checkout keeps the Git LFS pointer files. The LFS step below pulls
  # the objects, so that its error shows in the build log.
  export GIT_LFS_SKIP_SMUDGE=1
  step "Fetching commit $commit ($depth_text)"
  git init --quiet "$source_dir"
  git -C "$source_dir" remote add origin "$repository"
  if [ -f "$git_credentials/ssh-key" ]; then
    GIT_SSH_COMMAND="$key_ssh" git -C "$source_dir" "$@" fetch --quiet ${depth:+"$depth"} origin "$commit"
  else
    git -C "$source_dir" "$@" fetch --quiet ${depth:+"$depth"} origin "$commit"
  fi
  git -C "$source_dir" checkout --quiet FETCH_HEAD
  if [ -f "$source_dir/.gitmodules" ]; then
    if [ -n "$skip_submodules" ]; then
      step "Skipping submodules (turned off)"
    else
      step "Fetching submodules ($depth_text)"
      git -C "$source_dir" "$@" submodule update --quiet --init --recursive ${depth:+"$depth"}
    fi
  fi
  if [ -n "$(git -C "$source_dir" lfs ls-files -n)" ]; then
    if [ -n "$skip_lfs" ]; then
      step "Skipping Git LFS objects (turned off)"
    elif [ -n "$untrusted" ] && [ -f "$git_credentials/ssh-key" ]; then
      step "Skipping Git LFS objects (the source is not trusted, and the SSH key fetches only the commit)"
    else
      step "Fetching Git LFS objects"
      unset GIT_LFS_SKIP_SMUDGE
      git -C "$source_dir" "$@" lfs pull
    fi
  fi
else
  mkdir -p "$source_dir"
fi

# file_value FILE prints the file as it is, trailing newlines included.
file_value() { value=$(cat "$1"; printf x); printf '%s' "${value%x}"; }
# variable_file KEY prints the file of a build arg or a build secret.
variable_file() { if [ -f "$args_dir/$1" ]; then printf '%s' "$args_dir/$1"; else printf '%s' "$secrets_dir/$1"; fi; }
# The positional parameters become the variable options of every BuildKit
# run. Keys are validated by Sentinel ([A-Za-z_][A-Za-z0-9_]*).
set --
secret_keys=''
for file in "$args_dir"/* "$secrets_dir"/*; do
  [ -f "$file" ] || continue
  key=${file##*/}
  case "$type:$file" in
    dockerfile:"$args_dir"/*) set -- "$@" --opt "build-arg:$key=$(file_value "$file")" ;;
    *) set -- "$@" --secret "id=$key,src=$file"; secret_keys="$secret_keys $key" ;;
  esac
done

context=$source_dir/${base_directory:-.}
[ -d "$context" ] || { echo "error: the base directory ${base_directory:-.} does not exist" >&2; exit 1; }

metadata=/home/build/metadata.json
case "$image" in
  localhost/*) output="type=docker,name=$image,dest=/coolify/out/image.tar" ;;
  *) output="type=image,name=$image,push=true" ;;
esac
case "$type" in
  dockerfile)
    if [ -n "$repository" ]; then
      dockerfile=${dockerfile:-Dockerfile}
      [ -f "$context/$dockerfile" ] || { echo "error: $dockerfile does not exist in ${base_directory:-.}" >&2; exit 1; }
      dockerfile_dir=$(dirname "$context/$dockerfile")
      step "Building with $dockerfile"
    else
      dockerfile=Dockerfile dockerfile_dir=$inline_dockerfile
      step "Building the Dockerfile of the application"
    fi
    [ -n "$static_root" ] && { echo "error: --static-root needs --type railpack" >&2; exit 2; }
    [ -z "$target" ] || set -- "$@" --opt "target=$target"
    # build OUTPUT METADATA [OPTION...]
    build() {
      build_output=$1 build_metadata=$2
      shift 2
      buildctl build --progress plain --frontend dockerfile.v0 \
        --local context="$context" \
        --local dockerfile="$dockerfile_dir" \
        --opt filename="$(basename "$dockerfile")" \
        "$@" \
        --output "$build_output" --metadata-file "$build_metadata"
    }
    ;;
  railpack)
    [ -z "$target" ] || { echo "error: --target needs --type dockerfile" >&2; exit 2; }
    plan_dir=/home/build/plan
    mkdir -p "$plan_dir"
    static_env=''
    if [ -n "$static_root" ]; then
      publish_dir=$context/$static_root
      [ -d "$publish_dir" ] || { echo "error: the publish directory $static_root does not exist" >&2; exit 1; }
      [ -n "$(find "$publish_dir" -type f | head -n 1)" ] || { echo "error: the publish directory $static_root has no files" >&2; exit 1; }
      # Our config file replaces the railpack.json of the source, so it
      # contains the keys of that file. Our provider has priority.
      static_config=$plan_dir/railpack-static.json
      if [ -f "$context/railpack.json" ]; then
        jq '. + {"provider": "staticfile"}' "$context/railpack.json" > "$static_config" 2>/dev/null ||
          { echo "error: railpack.json in ${base_directory:-.} is not a valid JSON object" >&2; exit 1; }
      else
        printf '{"provider":"staticfile"}\n' > "$static_config"
      fi
      # Railpack reads --config-file relative to the source directory. The
      # config is outside the source, so go up from the context to
      # /home/build: one step for each segment of the base directory and one
      # for source.
      up=../
      old_ifs=$IFS IFS=/
      for segment in ${base_directory:-.}; do
        case "$segment" in ''|.) ;; *) up=$up../ ;; esac
      done
      IFS=$old_ifs
      static_env="--config-file ${up}plan/railpack-static.json --env RAILPACK_STATIC_FILE_ROOT"
      step "Serving the files of $static_root (static)"
      # Railpack makes each --env variable a secret of the plan, so BuildKit
      # needs this one as a secret too.
      printf '%s' "$static_root" > "$plan_dir/static-root"
      set -- "$@" --secret "id=RAILPACK_STATIC_FILE_ROOT,src=$plan_dir/static-root"
    fi
    step "Preparing the Railpack plan"
    # Railpack puts only the names of --env variables into the plan. A name
    # without a value is read from the environment of this one process.
    (
      for key in $secret_keys; do
        export "$key=$(file_value "$(variable_file "$key")")"
      done
      [ -z "$static_root" ] || export RAILPACK_STATIC_FILE_ROOT="$static_root"
      # shellcheck disable=SC2086
      railpack prepare "$context" $static_env $(for key in $secret_keys; do printf -- '--env %s ' "$key"; done) \
        --plan-out "$plan_dir/railpack-plan.json" --info-out "$plan_dir/info.json"
    )
    # BuildKit does not see a changed secret value, so Railpack mounts this
    # hash into the layers that use secrets.
    if [ -n "$secret_keys" ]; then
      secrets_hash=$(for key in $secret_keys; do printf '%s\n' "$key"; cat "$(variable_file "$key")"; printf '\n'; done | sha256sum)
      set -- "$@" --opt "build-arg:secrets-hash=${secrets_hash%% *}"
    fi
    step "Building with Railpack"
    build() {
      build_output=$1 build_metadata=$2
      shift 2
      buildctl build --progress plain --frontend gateway.v0 \
        --opt source="$RAILPACK_FRONTEND" \
        --local context="$context" \
        --local dockerfile="$plan_dir" \
        --opt filename=railpack-plan.json \
        "$@" \
        --output "$build_output" --metadata-file "$build_metadata"
    }
    ;;
  *)
    echo "error: unknown build type $type" >&2; exit 2 ;;
esac
# An external image (the image storage of the cluster) can have its own login.
image_config=$DOCKER_CONFIG
[ -f /run/coolify-image/config.json ] && image_config=/run/coolify-image
(export DOCKER_CONFIG="$image_config"; build "$output" "$metadata" "$@")

if [ -n "$push_image" ]; then
  step "Pushing $push_image"
  push_config=$DOCKER_CONFIG
  [ -f /run/coolify-push/config.json ] && push_config=/run/coolify-push
  (export DOCKER_CONFIG="$push_config"; build "type=image,name=$push_image,push=true" /home/build/push-metadata.json "$@") || {
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
