#!/usr/bin/env bash
# Regenerate rpms.lock.yaml from rpms.in.yaml using konflux-ci's
# rpm-lockfile-prototype, run from its official container image so no local
# dnf/skopeo/python3-dnf is required. Needs only podman (or docker) plus
# network access to registry.access.redhat.com and the Hummingbird repos.
#
# Run from the repository root:
#
#   ./hack/gen-rpm-lockfile.sh
#
# Regenerate whenever rpms.in.yaml or the base image digest in the
# Containerfile changes. Commit the resulting rpms.lock.yaml.
set -euo pipefail

# Base image the builder stage uses; the tool reads its /etc/yum.repos.d/ for
# the Hummingbird repo definitions. Keep in sync with the builder FROM in
# Containerfile.
BASE_IMAGE="${BASE_IMAGE:-registry.access.redhat.com/hi/python:3.12-builder@sha256:e383f6e33a4a1bfb77562c1254b3b2d8c00aaa2e73c9d64043f88f49d5c11d7f}"
ARCH="${ARCH:-x86_64}"
TOOL_IMAGE="${TOOL_IMAGE:-localhost/rpm-lockfile-prototype}"

engine="$(command -v podman || command -v docker || true)"
if [ -z "${engine}" ]; then
  echo "error: podman or docker is required" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${repo_root}"

if [ ! -f rpms.in.yaml ]; then
  echo "error: rpms.in.yaml not found in ${repo_root}" >&2
  exit 1
fi

echo ">>> Building rpm-lockfile-prototype image (${TOOL_IMAGE})"
curl -fsSL \
  https://raw.githubusercontent.com/konflux-ci/rpm-lockfile-prototype/refs/heads/main/Containerfile \
  | "${engine}" build -t "${TOOL_IMAGE}" -

echo ">>> Resolving RPMs against ${BASE_IMAGE} (${ARCH})"
"${engine}" run --rm -v "${PWD}:/work:Z" "${TOOL_IMAGE}:latest" \
  --image "${BASE_IMAGE}" \
  --arch "${ARCH}" \
  --outfile=rpms.lock.yaml \
  rpms.in.yaml

echo ">>> Wrote rpms.lock.yaml"
