#!/bin/bash
set -eo pipefail

if [ -z "${GOS_BUILD_NUMBER}" ]
then
	echo missing env GOS_BUILD_NUMBER
	exit 1
fi

# Initial builder preparation.
export OFFICIAL_BUILD=true
mkdir -pv ~/.ssh
curl -sL https://grapheneos.org/allowed_signers > ~/.ssh/grapheneos_allowed_signers
git config --global user.name "grapheneos"
git config --global user.email "grapheneos-build@localhost"
git config --global color.ui false
if [[ -f "/.gitcookies" ]]; then
  git config --global http.cookiefile /.gitcookies
fi

# Fetch OS source code tree.
echo "[INFO] Fetching OS tree..."
mkdir -p "/opt/build/grapheneos/grapheneos-${GOS_BUILD_NUMBER}"
cd "/opt/build/grapheneos/grapheneos-${GOS_BUILD_NUMBER}"
repo init --partial-clone --depth=1 -u https://github.com/GrapheneOS/platform_manifest.git -b "refs/tags/${GOS_BUILD_NUMBER}"
cd .repo/manifests
git config gpg.ssh.allowedSignersFile ~/.ssh/grapheneos_allowed_signers
git verify-tag $(git describe)
cd ../..
repo sync -j8 --retry-fetches=6 --force-sync --no-clone-bundle --no-tags
