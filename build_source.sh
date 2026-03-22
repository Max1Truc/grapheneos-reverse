#!/bin/bash
set -euo pipefail

export BUILD_NUMBER="$1"
export BUILD_DATETIME="$2"
export OFFICIAL_BUILD=true

if [ -z "${BUILD_NUMBER}" -o -z "${BUILD_DATETIME}" ]
then
	echo missing parameters BUILD_NUMBER and BUILD_DATETIME
	exit 1
fi

echo '[..] BUILDING'

source build/envsetup.sh
yarn --cwd vendor/adevtool/ install
adevtool generate-all -d tegu
lunch tegu-cur-user
m vendorbootimage vendorkernelbootimage target-files-package

echo '[OK] BUILD SUCCESS'
echo '[..] Creating key files'

mkdir -p keys/tegu
cd keys/tegu
CN=GrapheneOS
echo "" | ../../development/tools/make_key releasekey "/CN=$CN/"
echo "" | ../../development/tools/make_key platform "/CN=$CN/"
echo "" | ../../development/tools/make_key shared "/CN=$CN/"
echo "" | ../../development/tools/make_key media "/CN=$CN/"
echo "" | ../../development/tools/make_key networkstack "/CN=$CN/"
echo "" | ../../development/tools/make_key bluetooth "/CN=$CN/"
echo "" | ../../development/tools/make_key sdk_sandbox "/CN=$CN/"
echo "" | ../../development/tools/make_key gmscompat_lib "/CN=$CN/"
echo "" | ../../development/tools/make_key nfc "/CN=$CN/"
openssl genrsa 4096 | openssl pkcs8 -topk8 -scrypt -out avb.pem -passout pass:
echo "" | python -c "import pty; pty.spawn('../../external/avb/avbtool.py extract_public_key --key avb.pem --output avb_pkmd.bin'.split(' '))"
cd ../..

ssh-keygen -t ed25519 -f keys/tegu/id_ed25519 -N ""

echo '[OK] key files'
echo '[..] Creating release files'

m otatools-package
script/finalize.sh
script/generate-release.sh tegu "$BUILD_NUMBER"
