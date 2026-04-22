#!/bin/bash
set -exo pipefail

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
lunch tegu-cur-user
m

echo '[OK] BUILD SUCCESS'
