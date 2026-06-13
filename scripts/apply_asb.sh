#!/bin/bash

echo 'WARNING: this is work-in-progress!'

# usage: ./asb.sh <YYYY-MM | latest>
[ -z "$1" ] && { echo "usage: $0 <YYYY-MM>" >&2; exit 1; }

month="$1"
echo "Using bulletin $month" >&2
curl -s "https://source.android.com/docs/security/bulletin/${month%-*}/$month-01" |
grep -oE 'https://android\.googlesource[^"]+' |
while read -r url; do
    sub=${url#https://android.googlesource.com/platform/}; sub=${sub%%/+/*}
    curl -s -- "$url?format=TEXT" | base64 -d | patch -p1 -N -f -s -d "$sub" --dry-run &&
        echo "$sub ok" || echo "$sub KO"
    sleep 1
done
