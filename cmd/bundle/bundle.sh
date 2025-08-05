#!/bin/bash

rm -rf bundle || true
rm bundle.tar.gz || true
RELEASE_VERSION=${GITHUB_REF/refs\/tags\/v/}

IDS=("$@")

make_grep_pattern() {
    local pattern=""
    for id in "${IDS[@]}"; do
        if [[ -z "$pattern" ]]; then
            pattern="id: $id"
        else
            pattern="$pattern|id: $id"
        fi
    done
    echo "$pattern"
}

grep_pattern=$(make_grep_pattern)
echo "Patttern: $grep_pattern"

rsync_with_content_filter() {
    local src="$1"
    local dst="$2"

    if [ ${#IDS[@]} -eq 0 ]; then
        echo "No IDs passed, skipping content filtering."
        rsync -avr --exclude=README.md --exclude="*_test.rego" --exclude='*.'{go,yml,yaml} \
            --exclude=compliance --exclude=test "$src" "$dst"
        return
    fi

    EXCLUDES='README.md|.*_test\.rego$|.*\.(go|yml|yaml)$|compliance'
    tmpfile=$(mktemp)

    find "$src" -type f | while read -r absfile; do
        relfile="${absfile#$src}"
        if grep -qE "$grep_pattern" "$absfile"; then
            continue
        fi
        if echo "$relfile" | grep -qE "$EXCLUDES"; then
            continue
        fi
        echo "$relfile"
    done > "$tmpfile"

    cat $tmpfile

    rsync -avr --files-from="$tmpfile" "$src" "$dst"

    rm -f "$tmpfile"
}

for dir in kubernetes cloud docker; do
    mkdir -p bundle/policies/$dir/policies
    rsync_with_content_filter "checks/$dir/" "bundle/policies/$dir/policies"
done


for dir in kubernetes docker cloud test; do
    mkdir -p bundle/policies/$dir/lib
    rsync -avr --exclude="*_test.rego" --exclude="*.go" lib/$dir/* bundle/policies/$dir/lib
done


for dir in kubernetes; do
    mkdir -p bundle/commands/$dir
    rsync -avr commands/$dir/*  bundle/commands/$dir
done


for dir in config; do
    mkdir -p bundle/commands/$dir
    rsync -avr commands/$dir/* bundle/commands/$dir
done

mkdir -p bundle/specs/compliance
rsync -avr --exclude="*.go" --exclude="*.md" pkg/compliance bundle/specs

cp checks/.manifest bundle/
rm bundle/policies/.manifest
sed -i -e "s/\[GITHUB_SHA\]/${RELEASE_VERSION}/" bundle/.manifest
tar -C bundle -czvf bundle.tar.gz .
rm -rf bundle
