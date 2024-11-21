#!/bin/bash

rm -rf bundle || true
rm bundle.tar.gz || true
RELEASE_VERSION=${GITHUB_REF/refs\/tags\/v/}
MINOR_VERSION=$(echo ${RELEASE_VERSION} | cut -d. -f1,2)
MAJOR_VERSION=$(echo ${RELEASE_VERSION} | cut -d. -f1)
if [ -n "$GITHUB_ENV" ]; then
  echo "RELEASE_VERSION=$RELEASE_VERSION" >> $GITHUB_ENV
  echo "MINOR_VERSION=$MINOR_VERSION" >> $GITHUB_ENV
  echo "MAJOR_VERSION=$MAJOR_VERSION" >> $GITHUB_ENV
fi

for dir in kubernetes cloud docker; do
    mkdir -p bundle/policies/$dir/policies
    rsync -avr --exclude=README.md --exclude="*_test.rego" --exclude='*.'{go,yml,yaml} --exclude=compliance --exclude=test checks/$dir/  bundle/policies/$dir/policies
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
rsync -avr pkg/specs/compliance bundle/specs

cp checks/.manifest bundle/
rm bundle/policies/.manifest
sed -i -e "s/\[GITHUB_SHA\]/${RELEASE_VERSION}/" bundle/.manifest
tar -C bundle -czvf bundle.tar.gz .
rm -rf bundle
