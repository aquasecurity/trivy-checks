#!/bin/bash

rm -rf bundle || true
rm bundle.tar.gz || true

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

tar -C bundle -czvf bundle.tar.gz .
rm -rf bundle
