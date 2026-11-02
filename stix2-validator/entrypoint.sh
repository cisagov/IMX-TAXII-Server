#!/bin/sh

# Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
#
# This software is released to the public domain under 17 U.S.C. § 105.
# The Apache 2.0 license applies to the extent permitted by applicable law,
# and for the benefit of international users.

if [ ! -d /opt/schema ]
then
	mkdir -p /opt/schema
fi

cd /opt/schema

mkdir sparse-checkout
cd sparse-checkout
git init
git branch -m main
git remote add -f origin https://github.com/oasis-open/cti-stix-common-objects
git config core.sparseCheckout true
echo 'extension-definition-specifications/' >> .git/info/sparse-checkout
git pull origin main
rm -rf ../cti-stix-common-objects
cp -a extension-definition-specifications ../cti-stix-common-objects
cd ..
rm -rf sparse-checkout

mkdir sparse-checkout
cd sparse-checkout
git init
git branch -m main
git remote add -f origin https://github.com/opencybersecurityalliance/oca-iob
git config core.sparseCheckout true
echo 'apl_reference_implementation_bundle/revision_3/schemas/' >> .git/info/sparse-checkout
git pull origin main
rm -rf ../oca-iob
cp -a apl_reference_implementation_bundle/revision_3/schemas ../oca-iob
cd ..
rm -rf sparse-checkout

cd /
python3 validateEndpoint.py
