#!/usr/bin/sh

# Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
#
# This software is released to the public domain under 17 U.S.C. § 105.
# The Apache 2.0 license applies to the extent permitted by applicable law,
# and for the benefit of international users.

mkdir -p $1/schema

cd /tmp

rm -rf cti-stix-common-objects
git clone https://github.com/oasis-open/cti-stix-common-objects.git
tar cvfz cti-stix-common-objects.tgz cti-stix-common-objects/extension-definition-specifications
mv cti-stix-common-objects.tgz $1/schema

rm -rf oca-iob
git clone https://github.com/opencybersecurityalliance/oca-iob.git

mkdir -p oca-iob/.links
cd oca-iob/.links
ln -s ../apl_reference_implementation_bundle/revision_3/schemas/sdos/x-oca-behavior.json \
	extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62.json
ln -s ../apl_reference_implementation_bundle/revision_3/schemas/sdos/x-oca-detector.json \
	extension-definition--5cccba5c-0be4-450c-8672-b66e98515754.json
ln -s ../apl_reference_implementation_bundle/revision_3/schemas/sdos/x-oca-detection.json \
	extension-definition--c4690e13-107e-4796-8158-0dcf1ae7bc89.json
ln -s ../apl_reference_implementation_bundle/revision_3/schemas/observables/extended-process.json \
	extension-definition--f9dbe89c-0030-4a9d-8b78-0dcd0a0de874.json
ln -s ../apl_reference_implementation_bundle/revision_3/schemas/observables/extended-network-traffic.json \
	extension-definition--3b7505ce-2a18-496e-aa58-311dac6c1473.json
ln -s ../apl_reference_implementation_bundle/revision_3/schemas/observables/extended-windows-registry-key.json \
	extension-definition--2cf8c8c2-69f5-40f7-aa34-efcef2b912b1.json
ln -s ../apl_reference_implementation_bundle/revision_3/schemas/sdos/x-oca-playbook.json \
	extension-definition--809c4d84-7a6e-4039-97b4-da9fea03fcf9.json
ln -s ../apl_reference_implementation_bundle/revision_3/schemas/sdos/x-oca-coa-playbook-ext.json \
	extension-definition--bbc1d5c8-7ddc-4e89-be9c-f33ad02d71dd.json
cd /tmp

tar cvfz oca-iob.tgz oca-iob/apl_reference_implementation_bundle/revision_3/schemas oca-iob/.links
mv oca-iob.tgz $1/schema
