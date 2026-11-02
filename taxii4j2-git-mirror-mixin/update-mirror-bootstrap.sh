#!/usr/bin/sh

# Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
#
# This software is released to the public domain under 17 U.S.C. § 105.
# The Apache 2.0 license applies to the extent permitted by applicable law,
# and for the benefit of international users.

mkdir -p $1/mirror

cd /tmp

rm -rf cti-stix-common-objects
git clone https://github.com/oasis-open/cti-stix-common-objects.git
cd cti-stix-common-objects

tar cvfz extension-definition.tgz objects/extension-definition
mv extension-definition.tgz $1/mirror/1a1e76b0-c328-4622-ba38-d43b71e037e3.tgz

tar cvfz identity.tgz objects/identity
mv identity.tgz $1/mirror/b9985efb-7d4c-40ff-8dcd-3dd27cc4e04f.tgz

tar cvfz location.tgz objects/location
mv location.tgz $1/mirror/af062974-7640-4676-bcf1-d3de14edf5f7.tgz

tar cvfz marking-definition.tgz objects/marking-definition
mv marking-definition.tgz $1/mirror/dafa04d6-3c5b-43f9-91e6-298ec92816af.tgz
