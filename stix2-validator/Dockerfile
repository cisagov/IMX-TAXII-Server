# Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
#
# This software is released to the public domain under 17 U.S.C. § 105.
# The Apache 2.0 license applies to the extent permitted by applicable law,
# and for the benefit of international users.
ARG REGISTRY=docker.io/library

FROM $REGISTRY/python:alpine3.22

RUN apk update && apk upgrade
RUN apk add git

RUN pip3 install --upgrade pip
RUN pip3 install --force-reinstall -v flask stix2-validator==3.2.0
RUN pip3 install --upgrade setuptools
COPY ./validateEndpoint.py ./entrypoint.sh /

# Remove PIP
# RUN pip uninstall -y setuptools
RUN python3 -m pip uninstall -y pip && \
    rm -f usr/local/lib/python3.12/site-packages/pip-25.0.1.dist-info/METADATA

# Fix for stix validator issue 214
RUN sed -i "s/if instance\[\'type\'\] not in enums.TYPES\:/if instance\[\'type\'\] not in enums.TYPES and instance\[\'type\'\] not in enums.OBSERVABLE_TYPES\:/g" /usr/local/lib/python3.14/site-packages/stix2validator/v21/shoulds.py

# Fix to look for local schemas
RUN sed -i '/def retrieve_from_filesystem/a\    match = re.match(r"(https://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix)(2\\.\\d)", schema_path_uri)\n    if match:\n        schema_path_uri = schema_path_uri.replace(match.group(0), os.path.abspath(os.path.dirname(__file__) + "/schemas-" + match.group(2)))' /usr/local/lib/python3.14/site-packages/stix2validator/validator.py

ENTRYPOINT [ "python3", "validateEndpoint.py" ]
