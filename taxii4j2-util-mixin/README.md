<!--
  ~ Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
  ~
  ~ This software is released to the public domain under 17 U.S.C. § 105.
  ~ The Apache 2.0 license applies to the extent permitted by applicable law,
  ~ and for the benefit of international users.
-->

# taxii4j2-util-mixin

This module provides several administrative tools,
intended for use from the CLI,
that include

- `BulkLoader` for posting large payloads to an `objects` endpoint
- `ConfExport` for exporting api-root and collection configurations
via standard TAXII endpoints (works for all standards-compliant servers)
- `Exporter` for archiving all versions of all objects from an
api-root / collection pair (using standard TAXII endpoints)
- `Importer` for restoring all versions of all objects from an
api-root / collection pair as archived by `Exporter`
- `PConfExport` for exporting api-root, collection, and RBAC
configurations from a CISA TAXII server

## General

There are (at least) three different ways of running the utilities:

- for those with access to the source code, directly from a built jar / library directory on the host shell CLI
- for those with access (only?) to the Docker host, from the jar inside the TAXII server container
- for those running a CISA TAXII server, endpoints

In the first case, files can be on any host absolute path.
In the second, the TAXII container has a mounted volume with external path
specified by `${TAXII_IO}` in `.env` mappped to internal path `/opt/io`;
the *remote* TAXII server is at `https://localhost/taxii/v2.1-os/`,
input files should be copied to `${TAXII_IO}`, CLI paths most likely begin
with `/opt/io`, and output files will be available at `${TAXII_IO}`
on completion.

For example, with `${TAXII_IO}` containing `localTAXII443.json` and `169.json`,
`BulkLoader` (see below) is invoked

```
docker exec -it taxii4j2-th-es-taxii4j2-1 java -cp /opt/taxii4j2/taxii4j2-main-th-0.1-SNAPSHOT.jar \
	com.cisa.taxii4j2.util.BulkLoader /opt/io/localTAXII443.json Send2A1 raw /opt/io/err.txt \
	/opt/io/169.json
```

on a standard deployment (it providing the context for the jar file, api-root, and collection alias).
Any errors will appear in `${TAXII_IO}/err.txt` for the example.
All utilities are part of the `com.cisa.taxii4j2.util` package.

CISA server endpoints are documented in the following sections when available.

## `BulkLoader`

TAXII api-roots specify `max_content_length` which limits the payload size
of envelopes submitted to the `objects` endpoint.  However, envelope files from
external sources, e.g. [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data/tree/master)
with files of 40M+, can exceed the payload limit.  This utility breaks down
these large envelopes into chunks compatible with a target TAXII server's api-root,
submits the chunks, waits patiently for the `POST`s to complete, and reports
any errors resulting from any of the submissions. Arguments are

- path to the file containing the target TAXII server resource information
(see [README_REMOTE.md](../cti4j2-th/README_REMOTE.md)) *(input)*
- the target api-root (name only)
- the collection UUID (or alias if a CISA server)
- path to file for logging errors *(output)*
- path to envelope file *(input)*

On a CISA server
`POST ext/v1.0/util/<api-root>/collections/<collection-alias-or-id>/load`
takes multipart form data with `info` a string per
[README_REMOTE.md](../cti4j2-th/README_REMOTE.md)
and an `application/octet-stream` as `file`.
A curl building the form data might look like

```
curl -k --user 'imx-admin:$TAXII_PASSWORD' \
	https://localhost:9443/ext/v1.0/util/Send2A1/collections/vetted/load/ \
	-F info=@localTAXII9443.json -F file=@enterprise-attack.json
```

## `ConfExport`

This utility documents the api-roots and collections available to the authenticated user.
There **may** be other api-roots and/or collections for which the user is not
authorized; these will simply and silently not appear in the description.
Arguments are

- path to the file containing the target TAXII server resource information
(see [README_REMOTE.md](../cti4j2-th/README_REMOTE.md)) *(input)*
- path to configuration description *(output)*

On a CISA server
`POST ext/v1.0/util/conf`
with a payload per
[README_REMOTE.md](../cti4j2-th/README_REMOTE.md)
will reply a JSON configuration object suitable for submission to
`POST admin/v1.0/configure`

## `Exporter`

This utility, provided the user is authorized, will use standard TAXII
endpoints to extract all versions of all objects into a zip file having
an opaque directory structure (there is no intent for the administrator
to use the file in any other context than input to the `Importer` utility).
The completeness of this file is entirely dependent on the behavior
of the remote TAXII server with respect to iterating over a collection
while objects are or might be in the process of being added.
In other words, it works most reliably when there is no `POST` objects
activity...

Arguments are

- path to the file containing the target TAXII server resource information
(see [README_REMOTE.md](../cti4j2-th/README_REMOTE.md)) *(input)*
- the target api-root (name only)
- the collection UUID (or alias if a CISA server)
- path to file for logging errors *(output)*
- path to zip file *(output)*

On a CISA server
`POST ext/v1.0/util/<api-root>/collections/<collection-alias-or-id>/export`
with a payload per
[README_REMOTE.md](../cti4j2-th/README_REMOTE.md)
will reply a zip file suitable for submission to
`POST ext/v1.0/util/<api-root>/collections/<collection-alias-or-id>/import`
or one of the other explicit import methods.

## `Importer`

This utility `POST`s output from `Exporter` to an api-root /
collection pair on a remote host using standard TAXII endpoints.
Arguments are


- path to the file containing the target TAXII server resource information
(see [README_REMOTE.md](../cti4j2-th/README_REMOTE.md)) *(input)*
- the target api-root (name only)
- the collection UUID (or alias if a CISA server)
- path to file for logging errors *(output)*
- path to zip file from `Exporter` *(input)*

On a CISA server
`POST ext/v1.0/util/<api-root>/collections/<collection-alias-or-id>/import`
takes multipart form data with `info` a string per
[README_REMOTE.md](../cti4j2-th/README_REMOTE.md)
and an `application/octet-stream` as `file`.
A curl building the form data might look like

```
curl -k --user 'imx-admin:$TAXII_PASSWORD' \
	https://localhost:9443/ext/v1.0/util/Send2A1/collections/vetted/import/ \
	-F info=@localTAXII9443.json -F file=@tmp.zip
```

## `PConfExport`

This utility uses CISA-specific administrative endpoints to fully
extract api-root, collection, and RBAC configuration; it works only
for the `imx-admin` user name / role.  The output can be `POST`ed
to the CISA-specific `admin/v1.0/configure` administrative
endpoint to exactly replicate the original server configuration.
Arguments are

- path to the file containing the target TAXII server resource information
(see [README_REMOTE.md](../cti4j2-th/README_REMOTE.md)) *(input)*
- path to configuration description *(output)*

On a CISA server
`POST ext/v1.0/util/pconf`
with a payload per
[README_REMOTE.md](../cti4j2-th/README_REMOTE.md)
will reply a JSON configuration object suitable for submission to
`POST admin/v1.0/configure`.
In contrast to `util/conf`, this endpoint will include all RBAC
and user info (data unique to the CISA server which is defaulted
in the generic `util/conf`).
