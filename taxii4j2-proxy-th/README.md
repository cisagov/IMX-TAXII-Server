<!--
  ~ Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
  ~
  ~ This software is released to the public domain under 17 U.S.C. § 105.
  ~ The Apache 2.0 license applies to the extent permitted by applicable law,
  ~ and for the benefit of international users.
-->

# taxii4j2-proxy-th

This module provides a thin(ner) deployment of the CISA
TAXII server that proxies all standard TAXII endpoints to
a remote (TAXII server) resource.
Out of the box, it is configured to use a `SQLite` backing
store based on the assumption that its only lightweight
job is to maintain user credentials (for its own
administration and authentication to the remote resource).
It is configured entirely through environment variables;
in a Docker-based deployment these are provided via
the `.env` file to the compose file.

## Local Configuration

These environment variables define the local host
(proxy) configuration.

### `SQLITE_URL`

Defines the `JDBC` URL for `SQLite`, that is, the location
of the database file.  In a Docker-based deployment, the
path prefix must be a mounted host volume if persistence is
desired (the provided compose file provides a mounted volume).
The URL has the form e.g. `jdbc:sqlite:/opt/taxii4j2/data/taxii4j2.db`
where the prefix `jdbc:sqlite:` is required and is followed
by the absolute path to the persistence file.

### `TAXII_PASSWORD`

Defines bootstrap password for user name `imx-admin`.

### `TAXII_URL`

Used primarily to define protocol (`http` v. `https`),
and optional port, e.g. `https://<host>:<port>/`
of the local proxy host.
The host name and any given path are effectively ignored.
Out of the box, the CISA distribution relays endpoints
`https://<host>:<port>/taxii/v2.1-os/*` to the
remote host `CLIENT_URL/*` (see below)

### `TAXII_XUUID`

A UUID v4 used to uniquely distinguish the local server, e.g.
`49623f47-60a9-4068-b43d-7e177d46a969`

## Remote Resource Configuration

These environment variables define the path to and
authentication credentials for the remote TAXII server.
They are direct analogs to the members of the `RemoteInfo`
struct described in [README_REMOTE.md](../cti4j2-th/README_REMOTE.md).
Please refer to that document for recipes on concocting
viable remote resource location / authentication configurations
(not all variables are needed for any given authentication method).
Brief descriptions are provided below for familiar users.

### `CLIENT_URL`

**REQUIRED** URL of remote TAXII server; all endpoints will be referenced
relative to this.

### `CLIENT_USERNAME`

Multipurposed as direct basic authentication user name
and indirect OIDC user name.

### `CLIENT_PKCS10`

base64 encoding of a CSR

### `CLIENT_PKCS12`

base64 encoding of a PEM

### `CLIENT_PASSWORD`

Multipurposed as direct basic authentication password,
indirect OIDC user password, and PKCS12 PEM encryption password.

### `CLIENT_PROVIDER`

URL of OIDC token provider (e.g. a Keycloak instance).
