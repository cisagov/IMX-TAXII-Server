<!--
  ~ Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
  ~
  ~ This software is released to the public domain under 17 U.S.C. § 105.
  ~ The Apache 2.0 license applies to the extent permitted by applicable law,
  ~ and for the benefit of international users.
-->

# Referencing Remote Resources

The CISA server provides access to remote resources
(including TAXII servers).  This document provides the schema
for connection information given the authentication method
of the remote resource.

All schema include a required `url` member that specifies
the remote endpoint and an optional `uuid` member for
uniquely identifying the endpoint (if this member is not
provided at registration time, a unique random value will
be generated and assigned).

The following sections define the members for the
available authentication schemes:

- basic (username / password),
- OIDC (JWT),
- none (no credentials required),
- PKCS10 (certificate signing request), and
- PKCS12 (certificate / encrypted private key pair)

## Basic

Example

```
{
    "url": "https://host/path",
    "uuid": "0bc43c33-4536-47b7-9fa2-d1a99fbdc1c9",
    "username": "luser",
    "password": "dogsname"
}
```

The `username` and `password`, per standard, get base64-encoded
as a colon-separated pair and passed in the `Authorization: basic xxx`
header parameter.

## OIDC

Example

```
{
    "url": "https://host/path",
    "uuid": "0bc43c33-4536-47b7-9fa2-d1a99fbdc1c9",
    "realm": "theRealm",
    "resource": "theResource",
    "username": "luser",
    "password": "dogsname",
    "provider": "https://keycloak/auth/token"
}
```

The OIDC `.well-known` endpoint on the `provider` is used
to identify the token-granting endpoint for the `realm`.
The token endpoint is then issued a password grant for the
`resource` with the `username` / `password` (provider)
credentials.  Provided all goes well, the returned JWT is
attached to remote requests, per standard, in the
`Authorization: bearer xxx` header parameter.  The token
is refreshed as necessary (using the token-refresh endpoint
discovered from `.well-known`).

## None

Example

```
{
    "url": "https://host/path",
    "uuid": "10bc2772-7715-4868-9544-55c974eb271a"
}
```

No header parameters are generated / attached.

## PKCS10

Example

```
{
    "url": "https://host/path",
    "uuid": "341d6144-8508-4ce1-b58a-07206c42e54e",
    "pkcs10": "dGhpcyBpcyB0aGU..."
}
```

the `pkcs10` member is a base64-encoded certificate signing
request (CSR).  It is attached to remote requests as an
`Authorization: xxx` header parameter.  This somewhat odd
authentication method comes from the TAXII standard...

## PKCS12

Example

```
{
    "url": "https://host/path",
    "uuid": "04550c10-67cc-41e9-aacb-d95646a0728e",
    "pkcs12": "dGhpcyBpcyB0aGU...",
    "password": "dogsname"
}
```

The `pkcs12` member is a base64-encoded PEM with password `password`.
It is loaded into the application keystore and provided in response
to TLS client challenges establishing mTLS (two-way SSL).  The remote
resource may further use the credentials for identity, but that is at
the discretion of that server...
