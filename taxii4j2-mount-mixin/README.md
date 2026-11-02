<!--
  ~ Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
  ~
  ~ This software is released to the public domain under 17 U.S.C. § 105.
  ~ The Apache 2.0 license applies to the extent permitted by applicable law,
  ~ and for the benefit of international users.
-->

# taxii4j2-mount-mixin

This module provides a capability for virtually mounting a remote
TAXII server and binding it to a (local) path prefix; the api roots of the
remote server are then resolved / relativized against this local path
for endpoint access.  Mounts are persisted across server restarts.

 Mounts are controlled with three simple (local) endpoints.

## `POST taxii/mount`

 Initiate a connection to a remote TAXII server based on the payload (e.g.)

 ```
{
	"mp": "localhost9443",
	"info": {
		"username": "imx-admin",
		"password": "$TAXII_PASSWORD",
		"url": "https://localhost:9443/taxii/v2.1-os/"
	}
}
 ```

`mp` specifies the local path under which the remote endpoints will appear.
`info` is an instance of any [remote resource reference](../cti4j2-th/README_REMOTE.md).
After successfully invoking this endpoint,
the discovery (`taxii2`) endpoint on the local server will
(in addition to the local api roots) include the
api roots of the remote resource prefixed by `mp`.  These virtual api roots
behave exactly like local ones (i.e. can be suffixed by `/collections/` to
list the collections on the api root of the remote server).
The mount record is persisted and the connection will be reinstated across
server restarts (until `DELETE taxii/mount/{mount-point}` is invoked).

## `GET taxii/mounts`

 List the active mounts.

## `DELETE taxii/mount/{mount-point}`

 The connection to the remote server mounted at the path parameter
 `mount-point` is terminated, resources are released, records
 of the mount are deleted, the associated api roots will disappear,
 and the mount will **NOT** be activated on server restart.
