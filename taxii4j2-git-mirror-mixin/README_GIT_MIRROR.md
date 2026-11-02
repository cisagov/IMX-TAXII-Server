<!--
  ~ Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
  ~
  ~ This software is released to the public domain under 17 U.S.C. § 105.
  ~ The Apache 2.0 license applies to the extent permitted by applicable law,
  ~ and for the benefit of international users.
-->

# Git Repository Object Mirroring

The CISA server provides mechanisms for mirroring (copying) STIX objects from
Git repositories and, optionally, keeping them up to date with periodic refresh.
The high level process consists of registering a connection to a repository and
then associating one or more mappings of repository contents to one or more
collections.  As the objects / schema potentially change, those changes are
(eventually, based on the refresh rate) reflected in the server objects / schema.
This reflection is one way, that is, the use case is that a third party
(most likely the repository owner) is making changes and the desire is to
detect and act on those changes to keep the server objects in sync with
those in the repository.

It should be noted that the repository objects are persisted in the collection(s)
without respect to their api-root association nor their STIX compliance.
Therefore, conceivably, collections containing mirrored objects could contain
*broken* objects...

There are two modes for connection registration:

- associating a locally cloned repository, and
- creating a Git API-based connection to a repository

The first is somewhat more complex to initiate but works for all repositories.
It is faster, but has a larger storage footprint since the schema / objects exist in
both the clone and the server database.
The local (mirrored) copy will be automagically updated by the refreshes.
Changing the local clone **WILL** break things.

The second is easier, more network intensive, has a smaller storage footprint,
but will fail on repositories
having large directories (e.g. `cti-stix-common-objects` vulnerability
directory).

All Git management endpoints require `imx-admin` role of the authenticated user.
All registered repositories must be publicly accessible (in the current implementation).
Mirrors are persisted across server restarts.
A list of current mirrors, their mappings, and their status is available at
`GET admin/v1.0/mirrors`.

## Responses

Most of the endpoints respond with one or more `MirrorState` objects

```
{
	"filter": *registration info plus mappings (see below)*,
	"running": [ *zero or more mapping UUIDs* ]
}
```

The `running` member indicates which (if any) of the mappings are
currently executing an update. The `GET admin/v1.0/mirror/{UUID}/update`
endpoint will throw an exception if all mappings are not idle.

Endpoints return immediately with current state data, that is,
any implied / required mapping updates happen as
parallel asynchronous background tasks. Progress / status can
be obtained at `GET admin/v1.0/mirror/{UUID}`

## Git Repository Registration

Both forms of registration utilize the `POST admin/v1.0/mirror` endpoint.
The access method is determined
from payload details.  Both forms share the following payload members

```
{
	"master": "origin/main",
	"update_rate": "5 MINUTES"
}
```

with `master` (required) specifying the Git repository branch to be mirrored and
`update_rate` (optional) specifying the period between update checks.
Omitting `update_rate` requires the user / administrator to invoke
`GET admin/v1.0/mirror/{UUID}/update` manually to bring mirrored
objects up to date.  The update rate value must be an integer, white space,
and one of `DAYS`, `HOURS`, `MINUTES`.

Registering a repository replies a `MirrorState`
containing a UUID with which to reference the
registration in subsequent calls.  A list of the current registrations can
be obtained via `GET admin/v1.0/mirrors`.

### Locally Cloned Repository Registrations

This form of registration is created with a payload of the form (e.g.)


```
{
	"path": "/opt/repos/cti-stix-common-objects",
	"master": "origin/main",
	"update_rate": "1 DAYS"
}

```

with the emphases on the `path` member which points to a (manually created)
clone of the repository of interest.
Generally, the clone will reside in `${GIT_REPOS}` which,
in a standard deployment, gets mounted on `/opt/repos`.
The clone must use the `HTTPS` protocol.
Note that this path (and the associated data)
must be in the container's file system if running the server in Docker.
It is critical that no local changes are manually made on the clone's contents.

### API-based Registrations

This form of registration is created with a payload of the form (e.g.)

```
{
	"url": "https://api.github.com/repos/oasis-open/cti-stix-common-objects/",
	"token": "GITHUB API TOKEN HERE",
	"master": "origin/main",
	"update_rate": "5 MINUTES"
}
```

with the emphasis on the `url` member which ends with the repository owner. The `token` member is optional, but should generally be included
as a registered private authorization token for using the Git API to
mitigate potential access rate limits - see [Managing your personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)

## Repository Content Mappings

Content to be mirrored and the server destinations thereof are controlled
via the `POST admin/v1.0/mirror/{UUID}` endpoint.
(Mappings can also be included as part of the registration).
Registrations can have zero or more mappings, but they must be mutually
exclusive with respect to the schema / object paths (don't worry, the
server will flag and reject intersecting mappings).  Objects
and custom extension schema must be treated differently (more info coming)
hence the `type` member. The payload takes the following form e.g.


```
{
	"type": "SCHEMA",
	"includes": [
		"extension-definition-specifications"
	],
	"excludes": [
		"extension-definition-specifications/stix-1x"
	]
	"relocate": {
		"from": "https://raw.githubusercontent.com/oasis-open/cti-stix-common-objects/main/extension-definition-specifications/malware-behavior/",
		"to": "https://raw.githubusercontent.com/oasis-open/cti-stix-common-objects/main/extension-definition-specifications/malware-behavior-8e9/"
	}
}
```

`type` (mentioned above) has the value `SCHEMA` to treat the filtered
material as JSON Schema for validation or `OBJECT` to treat the filtered
material as STIX objects for injection into one or more repositories.
An example of object mapping e.g.

```
{
	"type": "OBJECT",
	"includes": [
		"objects/location"
	],
	"cIds": [
		"7d476dc7-5c2a-418b-b150-8b07cad20b43"
	]
}
```

In both forms, `includes` is required, must include at least one string,
and declares the directory root tree(s) of interest.  `excludes` is optional
and is used to trim branches off any / all `includes` trees.  In the first
example above, JSON Schema will be imported from the `extension-definition-specifications`
directory at the repository root, but schema in
the `extension-definition-specifications/stix-1x` directory and below
will be ignored.

Schema mirrors can contain an optional `relocate` member which rewrites the
incoming `$id` fields matching `from` to `to`. Recall that the `$id` field
of a JSON Schema defines the context for relative paths in `$ref` fields.
Changing the location of a schema on a server or in a file system can break
multipart schema; this feature provides a way to remediate those situations.

In the case of object mirrors, `cIds` (optional but neuters the mapping if omitted)
defines the destination collection(s).  Recall that objects are imported without
any validation whatsoever (minimum requirements are *id*/*version* of course).

All mappings are updated at the common period defined by the optional `update_rate`
parameter of the registration.  Mappings can be deleted with
`DELETE admin/v1.0/mirror/{UUID}/{mapping-UUID}`
and entire registrations with `DELETE admin/v1.0/mirror/{UUID}` with both
UUIDs available from the list endpoint.

Registrations and mappings persist across server restarts.
