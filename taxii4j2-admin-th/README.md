<!--
  ~ Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
  ~
  ~ This software is released to the public domain under 17 U.S.C. § 105.
  ~ The Apache 2.0 license applies to the extent permitted by applicable law,
  ~ and for the benefit of international users.
-->

# taxii4j2-admin-th

This module provides
programmatic- and web-facing capabilities
for TAXII server configuration management.

## Links To Detailed README files

- [Authentication via OIDC provider](README_OIDC.md)
- [Authentication by Mutual TLS](README_PKCS12.md)
- [Attribute Based Access Control](README_ABAC.md)
- [Management of OpenSearch snapshots](README_SNAPSHOT.md)

## Miscellaneous

### `GET admin/v1.0/permissions`

Returns the list of permissions the current user has.
The response is a JSON list of api-roots, and the collections in
that api-root that the user has read and/or write permission. If the
user has no access to the collection, it will not be included.

Response will be a list of `RootPermissions` objects as shown.

```
[
    {
        "api-root": "test",
        "collections": [
            {
                "id": "be16b481-399d-4abb-a217-5187265dc780",
                "title": "test",
                "can_read": true,
                "can_write": true
            }
        ]
    }
]
```

## Sandbox

The server maintains a set of api-root / collection pairs for which
RBAC is bypassed. That is, any authenticated user is authorized to
both read and write the pair. The intent is to provide a low
maintenance area for new user experimentation.
Sandbox members are persisted between server reboots.

All endpoints entail the `RootCollection` object

```
{
	"api-root": "sandbox",
	"collection": "8dc9c742-428d-440f-8583-6876fda0ba3f"
}
```

Both members are required.

### `POST admin/v1.0/sandbox`

Add a `RootCollection` to the sandbox.

### `DELETE admin/v1.0/sandbox`

Delete a `RootCollection` from the sandbox.

### `GET admin/v1.0/sandbox`

List the sandbox `RootCollection`s.

## Bulk Changes

`POST admin/v1.0/configure` accepts a payload of the shape

```
{
	"collections": [
		{
			"id": "7d476dc7-5c2a-418b-b150-8b07cad20b43",
			"title": "raw",
			"can_read": true,
			"can_write": true,
			"description": "new cyber threat intelligence awaiting review",
			"alias": "raw"
		},
		...
	],
	"fragments": [
		{
			"fragment": "Send2A1",
			"apiRoot": {
				"title": "Send2A1",
				"versions": [
					"application/taxii+json;version=2.0",
					"application/taxii+json;version=2.1"
				],
				"max_content_length": 524288,
				"description": "cyber threat intelligence workflow collections for Analyst1"
			},
			"rws": [
				{
					"cId": "f2107501-b441-4add-8935-dff122a73acb",
					"lenients": [
						"DONT_CHECK_CUSTOM_OBJECTS",
						"DONT_CHECK_CUSTOM_PROPERTIES"
					],
					"readers": [
						"imx-user"
					],
					"writers": [
						"imx-admin"
					]
				},
				...
			]
		}
	],
	"users": [
		{
			"user": "user0",
			"password": "user0pwd",
			"roles": [
				"imx-user",
				"imx-admin"
			]
		},
		...
	]
}
```

Refer to the TAXII specification for entries in the `collections` member.

`fragments` specifies api-roots, their connections to collections, and
the required roles for reading and writing them.
Each api-root specifies a partial path on which it is to appear on
the server, the api-root data defined by the TAXII specification, and
a set of collection associations.
Each association includes a collection UUID, an optional set of
validation leniencies, and arrays of read and write roles.

Finally, `users` is an array of basic authentication user, password,
role triplets.  The `password`, while in plain text here, is one-way hashed
in the server (it is unrecoverable through the user endpoints).

Refer to either `taxii4j2-ce-sqlite` or `taxii4j2-th-es`
to create and deploy a TAXII server.
