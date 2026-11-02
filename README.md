<!--
  ~ Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
  ~
  ~ This software is released to the public domain under 17 U.S.C. § 105.
  ~ The Apache 2.0 license applies to the extent permitted by applicable law,
  ~ and for the benefit of international users.
-->

# TAXII server

This module binds together all submodules developed for CISA
and provides an *easy button* for deploying a TAXII server.
Clone this repository and run the following:

```
docker rmi taxii4j2/th-es:0.1-SNAPSHOT
docker build -t taxii4j2/th-es:0.1-SNAPSHOT .
```

All relevant source code will be downloaded and the Docker image will
be built.

For modules configured for Maven publication, set `MAVEN_REPOSITORY_URL` to
the destination repository URL before running `mvn deploy` in that module.
Configure credentials under the `ties-gitlab` server ID in your Maven settings.

If there is a legacy server running, one should consider backing up
the objects in each collection prior to redeploying.
See [`Exporter'](taxii4j2-util-mixin/README.md) for instructions.
This allows one to destroy Docker volumes associated with object
storage ensuring that the database schema is *also* brought up to date.
See [`Importer'](taxii4j2-util-mixin/README.md) for instructions
post deployment to restore objects.

As delivered, the server assumes internet access,
using public Git repositories to create common objects and schema.
In the case that the deployment *does not* have internet access,
bootstrap files can be used to provide these objects and schema.
On a platform *with* internet access and the assumption that
`.env` has `TAXII_BOOTSTRAP=/opt/taxii4j2/data/bootstrap`,
in some convenient directory run

```
mkdir boostrap
sh taxii4j2-th-es/taxii-git-mirror-mixin/update-mirror-bootstrap.sh bootstrap
sh taxii4j2-th-es/taxii-validate-mixin/update-schema-bootstrap.sh bootstrap
```

These commands reach out to public GitHub and create local directories / files
consumable by the server during initialization.  Considering the `TAXII_BOOTSTRAP`
value above, copy this new `bootstrap` directory to `/opt/taxii4j2/data` on
the deployment host (sneaker net, S3, whatever method one is able to access it).
The common objects and schema will be loaded from the bootstrap files but,
of course, will never be updated (by detected new commits in GitHub) and are
frozen in time per when they were cloned by the scripts.

The server will not crash if neither internet access nor bootstrap files
are availble; simply the common object collections will be empty and edge
object validation will be unable to verify custom extension content.

It's worth mentioning that if the deployment host does not have internet access,
the image produced in the first code block above will need to be also moved to the deployment host
via `docker save | gzip -c > server.tgz` on the build host and
`zcat server.tgz | docker load` on the deployment host (with whatever
transfer gymnastics in between to move `server.tgz`). Similar maneuvers are
required to build, download, and transfer the validator and Elasticsearch
images

```
cd stix2-validator
docker build -t taxii4j2/stix2-validator:0.1-SNAPSHOT .
docker pull elasticsearch:8.15.2
```

Lather, rinse, repeat with those two images parallel to above.

Stop all legacy taxii4j2 containers (some Docker knowledge is assumed
in these instructions), and

```
docker volume rm $(docker volume ls -q)
docker compose up -d
```

to destroy object store volume(s) (any volumes in use by other containers
will not be affected - Docker will indicate that they are still in use)
and deploy the newly built version.
A suite of containers will be deployed for a
TAXII server on the port specified in the `.env` file.
It will be bootstrapped with an administrative user
`imx-admin` with the password found in the `.env` file
(see next section for changing this and other aspects).

Create api roots, associated collections,
and additional users / roles;
see [`GET admin/v1.0/configure`](taxii4j2-admin-th/README.md) for
instructions.
Import any saved objects (see above) and subscribe to any desired
Git object repositories;
see [`POST admin/v1.0/mirror`](taxii-git-mirror-mixin/README.md)
for instructions.

## Customization

The following configuration elements in `.env` can (sometimes should)
be customized.  The container suite will need to be taken down
(`docker-compose down`) and restarted (`docker-compose up -d`)
in order for changes to take effect.

### `TAXII_EXPOSED_PORT`

This is the integer-valued port at which the Dockerized TAXII server
endpoints are exposed.  It has an initial value of 8080 so as
(generally) not to
conflict with other applications running on the host.  Change to
443 for an `HTTPS` service or 80 for an `HTTP` service (see
upcoming comments on `TAXII_URL`) to eliminate the need for
explicitly including a port number on the endpoints.

### `TAXII_URL`

The code is shipped with the intent of creating `HTTP` TAXII
endpoints.  Changing the protocol to `HTTPS` (with an optional
change of `TAXII_EXPOSED_PORT`) will present secured TAXII
endpoints via `HTTPS`.  Also see the below section regarding
configuration for HTTPS certificates.

### `TAXII_PASSWORD`

On startup, an `imx-admin` user is created / updated with the
password found in this configuration item.  It is set to a
weak sample password, it must be updated to a strong value.

### `TAXII_XUUID`

It is possible, when using multiple servers, to have those
servers share a single Elasticsearch instance, for instance
by adding additional services based on the TAXII Docker
image into `docker-compose.yml`.  However, these TAXII
services should each override the `TAXII_XUUID` value
instance providing a unique UUID.  For
inquiring minds, this configuration item is used as a
prefix for indices within the referenced Elasticsearch
(as well as for localizing other items for each unique
server).  If this configuration item is **not** overridden, then there will
be dire conflicts on the Elasticsearch...like I said,
this is an expert-only venture that can reduce resource
footprint, but is not for the faint of heart...

### `GITHUB_TOKEN`

GitHub rate-limits API calls.  Without an authentication token, the
limit is low enough that the server schema / object mirroring
may not work.  Authenticated API calls have a large adequate
rate limit.
Create a private token for GitHub and set it here...

### `Analyst1`

`A1_HOST`, `A1_USER`, and `A1_PASS` define the API endpoint
and credentials for your Analyst1 install.  They are optional
and often set for you by scripts that wrap the server install...

## HTTPS certificates

To deploy using a custom certificate, the certificate
and private key should be in a PKCS12 keystore. Place the keystore
in the `keystore` directory. In the standard `docker-compose.yml`, this
directory is mounted into the container as /opt/keystore. In the `.env`
file, update the following environment variables as appropriate.

### `TAXII_KEYSTORE`

The full path in the container of the keystore.

### `TAXII_KEYSTORE_PASSWORD`

The password for opening the keystore.

### `TAXII_KEYSTORE_ALIAS`

If there is more than one certificate in the keystore, this should
contain the alias of the certificate for the server to use to identify
itself. If there is only one certificate in the keystore, this can be
left unset.

### `TAXII_TRUSTSTORE`

Optional parameter. If there are CA certificates that should be trusted
that are not part of the standard Java distribution, the full path of the
keystore containing trusted CA certificates can be put here.

### `TAXII_TRUSTSTORE_PASSWORD`

Optional parameter, only needed if `TAXII_TRUSTSTORE` is set. Password for
opening the truststore.

## Other Configurations

The following configurations in the `.env` file should not need to be change
in the majority of cases. They are documented here for completeness.

### `OPENSEARCH_URL`

The REST API endpoint of the OpenSearch cluster. If deployed via the
supplied `docker-compose.yml` file, this should not need to be changed. If
the TAXII server should use an externally deployed OpenSearch cluster,
this configuration should point to the external cluster.

### `OPENSEARCH_PASSWORD`

The password for the user `admin` in the OpenSearch cluster. If deployed
via the supplied `docker-compose.yml` file, this password will be set when the
OpenSearch cluster is deployed.

### `OPENSEARCH_SNAPSHOTS`

Local directory mounted to the OpenSearch container for saving snapshots.
This allows snapshots to be captured and easily extracted, to duplicate
or move the TAXII server.

### `VALIDATOR_URL`

The endpoint for calling the stix2-validator container. This will likely be
deployed along with the TAXII server container, and should not be changed.

### `SCHEMA_DIR`

Where the volume containing STIX schemas is mounted to the TAXII and
stix2-validator containers. The TAXII server will download the schemas
published in `https://github.com/oasis-open/cti-stix2-json-schemas`, and the
stix2-validator container uses the schemas to validate imported STIX
objects.

## Command line options

A default set of collections, api-roots and users can be set up via the
command line using the `-root` option. There are a number of root configuration
files built into the server, but additional files can be mounted to the
container and loaded via the command line in the container. The file is
a JSON file containing three possible elements, all of which are optional.

### `collections`

The `collections` element is an array of collection objects that could
be sent to the `POST /admin/v1.0/collection` endpoint.

```
{
	"id": "ca3d2657-13ab-4c2f-8fda-957531fb056c",
	"title": "dev-tlp2",
	"can_read": true,
	"can_write": true,
	"description": "Development/test objects with TLP 2 markings",
	"alias": "dev-tlp2",
	"media_types": [
		"application/stix+json"
	]
}
```

### `fragments`

The `fragments` element is an array of fragment objects that define
api-roots. The objects could individually be sent to the
`POST /admin/v1.0/fragment` endpoint.

```
{
	"fragment": "Send2A1",
	"apiRoot": {
		"title": "Send2A1",
		"versions": [
			"application/taxii+json;version=2.0",
			"application/taxii+json;version=2.1"
		],
		"max_content_length": 4194304,
		"description": "cyber threat intelligence workflow collections for Analyst1"
	},
	"rws": [
		{
			"cId": "ca3d2657-13ab-4c2f-8fda-957531fb056c",
			"readers": [
				"imx-admin",
				"imx-user"
			],
			"writers": [
				"imx-admin",
				"imx-user"
			]
		}
	]
}
```

### `users`

The `users` element is an array of user objects. The objects could
individaully be sent to the `POST /admin/v1.0/user` endpoint.

```
{
	"user": "user0",
	"password": "user0pwd",
	"roles": [
		"imx-user",
		"imx-admin"
	]
}
```
