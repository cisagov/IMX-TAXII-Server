<!--
  ~ Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
  ~
  ~ This software is released to the public domain under 17 U.S.C. § 105.
  ~ The Apache 2.0 license applies to the extent permitted by applicable law,
  ~ and for the benefit of international users.
-->

# TAXII ClientJob API

This API provides the capability to run jobs that access a remote TAXII server to
pull objects from a specific api-root and collection, and push them to another
server. The source server uses only standard TAXII functionality. The destination
server does not need to be a TAXII server, but must implement the `upsert`
and `accept` endpoints defined below. Jobs can be multi threaded, spawning up
to the number of concurrent worker threads specified in the workerCount parameter.

*Currently the remote attribute is required. The job will both read from a remote*
*TAXII server and push to a remote server. Local addresses can be used to access*
*the local server.*

Sample `Configuration` object

```
{
    "remote": {
        "uuid": "8e029e55-16c6-44f4-802c-340e4f1691ab",
        "upsert-info": {
            "url": "https://host.docker.internal:9443/admin/v1.0/clientJob/upsert",
            "username": "imx-admin",
            "password": "$TAXII_PASSWORD"
        },
        "accept-info": {
            "url": "https://host.docker.internal:9443/admin/v1.0/clientJob/accept",
            "username": "imx-admin",
            "password": "$TAXII_PASSWORD"
        }
    },
	"info": {
		"url": "https://taxii-imx.source.domain/taxii/v2.1-os/",
		"username": "imx-admin",
		"password": "$TAXII_PASSWORD"
	},
	"fragment": "test",
	"cId": "cb35fc80-6760-477b-946e-d922b123e0c2",
	"workerCount": 1,
	"workerDuration": "PT24H"
}
```

Once the job is created, a `Snapshot` object specifies the data to be
retrieved and the maximum size of the `Envelope` object. The worker will
populate the nextWorker field as it executes.

Sample `Snapshot` object

```
{
	"uuid": "8e029e55-16c6-44f4-802c-340e4f1691ab",
	"workerParams": [
		{
			"begin": "2025-10-08T18:07:16.532131Z",
			"end": "2025-10-08T19:07:16.532131Z",
			"filters": {
				"added_after": [
					"2025-10-08T18:07:16.532131Z"
				],
				"match[version]": [
					"all"
				],
				"limit": [
					"64"
				]
			}
		}
    ],
    "nextWorker": "2025-10-08T19:07:16.532131Z"
}
```

Both `Configuration` and `Snapshot` need to be extended
with primary key `uuid`.
Additionally, `Configuration` needs to be extended with two `RemoteInfo`
members:
`upsert` which will be `POST`ed with (extended) `Snapshot`
object JSONs by an actively running job for
check pointing and `accept` which will be `POST`ed with TAXII
`Envelope` object JSONs for STIX ingest.
Either / both of these endpoints can (obviously) have any of
the authorization methods that can be expressed in a `RemoteInfo`.
Jobs (re)enter idle state when the api-root / collection
is completely consumed, but persist to be reused
(e.g. to check / retrieve STIX objects newly added).

*Perhaps there needs to be a push endpoint for completion notification...*

## `POST admin/v1.0/clientJob/taxii`

Create a new idle `ClientJob`.
Accepts content type `application/json`:
a `Configuration` object JSON.
Returns status 200 with a `Configuration` object JSON
in which `nextWorker` timestamp is set / updated to first
available object in the api-root / collection pair,
404 if there are no available objects
(e.g. after a supplied `nextWorker` or simply an empty collection),
or 400 if the request can't be processed
(e.g. if the `uuid`, taken from the `POST`ed `Configuration`,
has been used
to successfully create a job earlier).
Note that in the case of a 404 return, the job
is still created, idle and ready for a later start attempt...

*I'm not sure I like the way I'm using 404 here...*

## `POST admin/v1.0/clientJob/snapshot`

Set a known `ClientJob` to a checkpoint;
the job **MUST** be idle.
Accepts content type `application/json`:
a `Snapshot` object JSON.
Returns status 200 with the supplied `Snapshot` object JSON
on success,
404 if the `uuid` is unknown,
or 400 if the request can't be processed
(e.g. the number of worker states is greater than
the originally configured `workerCount`
or job is running).

## `GET admin/v1.0/clientJob/{uuid}/configuration`

Returns status 200 and a `Configuration`
object JSON provided `uuid` is known or
404 otherwise.
This endpoint can be invoked regardless
of job running state.

Provided primarily for completeness since
a job configuration is immutable and
returned at creation...

## `GET admin/v1.0/clientJob/{uuid}/snapshot`

Returns status 200 and a `Snapshot`
object JSON provided `uuid` is known or
404 otherwise.
This endpoint can be invoked regardless
of job running state.

This endpoint is provided primarily for
convenience / completeness since checkpoints are
being actively and continuously pushed into
the `upsert` endpoint...

## `GET admin/v1.0/clientJob/{uuid}/start`

Returns status 200 and `boolean`
`true` if the job was idle
`false` otherwise or 404 if the `uuid`
is unknown.

## `GET admin/v1.0/clientJob/{uuid}/stop`

Returns status 200 and `boolean`
`true` if the job was running
`false` otherwise or 404 if the `uuid`
is unknown.


## `GET admin/v1.0/clientJob/{uuid}/isRunning`

For known `uuid`, returns 200 and `boolean` `true` if
job running `false` otherwise.
Returns 404 on unknown `uuid`.

Note that jobs can and will complete,
returning to idle state, once the
api-root / collection has been completely
collected...

## `DELETE admin/v1.0/clientJob/{uuid}`

Stops and deletes job provided `uuid`
is known returning 200 and a `Snapshot`
object JSON.  Returns 404 otherwise.

## `GET admin/v1.0/clientJob/list`

Returns a list of `Configuration` / `Snapshot`
pairs for all known jobs.

*Perhaps this should just return a list of known job uuids*

## `GET admin/v1.0/clientJob/{uuid}/status`

Returns an `application/json` object containing a list of
the status objects returned by the ingestion of each individual
`Envelope` ingested in the TAXII server for the job identified
by `uuid`. Each status object only
includes totals: the total count in the envelope, the counts
of successful and failed objects, the overall status, the
generated UUID of the bundle ingestion, and the
timestamp that the `Envelope` was ingested.

## `GET admin/v1.0/clientJob/{uuid}/status/{status uuid}`

Returns the detailed status object for the specific ingested
`Envelope`. The `uuid` identifies the client job and the
`status uuid` identifies the specific `Envelope`. This status
object includes the status and messages for each individual
STIX object included in the `Envelope`. This object is retrieved
from the destination TAXII server.

## `POST admin/v1.0/clientJob/accept`

Destination endpoint for a client job to push envelopes
of STIX data. Accepts `application/json` containing a TAXII
`Envelope` and the UUID and destination api-root and
collection of the client job.

## `POST admin/v1.0/clientJob/upsert`

Destination endpoint for a client job worker to push checkpoint
data. Accepts `application/json` of a `Snapshot` object. Each worker
sends snapshot when it completes.
