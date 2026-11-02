<!--
  ~ Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
  ~
  ~ This software is released to the public domain under 17 U.S.C. § 105.
  ~ The Apache 2.0 license applies to the extent permitted by applicable law,
  ~ and for the benefit of international users.
-->

# Snapshot Management

The CISA server, when using Elasticsearch as its backing store,
provides capabilities for creating, restoring, listing, and deleting
named *snapshots*. These contain all the necessary data to restore
the server to a point in time (the impetus perhaps being safety
backups, errant data, hardware failure, etc).  Name management,
policy, schedule and other related issues are left up to the
server system administrator. The endpoints described below provide
the minimal spanning set to cover snapshot managment.

## Configuration

Currently, the server is hardwired to read / write snapshots to
a filesystem directory named `/opt/snapshots`. Since the server
typically runs in a Docker container, the physical location
of this directory is under the control of the Run command
or Compose script that binds a host directory to this fixed
container directory.  Keep in mind that the bound host
volume could easily be a NFS volume or other form of shared
storage.

The Elasticsearch snapshot capabilities provide for other
backup media, e.g. AWS S3, Azure Blob, ...
The server could be reworked to have a more sophisticated
snapshot repository scheme, based on configuration data...

## Endpoints

### `GET admin/v1.0/snapshots`
List the previously captured
snapshots. The results include data related to snapshot name,
success / failure, items persisted, etc.

### `PUT admin/v1.0/snapshot/{name}`
Create a snapshot.
The endpoint returns immediately with acknowledgement
(positive if the data collection could be initiated) but
the snapshot building then continues asynchronously.
Progress / success can (should) be determined from the
`GET admin/v1.0/snapshot/{name}` endpoint...

### `GET admin/v1.0/snapshot/{name}`
Get snapshot status.

### `DELETE admin/v1.0/snapshot/{name}`
Remove a
snapshot and all its data from the repository.

### `PUT admin/v1.0/snapshot/{name}/restore`
Restore a
snapshot.  This synchronous endpoint, which may take a
non trivial amount of time to run, deletes all active
server indices (to include user, api root, collection configuration
data as well as all previously persisted objects), and
restores those data to the state at the moment of the
snapshot creation.
