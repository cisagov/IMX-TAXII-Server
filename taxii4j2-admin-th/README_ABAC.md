<!--
  ~ Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
  ~
  ~ This software is released to the public domain under 17 U.S.C. § 105.
  ~ The Apache 2.0 license applies to the extent permitted by applicable law,
  ~ and for the benefit of international users.
-->

# Marking Based Access Control

The CISA server supports optional access control based on marking definition object ids.
Groups can be set up that have a list of ids of marking-definition objects. Users assigned
to that group can only see objects that have one of the given marking definition object ids
in the object_marking_refs STIX field. Groups are additive; if a user is assigned to more
than one group, they will be able to access objects that have any of the marking ids
contained in any of the assigned groups. Marking based access control does not apply to
objects that do not have an object_marking_refs field; those objects will be visible
to all users based on the existing role based access control.

The group object contains a name that must be unique across all groups in the particular
TAXII server instance, and two lists, one of marking-definition object ids and one of
user names.

```
{
    "name": "test-group",
    "markings": [
        "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb"
    ],
    "users": [
        "user0",
        "user1"
    ]
}
```

The users do not need to be also created in the TAXII server. Users created in an
external OIDC provider can be assigned to groups, but the user names must match
exactly.

## API Endpoints

### `GET /admin/v1.0/groups`

Return a list of all groups configured in the TAXII server.

### `GET /admin/v1.0/group/{group name}`

Return the definition of one group by name.

### `POST /admin/v1.0/group`

Create or update a group. Body of the POST is a group definition object, it
will be created if it does not exist, or will replace the existing group
definition with that name if it does already exist. Both markings and users
are optional.

### `POST /admin/v1.0/group/{group name}/addMarkings`

Add markings to the group named `group name`. Body of the POST is a JSON array
of marking definition IDs that will be added to the group markings list, if
they are not already in the list. Returns the updated group definition.

### `POST /admin/v1.0/group/{group name}/removeMarkings`

Remove markings from the group named `group name`. Body of the POST is a JSON
array of marking definition IDs that will be removed from the group markings
list, if they appear. Returns the updated group definition.

### `POST /admin/v1.0/group/{group name}/addUsers`

Add users to the group named `group name`. Body of the POST is a JSON array
of usernames that will be added to the users list, if they do not exist.
Returns the updated group definition.

### `POST /admin/v1.0/group/{group name}/removeUsers`

Remove users from the group named `group name`. Body of the POST is a JSON
array of usernames that will be removed from the users list, if they exist.
Returns the updated group definition.

### `DELETE /admin/v1.0/group/{group name}`

Deletes the group named `group name`. Access control restrictions based on
the group will immediately be lifted.

## Group assignment via OIDC

Group assignment can be done in the OIDC provider; the groups in
each must be configured with identical group names. The TAXII server is able to
retrieve the list of groups that a user is a member of from the access token.
The OIDC provider may require additional configuration to include this in the token.

### Keycloak configuration

To configure a Keycloak realm to include the group membership in the access token,
navigate to the Client scopes page, and go to the Profile scope. Under the
Mappers tab, click Add mapper > By Configuration. Choose the Group Membership
mapper. Set the Token Claim Name to `groups`. Disable the `Full group path` setting,
and make sure that `Add to access token` is enabled. Click Save.

Creation of groups, and assignment of users to groups, can then be done within
Keycloak. Groups must also be created in the TAXII server with identical names,
but users do not need to be assigned within the TAXII server.
