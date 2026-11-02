<!--
  ~ Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
  ~
  ~ This software is released to the public domain under 17 U.S.C. § 105.
  ~ The Apache 2.0 license applies to the extent permitted by applicable law,
  ~ and for the benefit of international users.
-->

# Authentication By OIDC Provider

The server can perform authentication using an OIDC token from a trusted
OIDC provider. The token must be passed to the API call as a Bearer token
in the `Authentication` header.

If the token is valid, the user will be given access to any TAXII roles
that are in the `realm_access` list or the `resource_access` list. The role
must be predefined in the TAXII server, and must have the same name as
the role defined in the OIDC provider. Any additional roles defined in
the OIDC provider that the user may be given will have no impact on the
TAXII server access.

The user will also be included in any
[Marking Based Access Control](README_ABAC.md) groups that the user is
a member of in the OIDC provider. Again, the group must be predefined in
the TAXII server, and the name of the group in the TAXII server must match
the name of the group in the OIDC provider. Groups that are defined in the
OIDC provider by not in the TAXII server will have no impact on TAXII server
access.

## White Listing Token Issuers

Token issuers must be predefined in the TAXII server before tokens
will be accepted.  Issuers are specified as follows

```
{
	"iss": "http://host:port",
	"required_role": "blessed-user"
}
```

`iss` is a required field containing the URL of an allowed value for the `iss`
field in the token itself.
The token is validated using the `userinfo_endpoint` member from the
`.well-known/openid-configuration` on the issuer or
`{iss}/protocol/openid-connect/userinfo` as a default.
`required_role` is an optional field.  If present,
the token *must* include the role in its body.

`VALID_ISSUERS` is an optional system environment variable containing a JSON
list of issuers to be loaded on server startup.

### `POST admin/v1.0/issuer`

Add the payload as a trusted issuer.

### `GET admin/v1.0/issuers`

Reply a list of all trusted issuers.

###	`GET admin/v1.0/issuer/{iss}`

Reply trusted issuer by `iss` member (will include `required_role`
if originally specified.

###`DELETE admin/v1.0/issuer/{iss}`

Delete trusted issuer by `iss`.
