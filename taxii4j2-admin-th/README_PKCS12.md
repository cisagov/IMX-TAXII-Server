<!--
  ~ Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
  ~
  ~ This software is released to the public domain under 17 U.S.C. § 105.
  ~ The Apache 2.0 license applies to the extent permitted by applicable law,
  ~ and for the benefit of international users.
-->

# PKCS12 Authentication Management

The CISA server supports PKCS12 authentication.
Clients provide a certificate / private key pair during TLS handshake
to establish both mTLS (two-way TLS) and user identity
(derived from the RDN information in the certificate).

Administrators can either
- use the server itself to generate a new self-signed certificate / private key pair to be
imported into the truststore (in a single step),
- provide a single user certificate (generated / procured elsewhere)
and import it into the server truststore, or
- provide the CA certificate chain of an organization generating certificates to be
used, import the chain into the server truststore, and create specific user accounts
separately using the certificate subject name.

Which method to use will depend on the number of accounts to be created and the
availability of externally generated certificates.

## Certificate / Private Key Generation

The parameterized endpoint `admin/v1.0/pkcs12/{O}/{CN}`
(a `POST` accessible only to users granted the `imx-admin` role)
expects a JSON
payload - an array of strings - that defines the roles to be granted to the user.
The `{O}` URL path parameter is encoded into the `owner` RDN;
similarly the `{CN}` URL path parameter is encoded into the `common name` RDN.
These two parameters make up the generated user name and should be unique
(unless the desire is to create a new certificate for an existing PKCS12 user).

`curl -k --user 'imx-admin:$TAXII_PASSWORD' https://localhost:9443/admin/v1.0/pkcs12/CISA/IMX-User -H 'Content-Type: application/json' -d '["imx-user"]'`

returns a JSON like

```
{
  "byo": {
    "p12": "p12 value...",
    "password": "password",
    "roles": [
      "imx-user"
    ]
  },
  "crt": "crt value...",
  "key": "key value..."
}
```

Within the `byo` element, the base64-encoded PKCS12 keystore and its encryption password are provided
(to be used by your favorite HTTPS client software).
The certificate and unencrypted private key are provided in the `crt` and `key` fields respectively.

As a proof of concept, we'll use `curl`.
Using your favorite text editor, craft the certificate and key into the following shapes
(I captured the original JSON response into a file, named my certificate file `kad.crt` and my unencrypted private key file `kad.key`)...

```
crt value...
```

```
key value...
```

...by splitting the response and converting the `\n` literals to real EOL characters
(exercise left to the reader).

Assuming everything was done correctly

`curl -k https://localhost:9443/taxii/v2.1-os/taxii2/ --cert kad.crt --key kad.key`

will successfully connect to the server using mTLS and authenticate.

## Importing an External Certificate

The endpoint `/admin/v1.0/pkcs12/byo` accepts the `byo` object returned in the above call.
The JSON submission can take either a PCKS12 keystore and password, or a PEM encoded certificate.
Only one or the other should be submitted.

```
{
    "pem":
"pem value...",
    "roles": [ "imx-admin", "imx-user" ]
}

```

or

```
{
	"p12": "p12 value...",
	"password": "password",
	"roles": [ "imx-admin", "imx-user" ]
}

```

The newlines in the PEM formatted certificate are part of the PEM standard, and must be converted
to `\n` before being submitted to the endpoint. The proper format can be generated with the following
command.

`awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' test.crt `

### Example of Importing a Certificate

For the purposes of this example, I...

```
openssl req -newkey rsa:2048 -nodes -keyout domain.key -out domain.csr -subj /O=X/CN=Y
openssl x509 -signkey domain.key -in domain.csr -req -days 365 -out domain.crt
openssl pkcs12 -export -in domain.crt -inkey domain.key -name newbie -passout 'pass:Q' -out domain.p12
base64 -w 0 domain.p12 > domain.p12.b64
```

...generated the CSR (`domain.csr`) / unencrypted private key (`domain.key`) pair, self-signed
it (`domain.crt`), built a PEM (`domain.p12`) and finally base64-encoded it.
I now have what I would e.g. buy from a certificate provider (albeit mine is self-signed).

The `admin/v1.0/pkcs12/byo` (a `POST` accessible to users granted `imx-admin` role) takes
a payload like

```
{
	"pem": "men value...",
	"password": "Q",
	"roles": [
		"imx-user"
	]
}
```

where the PEM came from my `domain.p12.b64` and the password from the PEM generating `openssl` call parameter.
Keep in mind that my simple password is ephemeral and only serves the purpose of encoding my
example PEM.  Now, I

`curl -k --user 'imx-admin:$TAXII_PASSWORD' https://localhost:9443/admin/v1.0/pkcs12/byo -H 'Content-Type: application/json' -d @domain.json`

and get

```
{
  "user": "CN=Y, O=X",
  "password": "MD5:md5 value...",
  "roles": [
    "imx-user"
  ]
}
```

which is the internalized user name and password (both derived from the PEM contents -
again reminding the reader that this user password has nothing to do with the simple
PEM password used earlier).
If I did things correctly, I can now access the server with

`curl -k https://localhost:9443/taxii/v2.1-os/taxii2/ --cert domain.crt --key domain.key`

which indeed I can.

## Importing a Certificate Authority Trust Chain

The server can also use certificates from a trusted certificate authority to identify users. This configuration
requires multiple steps; first adding the trust chain to the server's truststore, and then creating user accounts
in the server using the subject name in the certificate.

### Deploy a custom Truststore

The Certificate Authority trust chain (root certificate and any intermediate signing certficates) should be in a
PKCS12 keystore file mounted to the TAXII server container. This should be in the same location as the keystore
file containing the server certificate used by the server. Set the environment variables `TAXII_TRUSTSTORE` and
`TAXII_TRUSTSTORE_PASSWORD` to the file location and truststore password.  For example,

```
TAXII_TRUSTSTORE=/opt/keystore/truststore.p12
TAXII_TRUSTSTORE_PASSWORD=password
```

The trust chain can also be included in the keystore file, if no separate truststore is used.

### Create user accounts

Adding the Certificate Authority trust chain will allow the server to authenticate via a client certificate
signed by the Certificate Authority, but does not grant access. The user must be added to the server
using the same endpoints that are used to create, update and delete users that use Basic authentication.
The user account must use the Subject Name used in the certificate, and include the list of roles granted
to the user. The account should not include a password, since authentication is being performed via
mutual TLS.

For example, post the following to the endpoint `https://localhost:9443/admin/v1.0/user` to grant access
to the user identified by a certificate with the given subject, and to give the user the `imx-admin` role.

```
{
    "user": "CN=Test User, C=US",
    "roles": [ "imx-user" ]
}
```
