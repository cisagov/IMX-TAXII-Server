/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.method;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.CTIMediaType;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.auth.data.Fragment;
import com.cisa.taxii4j2.auth.data.Issuer;
import com.cisa.taxii4j2.auth.data.Lenient;
import com.cisa.taxii4j2.auth.data.MappedCollections;
import com.cisa.taxii4j2.auth.data.MappedCollections.MappedCollection;
import com.cisa.taxii4j2.auth.data.RWCollection;
import com.cisa.taxii4j2.auth.data.TAXIICredentials;
import com.cisa.taxii4j2.auth.data.TCPKCS12;
import com.cisa.taxii4j2.auth.data.User;
import com.cisa.taxii4j2.auth.method.BulkAdmin.Configuration;
import com.cisa.taxii4j2.auth.method.GroupAdmin.Group;
import com.cisa.taxii4j2.auth.method.RoleAdmin.RoleUse;
import com.cisa.taxii4j2.auth.method.RootCollectionAdmin.RootCollection;
import com.cisa.taxii4j2.data.ApiRoot;
import com.cisa.taxii4j2.data.Collections.Collection;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.method.impl.Objects;
import com.cisa.taxii4j2.method.logging.LogEntryConnector;
import com.cisa.taxii4j2.servlet.Logged;
import com.cisa.taxii4j2.servlet.security.TAXIITrustManager;
import com.cisa.taxii4j2.servlet.store.DbBase;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


@Singleton
@Path("/admin/v1.0/")
public class AuthEndpoint extends MinAuthEndpoint {

	public static final Logger logger = LogManager.getLogger(AuthEndpoint.class);

	private final RootCollectionAdmin rootCollectionAuth;
	private final BulkAdmin authConfiguration;
	private final RoleAdmin roleAdmin;
	private final GroupAdmin groupAdmin;
	private final IssuerAdmin issuerAdmin;
	private final DbBase db;
	private final Objects objects;

	@Inject
	public AuthEndpoint(UserAdmin userAuth, RootCollectionAdmin rootCollectionAuth, BulkAdmin authConfiguration,
			RoleAdmin roleAdmin, GroupAdmin groupAdmin, IssuerAdmin issuerAdmin, LogEntryConnector connector, DbBase db,
			Objects objects) {
		super(userAuth, connector);
		this.rootCollectionAuth = rootCollectionAuth;
		this.authConfiguration = authConfiguration;
		this.roleAdmin = roleAdmin;
		this.groupAdmin = groupAdmin;
		this.issuerAdmin = issuerAdmin;
		this.db = db;
		this.objects = objects;
	}

	@Tag(name = "Database Management")
	@Operation(description = "list available snapshots")
	@GET
	@Path("snapshots")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public Response listSnapshots() {
		logger.info("Retrieved list of snapshots; path=[taxii]/admin/v1.0/snapshots");
		try {
			return ok(db.listSnapshots());
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Database Management")
	@Operation(description = "create a snapshot (async - use GET snapshot/{name} to check status")
	@PUT
	@Path("snapshot/{name}")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public Response createSnapshot(@PathParam("name") String name) {
		logger.info("Created snapshot; path=[taxii]/admin/v1.0/snapshot/" + name);
		try {
			return ok(db.createSnapshot(name));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Database Management")
	@Operation(description = "get snapshot status")
	@GET
	@Path("snapshot/{name}")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public Response getSnapshotStatus(@PathParam("name") String name) {
		logger.info("Checked status of snapshot; path=[taxii]/admin/v1.0/snapshot/" + name);
		try {
			return ok(db.getSnapshotStatus(name));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Database Management")
	@Operation(description = "delete snapshot")
	@DELETE
	@Path("snapshot/{name}")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public Response deleteSnapshot(@PathParam("name") String name) {
		logger.info("Deleted snapshot; path=[taxii]/admin/v1.0/snapshot/" + name);
		try {
			return ok(db.deleteSnapshot(name));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Database Management")
	@Operation(description = "restore a snapshot - synchronous")
	@PUT
	@Path("snapshot/{name}/restore")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public Response restoreSnapshot(@PathParam("name") String name) {
		logger.info("Restored snapshot; path=[taxii]/admin/v1.0/snapshot/" + name);
		try {
			return ok(db.restoreSnapshot(name));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(operationId = "list-lenients", description = "get options for api / collection validation control")
	@GET
	@Path("lenients")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response listLenients() {
		logger.info("Retrieved list of lenients; path=[taxii]/admin/v1.0/lenients");
		try {
			return ok(rootCollectionAuth.listLenients());
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@JsonInclude(Include.NON_NULL)
	public static class ByoPkcs12 {

		private static final String tagKey = "tag";
		private static final String pemKey = "pem";
		private static final String pkcs12Key = "p12";
		private static final String passwordKey = "password";
		private static final String rolesKey = "roles";

		@JsonProperty(tagKey)
		private final String tag;

		@JsonProperty(pemKey)
		private final String pem;

		@JsonProperty(pkcs12Key)
		private final String p12;

		@JsonProperty(passwordKey)
		private final String password;

		@JsonProperty(rolesKey)
		private final Set<String> roles;

		@JsonCreator
		public ByoPkcs12(@JsonProperty(value = tagKey, required = false) String tag,
				@JsonProperty(value = pemKey, required = false) String pem,
				@JsonProperty(value = pkcs12Key, required = false) String p12,
				@JsonProperty(value = passwordKey, required = false) String password,
				@JsonProperty(value = rolesKey, required = false) Set<String> roles) {
			super();

			if (pem == null && p12 == null) {
				throw new IllegalStateException("One of pem or p12 must be set");
			}
			this.tag = tag;
			this.pem = pem;
			this.p12 = p12;
			this.password = password;
			this.roles = roles;
		}

		public Set<String> getRoles() {
			return roles;
		}

		public String getTag() {
			return tag;
		}

		public String getPem() {
			return pem;
		}

		public String getP12() {
			return p12;
		}

		public String getPassword() {
			return password;
		}

		@JsonIgnore
		public Map.Entry<String, Certificate> getEntry() {
			try (InputStream in = new ByteArrayInputStream(Base64.getDecoder().decode(p12))) {
				KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
				keyStore.load(in, password.toCharArray());
				Enumeration<String> iAlias = keyStore.aliases();
				while (iAlias.hasMoreElements()) {
					String alias = iAlias.nextElement();
					return new AbstractMap.SimpleImmutableEntry<String, Certificate>(alias,
							keyStore.getCertificate(alias));
				}
				throw new IllegalStateException();
			} catch (Exception e) {
				throw new IllegalStateException(e);
			}
		}

		@JsonIgnore
		public Certificate getCertificate() {
			if (p12 != null) {
				return getEntry().getValue();
			}
			else if (pem != null) {
				try (InputStream in = new ByteArrayInputStream(pem.getBytes())) {
					return CertificateFactory.getInstance("X.509").generateCertificate(in);
				} catch (Exception e) {
					throw new IllegalStateException(e);
				}
			}
			return null;
		}

		@Override
		public String toString() {
			return JSON.convertValue(this, JsonNode.class).toPrettyString();
		}

	}

	@Tag(name = "Authentication Management")
	@Operation(operationId = "import-PKCS12-cert", description = "install PKCS12 certificate as user")
	@POST
	@Path("pkcs12/byo")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response byoPkcs12(ByoPkcs12 request) {
		logger.info("Installed PKCS12 certificate; path=[taxii]/admin/v1.0/pkcs12/byo");
		Certificate certificate = request.getCertificate();
		User user = TCPKCS12.getUser(certificate);
		TAXIITrustManager.instance(request.getTag()).addCertificate(user.getUser(), certificate);
		Set<String> roles = request.getRoles();
		if (roles != null) {
			request.getRoles().forEach(role -> user.addRole(role));
		}
		return super.upsertUser(user, false);
	}

	@JsonInclude(Include.NON_NULL)
	public static class Pkcs12Response {

		private static final String byoKey = "byo";
		private static final String crtKey = "crt";
		private static final String keyKey = "key";

		@JsonProperty(byoKey)
		private final ByoPkcs12 byo;

		@JsonProperty(crtKey)
		private final String crt;

		@JsonProperty(keyKey)
		private final String key;

		@JsonCreator
		public Pkcs12Response(@JsonProperty(value = byoKey, required = true) ByoPkcs12 byo,
				@JsonProperty(value = crtKey, required = true) String crt,
				@JsonProperty(value = keyKey, required = true) String key) {
			super();
			this.byo = byo;
			this.crt = crt;
			this.key = key;
		}

		public ByoPkcs12 getByo() {
			return byo;
		}

		public String getCrt() {
			return crt;
		}

		public String getKey() {
			return key;
		}

	}

	@Tag(name = "Authentication Management")
	@Operation(operationId = "generate-PKCS12-cert", description = "generate and install PKCS12 certificate as user")
	@POST
	@Path("pkcs12/{O}/{CN}")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response createPkcs12(@PathParam("O") String O, @PathParam("CN") String CN, Set<String> roles) {
		try {
			logger.info("Generated and installed PKCS12 certificate; path=[taxii]/admin/v1.0/pkcs12/" + O + "/" + CN);
//			openssl req -newkey rsa:2048 -nodes -keyout domain.key -out domain.csr -subj /O=X/CN=Y -passout 'pass:Z'
			String subj = String.format("/O=%s/CN=%s", O, CN);
			java.nio.file.Path domainKey = Files.createTempFile("pkcs12", ".key");
			java.nio.file.Path domainCSR = Files.createTempFile("pkcs12", ".csr");
			ProcessBuilder builder = new ProcessBuilder("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout",
					domainKey.toString(), "-out", domainCSR.toString(), "-subj", subj);
			File devNull = new File("/dev/null");
			builder.redirectError(devNull).redirectOutput(devNull);
			Process process = builder.start();
			if (!process.waitFor(15, TimeUnit.SECONDS)) {
				throw new InternalServerErrorException();
			}
			String key = null;
			try (InputStream in = Files.newInputStream(domainKey)) {
				key = new String(in.readAllBytes());
			}

//			openssl x509 -signkey domain.key -in domain.csr -req -days 365 -out domain.crt
			java.nio.file.Path domainCrt = Files.createTempFile("pkcs12", ".crt");
			builder = new ProcessBuilder("openssl", "x509", "-signkey", domainKey.toString(), "-in",
					domainCSR.toString(), "-req", "-days", "365", "-out", domainCrt.toString());
			builder.redirectError(devNull).redirectOutput(devNull);
			process = builder.start();
			if (!process.waitFor(15, TimeUnit.SECONDS)) {
				throw new InternalServerErrorException();
			}
			String crt = null;
			try (InputStream in = Files.newInputStream(domainCrt)) {
				crt = new String(in.readAllBytes());
			}

//			openssl pkcs12 -export -in domain.crt -inkey domain.key -name newbie -passout 'pass:Q' -out domain.p12
			String password = User.generatePassword();
			java.nio.file.Path domainP12 = Files.createTempFile("pkcs12", ".p12");
			builder = new ProcessBuilder("openssl", "pkcs12", "-export", "-in", domainCrt.toString(), "-inkey",
					domainKey.toString(), "-name", "newbie", "-passout", String.format("pass:%s", password), "-out",
					domainP12.toString());
			builder.redirectError(devNull).redirectOutput(devNull);
			process = builder.start();
			if (!process.waitFor(15, TimeUnit.SECONDS)) {
				throw new InternalServerErrorException();
			}
			String pem = null;
			try (InputStream in = Files.newInputStream(domainP12)) {
				pem = Base64.getEncoder().encodeToString(in.readAllBytes());
			}

			ByoPkcs12 request = new ByoPkcs12(null, null, pem, password, roles);
			byoPkcs12(request);

			Pkcs12Response response = new Pkcs12Response(request, crt, key);
			return Response.ok(response).build();

		} catch (IOException | InterruptedException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Tag(name = "Authentication Management")
	@Operation(description = "add an OIDC token issuer to the whitelist")
	@POST
	@Path("issuer")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Issuer putIssuer(Issuer issuer) {
		logger.info("Added OIDC token issuer to whitelist; path=[taxii]/admin/v1.0/issuer; input=" + issuer);
		return issuerAdmin.put(issuer);
	}

	@Tag(name = "Authentication Management")
	@Operation(description = "get list of whitelisted OIDC token issuers")
	@GET
	@Path("issuers")
	@Produces(MediaType.APPLICATION_JSON)
	public List<Issuer> listIssuers() {
		logger.info("Retrieved whitelisted OIDC token issuers; path=[taxii]/admin/v1.0/issuers");
		return issuerAdmin.list();
	}

	@Tag(name = "Authentication Management")
	@Operation(description = "get whitelisted OIDC token issuer by URL")
	@GET
	@Path("issuer/{iss}")
	@Produces(MediaType.APPLICATION_JSON)
	public Issuer getIssuer(@PathParam("iss") String iss) {
		logger.info("Retrieved whitelisted OIDC token issuer; path=[taxii]/admin/v1.0/issuer/" + iss);
		return issuerAdmin.get(iss);
	}

	@Tag(name = "Authentication Management")
	@Operation(description = "remove whitelisted OIDC token issuer by URL")
	@DELETE
	@Path("issuer/{iss}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response deleteIssuer(@PathParam("iss") String iss) {
		logger.info("Removed  OIDC token issuer from whitelist; path=[taxii]/admin/v1.0/issuer/" + iss);
		issuerAdmin.delete(iss);
		return Response.ok().build();
	}

	@Tag(name = "Miscellaneous")
	@Operation(description = "get actual user r/w permissions based on credentials")
	@GET
	@Path("permissions")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public Response permissions(@HeaderParam(HttpHeaders.AUTHORIZATION) String credentials) {
		logger.info("Retrieved user's r/w permissions based on credentials; path=[taxii]/admin/v1.0/permissions; input=" + credentials);
		return Response.ok().entity(rootCollectionAuth.permissions(TAXIICredentials.getUser(credentials).getRoles()))
				.build();
	}

	@Tag(name = "Anonymous Access Management")
	@Operation(description = "add one or more api-root/collection-id pairs to anonymous user whitelist")
	@POST
	@Path("sandbox")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public Response sandboxAdd(List<RootCollection> rcs) {
		logger.info("Added api root/collection id pair to Sandbox anonymous user whitelist; path=[taxii]/admin/v1.0/sandbox; input=" + rcs);
		try {
			rootCollectionAuth.sandboxAdd(rcs);
			return Response.ok().build();
		} catch (Exception e) {
			throw new BadRequestException(e);
		}
	}

	@Tag(name = "Anonymous Access Management")
	@Operation(description = "remove one or more api-root/collection-id pairs from anonymous user whitelist")
	@DELETE
	@Path("sandbox")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public Response sandboxRemove(List<RootCollection> rcs) {
		logger.info("Removed api root/collection id pair to Sandbox anonymous user whitelist; path=[taxii]/admin/v1.0/sandbox" + rcs);
		try {
			rootCollectionAuth.sandboxRemove(rcs);
			return Response.ok().build();
		} catch (Exception e) {
			throw new BadRequestException(e);
		}
	}

	@Tag(name = "Anonymous Access Management")
	@Operation(description = "reply api-root/collection-id pairs on anonymous user whitelist")
	@GET
	@Path("sandbox")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public Response sandboxSet() {
		logger.info("Retrieved api root/collection id pairs on Sandbox anonymous user whitelist; path=[taxii]/admin/v1.0/sandbox");
		try {
			return Response.ok(rootCollectionAuth.sandboxSet(), MediaType.APPLICATION_JSON).build();
		} catch (Exception e) {
			throw new BadRequestException(e);
		}
	}

	@Tag(name = "Documentation")
	@Operation(operationId = "api", description = "displays OpenAPI documentation")
	@GET
	@Path("api")
	@Produces(MediaType.TEXT_HTML)
	@Logged
	public InputStream api() {
		logger.info("Retrieved OpenAPI documentation; path=[taxii]/admin/v1.0/api");
		return ClassLoader.getSystemResourceAsStream("api.html");
	}

	@Tag(name = "Bulk Changes")
	@Operation(description = "creates users, api-roots, and collections from the payload")
	@POST
	@Path("configure")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response configure(Configuration configuration) {
		logger.info("Created user, api roots, and/or collections from payload; path=[taxii]/admin/v1.0/configure; input=" + configuration);
		try {
			return ok(authConfiguration.configure(configuration));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	// @Override
	public void close() throws IOException {

	}

	@Tag(name = "API Root Management")
	@Operation(operationId = "upsert-api-root", description = "create (or replace) an api-root. setting create to true (default false) ensures creation.")
	@POST
	@Path("api-root")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response upsertFragment(Fragment fragment, @DefaultValue("false") @QueryParam("create") boolean create) {
		logger.info("Created or replaced api root; path=[taxii]/admin/v1.0/api-root; input=" + fragment);
		try {
			return ok(rootCollectionAuth.upsertFragment(fragment, create));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(operationId = "read-api-root", description = "get details for the named api-root")
	@GET
	@Path("api-root/{name}")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response readFragment(@PathParam("name") String name) {
		logger.info("Retrieved details for api root; path=[taxii]/admin/v1.0/api-root/" + name);
		try {
			return ok(rootCollectionAuth.readFragment(name));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	private Response ok(Object entity) {
		return Response.ok(entity, CTIMediaType.TAXII2_1).build();
	}

	private Response error(WebApplicationException e) {
		return error(e, e.getResponse().getStatusInfo());
	}

	private Response error(Exception e) {
		return error(e, Response.Status.INTERNAL_SERVER_ERROR);
	}

	private Response error(Exception e, Response.StatusType status) {
		Integer statusCode = status.getStatusCode();
		return Response.status(statusCode)
				.entity(new Error(status.toString(), e.getMessage(), null, null, statusCode.toString(), null, null))
				.type(CTIMediaType.TAXII2_1).build();
	}

	@Tag(name = "API Root Management")
	@Operation(operationId = "list-api-roots", description = "list the existing api-root details")
	@GET
	@Path("api-roots")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response listFragments() {
		logger.info("Retrieved list of api root details; path=[taxii]/admin/v1.0/api-roots");
		try {
			return ok(rootCollectionAuth.listFragments());
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(operationId = "delete-api-root", description = "delete named api-root")
	@DELETE
	@Path("api-root/{name}")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response deleteFragment(@PathParam("name") String name) {
		logger.info("Deleted api root; path=[taxii]/admin/v1.0/api-root/" + name);
		try {
			return ok(rootCollectionAuth.deleteFragment(name));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(description = "add a role that can write to the named collection in the context of the named api-root")
	@POST
	@Path("api-root/{name}/{cId}/addCan_write")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response addCan_write(@PathParam("name") String name, @PathParam("cId") String cId, String writer) {
		logger.info("Added role that can write to collection; path=[taxii]/admin/v1.0/" + name + "/" + cId + "/addCan_write");
		try {
			return ok(rootCollectionAuth.addCan_write(name, cId, writer));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(description = "add a role that can read from the named collection in the context of the named api-root")
	@POST
	@Path("api-root/{name}/{cId}/addCan_read")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response addCan_read(@PathParam("name") String name, @PathParam("cId") String cId, String reader) {
		logger.info("Added role that can read from collection; path=[taxii]/admin/v1.0/api-root/" + name + "/" + cId + "/addCan_read");
		try {
			return ok(rootCollectionAuth.addCan_read(name, cId, reader));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(description = "identify a role that will no longer be able to write from the named collection in the context of the named api-root")
	@POST
	@Path("api-root/{name}/{cId}/removeCan_write")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response removeCan_write(@PathParam("name") String name, @PathParam("cId") String cId, String writer) {
		logger.info("Removed role from writing to collection; path=[taxii]/admin/v1.0/api-root" + name + "/" + cId + "/removeCan_write");
		try {
			return ok(rootCollectionAuth.removeCan_write(name, cId, writer));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(description = "identify a role that will no longer be able to read from the named collection in the context of the named api-root")
	@POST
	@Path("api-root/{name}/{cId}/removeCan_read")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response removeCan_read(@PathParam("name") String name, @PathParam("cId") String cId, String reader) {
		logger.info("Added role from reading collection; path=[taxii]/admin/v1.0/api-root/" + name + "/" + cId + "/removeCan_read");
		try {
			return ok(rootCollectionAuth.removeCan_read(name, cId, reader));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(description = "remove all access to the named collection in the context of the named api-root")
	@DELETE
	@Path("api-root/{name}/{cId}/removeRW")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response removeRW(@PathParam("name") String name, @PathParam("cId") String cId) {
		logger.info("Removed all read/write access to collection; path=[taxii]/admin/v1.0/" + name + "/" + cId + "/removeRW");
		try {
			return ok(rootCollectionAuth.removeRW(name, cId));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(description = "add access to the named collection in the context of the named api-root. side effect of TLP objects being added to referenced collection.")
	@POST
	@Path("api-root/{name}/addRW")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response addRW(@PathParam("name") String name, RWCollection rw) {
		logger.info("Added access to collection; path=[taxii]/admin/v1.0/" + name + "/addRW");
		try {
			return ok(rootCollectionAuth.addRW(name, rw));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(operationId = "set-api-root-lenients", description = "set api-root behavior with respect to object ingest")
	@POST
	@Path("api-root/{name}/lenients")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response setLenients(@PathParam("name") String name, Set<Lenient> values) {
		logger.info("Set api root behaviour for object ingest; path=[taxii]/admin/v1.0/api-root/" + name + "/lenients");
		try {
			return ok(rootCollectionAuth.setLenients(name, values));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(operationId = "get-api-root-lenients", description = "get api-root behavior with respect to object ingest")
	@GET
	@Path("api-root/{name}/lenients")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response getLenients(@PathParam("name") String name) {
		logger.info("Retrieved api root behaviour for object ingest; path=[taxii]/admin/v1.0/api-root/" + name + "/lenients");
		try {
			return ok(rootCollectionAuth.getLenients(name));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(operationId = "add-api-root-lenients", description = "add api-root behavior with respect to object ingest")
	@POST
	@Path("api-root/{name}/lenients/add")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response addLenients(@PathParam("name") String name, Set<Lenient> values) {
		logger.info("Added api root behaviour for object ingest; path=[taxii]/admin/v1.0/api-roots" + name + "/lenients/add");
		try {
			return ok(rootCollectionAuth.addLenients(name, values));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(operationId = "remove-api-root-lenients", description = "remove api-root behavior with respect to object ingest")
	@POST
	@Path("api-root/{name}/lenients/remove")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response removeLenients(@PathParam("name") String name, Set<Lenient> values) {
		logger.info("Removed api root behaviour for object ingest; path=[taxii]/admin/v1.0/api-root/" + name + "/lenients/remove");
		try {
			return ok(rootCollectionAuth.removeLenients(name, values));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(operationId = "set-collection-lenients", description = "set collection behavior WRT object ingest")
	@POST
	@Path("api-root/{name}/{cId}/lenients")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response setLenients(@PathParam("name") String name, @PathParam("cId") String cId, Set<Lenient> values) {
		logger.info("Set collection behaviour for object ingest; path=[taxii]/admin/v1.0/api-root/" + name + "/" + cId + "/lenients");
		try {
			return ok(rootCollectionAuth.setLenients(name, rootCollectionAuth.readCollection(cId).getId(), values));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(operationId = "get-collection-lenients", description = "get collection behavior WRT object ingest")
	@GET
	@Path("api-root/{name}/{cId}/lenients")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response getLenients(@PathParam("name") String name, @PathParam("cId") String cId) {
		logger.info("Retrieved collection behaviour for object ingest; path=[taxii]/admin/v1.0/api-root" + name + "/" + cId + "/lenients");
		try {
			return ok(rootCollectionAuth.getLenients(name, rootCollectionAuth.readCollection(cId).getId()));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(operationId = "add-collection-lenients", description = "Add collection behavior WRT object ingest")
	@POST
	@Path("api-root/{name}/{cId}/lenients/add")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response addLenients(@PathParam("name") String name, @PathParam("cId") String cId, Set<Lenient> values) {
		logger.info("Added collection behaviour for object ingest; path=[taxii]/admin/v1.0/api-root/" + name + "/" + cId + "/lenients/add");
		try {
			return ok(rootCollectionAuth.addLenients(name, rootCollectionAuth.readCollection(cId).getId(), values));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(operationId = "remove-collection-lenients", description = "Remove collection behavior WRT object ingest")
	@POST
	@Path("api-root/{name}/{cId}/lenients/remove")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response removeLenients(@PathParam("name") String name, @PathParam("cId") String cId, Set<Lenient> values) {
		logger.info("Removed collection behaviour for object ingest; path=[taxii]/admin/v1.0/api-root/" + name + "/" + cId + "/lenients/remove");
		try {
			return ok(rootCollectionAuth.removeLenients(name, rootCollectionAuth.readCollection(cId).getId(), values));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(description = "update the apiRoot data for the named api-root")
	@POST
	@Path("api-root/{name}/setApiRoot")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response setApiRoot(@PathParam("name") String name, ApiRoot apiRoot) {
		logger.info("Updated apiRoot data for the named api root; path=[taxii]/admin/v1.0/api-root/" + name + "/setApiRoot; input=" + apiRoot);
		try {
			return ok(rootCollectionAuth.setApiRoot(name, apiRoot));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "API Root Management")
	@Operation(description = "get the mapped collections for the named api-root")
	@GET
	@Path("api-root/{name}/collections")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response mappedCollections(@PathParam("name") String name) {
		logger.info("Retrieved collections on api root; path=[taxii]/admin/v1.0/api-root/" + name + "/collections");
		try {
			List<MappedCollection> mcs = new ArrayList<>();
			List<RWCollection> rws = rootCollectionAuth.readFragment(name).getRws();
			if (rws != null) {
				for (RWCollection rw : rws) {
					mcs.add(new MappedCollection(rootCollectionAuth.readCollection(rw.getId()), rw));
				}
			}
			return ok(new MappedCollections(mcs));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Collection Management")
	@Operation(description = "get details for the named collection (id or alias)")
	@GET
	@Path("collection/{cId}")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response readCollection(@PathParam("cId") String cId) {
		logger.info("Retrieved details for collection; path=[taxii]/admin/v1.0/collection/" + cId);
		try {
			return ok(rootCollectionAuth.readCollection(cId));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Collection Management")
	@Operation(description = "list the existing collection details")
	@GET
	@Path("collections")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response listCollections() {
		logger.info("Retrieved details for all collections; path=[taxii]/admin/v1.0/collections");
		try {
			return ok(rootCollectionAuth.listCollections());
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Collection Management")
	@Operation(description = "create (or replace) a collection. setting create to true (default false) ensures create")
	@POST
	@Path("collection")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response upsertCollection(Collection collection,
			@DefaultValue("false") @QueryParam("create") boolean create) {
		logger.info("Created or replaced collection; path=[taxii]/admin/v1.0/collections; input=" + collection);
		try {
			return ok(rootCollectionAuth.upsertCollection(collection, create));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Collection Management")
	@Operation(description = "delete the named collection (id or alias)")
	@DELETE
	@Path("collection/{cId}")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response deleteCollection(@PathParam("cId") String cId) {
		logger.info("Deleted collection; path=[taxii]/admin/v1.0/collection/" + cId);
		try {
			return ok(rootCollectionAuth.deleteCollection(cId));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Collection Management")
	@Operation(description = "delete all objects in the named collection (id or alias)")
	@DELETE
	@Path("collection/{cId}/objects")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response clearCollection(@PathParam("cId") String cId) {
		logger.info("Removed all objects in collection; path=[taxii]/admin/v1.0/collection/" + cId);
		try {
			objects.delete(rootCollectionAuth.readCollection(cId).getId(), null, new Filters());
			return Response.ok().build();
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Collection Management")
	@Operation(description = "set the description for the named collection (id or alias)")
	@POST
	@Path("collection/{cId}/setDescription")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response setDescription(@PathParam("cId") String cId, String description) {
		logger.info("Set description for collection; path=[taxii]/admin/v1.0/collection/" + cId + "/setDescription; input=" + description);
		try {
			return ok(rootCollectionAuth.setDescription(cId, description));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Collection Management")
	@Operation(description = "set the alias for the named collection (id or alias)")
	@POST
	@Path("collection/{cId}/setAlias")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response setAlias(@PathParam("cId") String cId, String alias) {
		logger.info("Set alias for collection; path=[taxii]/admin/v1.0/collection/" + cId + "/setAlias; input=" + alias);
		try {
			return ok(rootCollectionAuth.setAlias(cId, alias));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Collection Management")
	@Operation(description = "add a media type for the named collection (id or alias)")
	@POST
	@Path("collection/{cId}/addMedia_type")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response add(@PathParam("cId") String cId, String media_type) {
		logger.info("Added media type for collection; path=[taxii]/admin/v1.0/colletion/" + cId + "/addMedia_type; input=" + media_type);
		try {
			return ok(rootCollectionAuth.addMedia_type(cId, media_type));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Collection Management")
	@Operation(description = "remove a media type from the named collection (id or alias)")
	@DELETE
	@Path("collection/{cId}/removeMedia_type/{media_type}")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response remove(@PathParam("cId") String cId, @PathParam("media_type") String media_type) {
		logger.info("Removed media type from collection; path=[taxii]/admin/v1.0/collection/" + cId + "/removeMedia_type/" + media_type);
		try {
			return ok(rootCollectionAuth.removeMedia_type(cId, media_type));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Collection Management")
	@Operation(description = "set the global read permission for the named collection (id or alias)")
	@POST
	@Path("collection/{cId}/setCan_read")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response setCan_read(@PathParam("cId") String cId, boolean can_read) {
		logger.info("Set global read permission for collection; path=[taxii]/admin/v1.0/collection" + cId + "/setCan_read");
		try {
			return ok(rootCollectionAuth.setCan_read(cId, can_read));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Collection Management")
	@Operation(description = "set the global write permission for the named collection (id or alias)")
	@POST
	@Path("collection/{cId}/setCan_write")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response setCan_write(@PathParam("cId") String cId, boolean can_write) {
		logger.info("Set global write permission for collection; path=[taxii]/admin/v1.0/collection/" + cId + "setCan_write");
		try {
			return ok(rootCollectionAuth.setCan_write(cId, can_write));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Collection Management")
	@Operation(description = "set the title for the named collection (id or alias)")
	@POST
	@Path("collection/{cId}/setTitle")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response setTitle(@PathParam("cId") String cId, String title) {
		logger.info("Set title for collection; path=[taxii]/admin/v1.0/collection/" + cId + "/setTitle");
		try {
			return ok(rootCollectionAuth.setTitle(cId, title));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Role Management")
	@Operation(description = "list roles (derived from those in use)")
	@GET
	@Path("roles")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response listRoles() {
		logger.info("Retrieved list of roles; path=[taxii]/admin/v1.0/roles");
		try {
			return ok(roleAdmin.list());
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Role Management")
	@Operation(description = "reply usage (api-root / collection / RW pairs and user_names) of a role")
	@GET
	@Path("role/{role}")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response readRole(@PathParam("role") String role) {
		logger.info("Retrieved usage of role; path=[taxii]/admin/v1.0/role/" + role);
		try {
			return ok(roleAdmin.read(role));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Role Management")
	@Operation(description = "delete role (from api-root / collection pairs and users)")
	@DELETE
	@Path("role/{role}")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response deleteRole(@PathParam("role") String role) {
		logger.info("Removed role; path=[taxii]/admin/v1.0/role/" + role);
		try {
			roleAdmin.delete(role);
			return Response.ok().build();
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Role Management")
	@Operation(description = "upsert (api-root / collection / RW triples and user names)")
	@POST
	@Path("role/{role}")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response upsertRole(@PathParam("role") String role, RoleUse roleUse) {
		logger.info("Upsert action on role; path=[taxii]/admin/v1.0/role/" + role + "; input=" + roleUse);
		try {
			return ok(roleAdmin.upsert(role, roleUse));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Group Management")
	@Operation(description = "list groups")
	@GET
	@Path("groups")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response listGroups() {
		logger.info("Retrieved list of groups; path=[taxii]/admin/v1.0/groups");
		try {
			return ok(groupAdmin.list());
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Group Management")
	@Operation(description = "get details for a specific group")
	@GET
	@Path("group/{group}")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response readGroup(@PathParam("group") String group) {
		logger.info(String.format("Retrieved specific group; path=[taxii]/admin/v1.0/group/%s", group));
		try {
			return ok(groupAdmin.read(group));
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Group Management")
	@Operation(description = "delete a group")
	@DELETE
	@Path("group/{group}")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response deleteGroup(@PathParam("group") String group) {
		logger.info(String.format("Delete group; path=[taxii]/admin/v1.0/group/%s", group));
		try {
			groupAdmin.delete(group);
			return Response.ok().build();
		} catch (Exception e) {
			return error(e);
		}

	}

	@Tag(name = "Group Management")
	@Operation(description = "create or update a group")
	@POST
	@Path("group")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response upsertGroup(Group group) {
		logger.info(String.format("Upsert group; path=[taxii]/admin/v1.0/group; name=%s", group.getName()));
		try {
			return ok(groupAdmin.upsert(group));
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Group Management")
	@Operation(description = "add users to an existing group")
	@POST
	@Path("group/{groupName}/addUsers")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response addUsersToGroup(@PathParam("groupName") String groupName, Set<String> userList) {
		logger.info(String.format("Add users to group; path=[taxii]/admin/v1.0/group/%s/addUsers", groupName));
		try {
			return ok(groupAdmin.addUsers(groupName, userList, false));
		} catch (Exception e) {
			return error(e);
		}
	}


	@Tag(name = "Group Management")
	@Operation(description = "remove users from an existing group")
	@POST
	@Path("group/{groupName}/removeUsers")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response removeUsersFromGroup(@PathParam("groupName") String groupName, Set<String> userList) {
		logger.info(String.format("Replace users in group; path=[taxii]/admin/v1.0/group/%s/removeUsers", groupName));
		try {
			return ok(groupAdmin.addUsers(groupName, userList, true));
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Group Management")
	@Operation(description = "add markings to an existing group")
	@POST
	@Path("group/{groupName}/addMarkings")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response addMarkingsToGroup(@PathParam("groupName") String groupName, Set<String> markingList) {
		logger.info(String.format("Add users to group; path=[taxii]/admin/v1.0/group/%s/addMarkings", groupName));
		try {
			return ok(groupAdmin.addMarkings(groupName, markingList, false));
		} catch (Exception e) {
			return error(e);
		}
	}


	@Tag(name = "Group Management")
	@Operation(description = "remove markings from an existing group")
	@POST
	@Path("group/{groupName}/removeMarkings")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response removeMarkingsFromGroup(@PathParam("groupName") String groupName, Set<String> markingList) {
		logger.info(String.format("Replace users in group; path=[taxii]/admin/v1.0/group/%s/removeMarkings", groupName));
		try {
			return ok(groupAdmin.addMarkings(groupName, markingList, true));
		} catch (Exception e) {
			return error(e);
		}
	}

}
