/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.method;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.cti4j2.CTIMediaType;
import com.cisa.taxii4j2.auth.data.User;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.method.logging.LogEntryConnector;
import com.cisa.taxii4j2.method.logging.LogEntryFilter;
import com.cisa.taxii4j2.servlet.Logged;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@Singleton
@Path("/admin/v1.0/")
public class MinAuthEndpoint {

	public static final Logger logger = LogManager.getLogger(MinAuthEndpoint.class);

	protected final UserAdmin userAuth;
	private final String adminUserName;
	private final String adminRole;
	private final LogEntryConnector connector;

	@Context
	private UriInfo uriInfo;

	@Inject
	public MinAuthEndpoint(UserAdmin userAuth, LogEntryConnector connector) {
		super();
		this.userAuth = userAuth;
		AuthConfig authConfig = PropsAuthConfig.instance();
		adminUserName = authConfig.getTaxiiAdminUsername();
		adminRole = authConfig.getAdminRole();
		this.connector = connector;
	}

	@JsonInclude(Include.NON_NULL)
	public static class BasePkcs10 {

		protected static final String pkcs10Key = "pkcs10";

		@JsonProperty(pkcs10Key)
		private final byte[] pkcs10;

		@JsonCreator
		protected BasePkcs10(@JsonProperty(value = pkcs10Key, required = true) byte[] pcks10) {
			super();
			this.pkcs10 = pcks10;
		}

		public byte[] getPkcs10() {
			return pkcs10;
		}

	}

	@JsonInclude(Include.NON_NULL)
	public static class ByoPkcs10 extends BasePkcs10 {

		private static final String rolesKey = "roles";

		@JsonProperty(rolesKey)
		private final List<String> roles;

		@JsonCreator
		public ByoPkcs10(@JsonProperty(value = pkcs10Key, required = true) byte[] pkcs10,
				@JsonProperty(value = rolesKey, required = false) List<String> roles) {
			super(pkcs10);
			this.roles = roles;
		}

		public List<String> getRoles() {
			return roles;
		}

	}

	@JsonInclude(Include.NON_NULL)
	public static class ResponsePkcs10 extends BasePkcs10 {

		private static final String userKey = "user";

		@JsonProperty(userKey)
		private final User user;

		@JsonCreator
		public ResponsePkcs10(@JsonProperty(value = pkcs10Key, required = true) byte[] pkcs10,
				@JsonProperty(value = userKey, required = true) User user) {
			super(pkcs10);
			this.user = user;
		}

		public User getUser() {
			return user;
		}

	}

	private ResponsePkcs10 pkcs10Helper(byte[] b, List<String> roles) throws IOException {
		PKCS10CertificationRequest csr = new PKCS10CertificationRequest(b);
		String[] kvs = Arrays.stream(csr.getSubject().getRDNs()).map(rdn -> rdn.getFirst())
				.map(kv -> String.format("%s=%s", kv.getType(), kv.getValue())).toArray(String[]::new);
		String username = Arrays.toString(kvs);
		String password = Base64.getEncoder().encodeToString(csr.getSignature());
		User user = userAuth.upsertUser(new User(username, password, roles), true);
		return new ResponsePkcs10(b, user);
	}

	@Tag(name = "Authentication Management")
	@Operation(operationId = "import-PKCS10-cert", description = "import PKCS10 as user")
	@POST
	@Path("pkcs10/byo")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public ResponsePkcs10 byoPkcs10(ByoPkcs10 byoPcks10) {
		logger.info("Imported PKCS10 as user; path=" + "[taxii]/admin/v1.0/pkcs10/byo; input=" + byoPcks10);
		try {
			return pkcs10Helper(byoPcks10.getPkcs10(), byoPcks10.roles);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

	@Tag(name = "Authentication Management")
	@Operation(operationId = "generate-PKCS10-cert", description = "generate and import PKCS10 as user")
	@POST
	@Path("pkcs10/{O}/{CN}")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public ResponsePkcs10 createPkcs10(@PathParam("O") String O, @PathParam("CN") String CN, List<String> roles) {
		logger.info("Generated and imported PKCS10 as user; path=[taxii]/admin/v1.0/pkcs10/" + O + "/" + CN);
		try {
			String subj = String.format("/O=%s/CN=%s", O, CN);
			ProcessBuilder builder = new ProcessBuilder("openssl", "req", "-out", "-", "-newkey", "rsa:2048",
					"-outform", "der", "-subj", subj, "-passout", "pass:CalJason2021!", "-keyout", "/dev/null");
			java.nio.file.Path stdout = Files.createTempFile("pkcs10", ".stdout");
			builder.redirectError(new File("/dev/null")).redirectOutput(stdout.toFile());
			Process process = builder.start();
			if (!process.waitFor(15, TimeUnit.SECONDS)) {
				throw new InternalServerErrorException();
			}
			try (InputStream in = Files.newInputStream(stdout)) {
				byte[] b = in.readAllBytes();
				return pkcs10Helper(b, roles);
			}
		} catch (IOException | InterruptedException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Tag(name = "Logging")
	@Operation(operationId = "get-logging-requests", description = "search for logged server requests")
	@GET
	@Path("requests")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public Response requests() {
		logger.info("Retrieved logged server requests; path=[taxii]/admin/v1.0/requests");
		try {
			return ok(connector.readRequestLogEntry(new LogEntryFilter(uriInfo.getQueryParameters())));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "Logging")
	@Operation(operationId = "get-logging-responses", description = "get one or more logged server responses by event_id(s)")
	@GET
	@Path("responses")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public Response responses(@DefaultValue("") @QueryParam("event_ids") String value) {
		logger.info("Retrieved responses by event id(s); path=[taxii]/admin/v1.0/responses; input=" + value);
		try {
			Set<Integer> event_ids = new TreeSet<>();
			for (String event_id : value.trim().split("\\s*,\\s*")) {
				try {
					event_ids.add(Integer.valueOf(event_id));
				} catch (Exception e) {

				}
			}
			return ok(connector.readResponseLogEntry(event_ids.stream().mapToInt(i -> i.intValue()).toArray()));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	// @Override
	public void close() throws IOException {

	}

	@Tag(name = "User Management")
	@Operation(operationId = "upsert-user", description = "create (or replace) a user. setting create to true (default false) ensures creation")
	@POST
	@Path("user")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response upsertUser(User user, @DefaultValue("false") @QueryParam("create") boolean create) {
		logger.info("Created or replaced a user; path=[taxii]/admin/v1.0/user; input=" + user);
		if (user.getUser().equals(adminUserName)) {
			user.addRole(adminRole);
		}
		try {
			return ok(userAuth.upsertUser(user, create));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "User Management")
	@Operation(operationId = "get-user", description = "get user details by name")
	@GET
	@Path("user/{name}")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response readUserByName(@PathParam("name") String name) {
		logger.info("Retrieved user details; path=[taxii]/admin/v1.0/user/" + name);
		try {
			return ok(userAuth.readUserByName(name));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "User Management")
	@Operation(operationId = "list-users", description = "list details for all users")
	@GET
	@Path("users")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response listUsers() {
		logger.info("Retrieved list of details for all users; path=[taxii]/admin/v1.0/users");
		try {
			return ok(userAuth.listUsers());
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "User Management")
	@Operation(operationId = "delete-user", description = "delete a user by name")
	@DELETE
	@Path("user/{name}")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response deleteUser(@PathParam("name") String name) {
		logger.info("Deleted a user; path=[taxii]/admin/v1.0/user/" + name);
		if (name.equals(adminUserName)) {
			throw new BadRequestException(
					String.format("Bootstrap admin user name \"%s\" can't be deleted", adminUserName));
		}
		try {
			return ok(userAuth.deleteUser(name));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "User Management")
	@Operation(operationId = "set-user-password", description = "set password for named (existing) user")
	@POST
	@Path("user/{name}/setPassword")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response setPassword(@PathParam("name") String name, String value) {
		logger.info("Set password for a user; path=[taxii]/admin/v1.0/user/" + name + "/setPassword; input=" + value);
		try {
			return ok(userAuth.setPassword(name, value));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "User Management")
	@Operation(operationId = "add-user-role", description = "add a role to the named (existing) user")
	@POST
	@Path("user/{name}/addRole")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response addRole(@PathParam("name") String name, String role) {
		logger.info("Added role to a user; path=[taxii]/admin/v1.0/user/" + name + "/addRole; input=" + role);
		try {
			return ok(userAuth.addRole(name, role));
		} catch (WebApplicationException e) {
			return error(e);
		} catch (Exception e) {
			return error(e);
		}
	}

	@Tag(name = "User Management")
	@Operation(operationId = "remove-user-role", description = "remove a role from the named (existing) user")
	@DELETE
	@Path("user/{name}/removeRole/{role}")
	@Consumes(CTIMediaType.TAXII2_1)
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response removeRole(@PathParam("name") String name, @PathParam("role") String role) {
		logger.info("Removed role from a user; path=[taxii]/admin/v1.0/user/" + name + "/removeRole/" + role);
		if (name.equals(adminUserName) && role.equals(adminRole)) {
			throw new BadRequestException(
					String.format("Can't remove role \"%s\" from user \"%s\"", adminRole, adminUserName));
		}
		try {
			return ok(userAuth.removeRole(name, role));
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

	protected UserAdmin getUserAuth() {
		return userAuth;
	}

}
