/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.ext.method;

import java.net.URL;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.taxii4j2.servlet.Logged;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

@Path("ext/v1.0/schema")
public class SchemaEndpoint {

	private final SchemaRepo schemaRepo;

	@Inject
	public SchemaEndpoint(SchemaRepo schemaRepo) {
		super();
		this.schemaRepo = schemaRepo;
	}

	@POST
	@Path("{id}")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public URL putSchema(
			@PathParam("id") String id,
			JsonNode schema,
			@DefaultValue("true") @QueryParam("create") boolean create) {
		schemaRepo.putSchema(id, schema, create);
		return schemaRepo.url(id);
	}

	@GET
	@Path("{id}")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public JsonNode getSchema(
			@PathParam("id") String id) {
		return schemaRepo.getSchema(id);
	}

	@GET
	@Path("list")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public Map<String, JsonNode> listSchema() {
		return schemaRepo.listSchema();
	}

	@DELETE
	@Path("{id}")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public boolean deleteSchema(
			@PathParam("id") String id) {
		return schemaRepo.deleteSchema(id);
	}

}
