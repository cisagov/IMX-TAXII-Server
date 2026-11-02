/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.a1;

import java.io.IOException;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.glassfish.jersey.media.multipart.FormDataMultiPart;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.UriInfo;

@Singleton
@Path("A1")
public class A1Endpoint {

	@Context
	private UriInfo uriInfo;

	private A1ClientBase client;
	private JsonNode error;
	private Logger logger = LogManager.getLogger(A1Endpoint.class);

	@Inject
	public A1Endpoint() throws IOException {
		super();
		try {
			this.client = new A1ClientBase();
		} catch (Exception e) {
			error = JSON.toJsonNode(new Error(e));
			logger.log(Level.WARN, "A1Endpoint<init>", e);
		}
	}

	@GET
	@Path("{path:.+}")
	@Produces(MediaType.APPLICATION_JSON)
	public JsonNode get(@PathParam("path") String path) {
		return (client != null) ? client.getHelper(JsonNode.class, uriInfo.getQueryParameters(), path) : error;
	}

	@POST
	@Path("{path:.+}")
	@Consumes(MediaType.MULTIPART_FORM_DATA)
	@Produces(MediaType.APPLICATION_JSON)
	public JsonNode multiPart(@PathParam("path") String path, FormDataMultiPart multiPart) {
		return (client != null) ? client.postHelper(Entity.entity(multiPart, multiPart.getMediaType()), JsonNode.class,
				uriInfo.getQueryParameters(), path) : error;
	}

	@POST
	@Path("sensors/{id}/taskings/approveAllAndUpdate")
	@Produces(MediaType.APPLICATION_JSON)
	public JsonNode noEntity(@PathParam("id") String id) {
		return (client != null) ? client.postHelper(null, JsonNode.class, uriInfo.getQueryParameters(), "sensors", id,
				"taskings", "approveAllAndUpdate") : error;
	}

	@POST
	@Path("objects/stix/{reportingSourceId}")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public JsonNode jsonEntity(@PathParam("reportingSourceId") String reportingSourceId, String stix) {
		return (client != null) ? client.postHelper(Entity.json(stix), JsonNode.class, uriInfo.getQueryParameters(),
				"objects", "stix", reportingSourceId) : error;
	}

}
