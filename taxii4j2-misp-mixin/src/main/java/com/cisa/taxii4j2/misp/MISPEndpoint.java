/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.misp;

import java.net.MalformedURLException;

import com.fasterxml.jackson.databind.JsonNode;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Path("/admin/v1.0/misp")
public class MISPEndpoint {

	private final MISPClient client;

	@Inject
	public MISPEndpoint() throws MalformedURLException {
		super();
		this.client = new MISPClient();
	}

    @POST
    @Path("mispToStix")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public JsonNode mispToStix(JsonNode body) {
        return client.post(body, "events", "mispToStix", "2");
    }

    @POST
    @Path("stixToMisp")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public JsonNode stixToMisp(JsonNode body) {
        return client.post(body, "events", "stixToMisp", "2");
    }

	@POST
	@Path("upload_stix")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public JsonNode upload_stix(JsonNode body) {
		return client.post(body, "events", "upload_stix", "2");
	}

	@POST
	@Path("restSearch")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public JsonNode restSearch(JsonNode body) {
		return client.post(body, "events", "restSearch");
	}

	@POST
	@Path("add")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public JsonNode postMisp(JsonNode body) {
		return client.post(body, "events", "add");
	}

}
