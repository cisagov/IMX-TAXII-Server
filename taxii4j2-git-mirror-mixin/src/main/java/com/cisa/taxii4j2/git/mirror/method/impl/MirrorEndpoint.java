/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.mirror.method.impl;

import java.util.List;
import java.util.UUID;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.taxii4j2.auth.method.RootCollectionRead;
import com.cisa.taxii4j2.git.mirror.GitHubRepo;
import com.cisa.taxii4j2.git.mirror.GitHubRepos;
import com.cisa.taxii4j2.git.mirror.Mapping;
import com.cisa.taxii4j2.git.mirror.method.TAXIIMirror;
import com.cisa.taxii4j2.git.mirror.method.TAXIIMirror.MirrorState;
import com.cisa.taxii4j2.servlet.Logged;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@Path("/admin/v1.0")
public class MirrorEndpoint {

	public static final Logger logger = LogManager.getLogger(MirrorEndpoint.class);

	private final TAXIIMirror mirror;
	private final RootCollectionRead rcr;

	@Inject
	public MirrorEndpoint(TAXIIMirror mirror, RootCollectionRead rcr) {
		super();
		this.mirror = mirror;
		this.rcr = rcr;
	}

	@Operation(description = "create and import new Git mirror")
	@POST
	@Path("mirror")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public MirrorState mirrorCreate(GitHubRepo filter) {
		logger.info("Created and imported new Git mirror; path=[taxii]/admin/v1.0/mirror");
		return mirror.mirrorCreate(filter.normalize(rcr));
	}

	@Operation(description = "add and import a new mapping to an existing Git mirror")
	@POST
	@Path("mirror/{uuid}")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public MirrorState mirrorAdd(@PathParam("uuid") UUID uuid, Mapping mapping) {
		logger.info("Added and ipmorted new mapping for Git mirror; path=[taxii]/admin/v1.0/mirror/" + uuid + "; input=" + mapping);
		return mirror.mirrorAdd(uuid, mapping.normalize(rcr));
	}

	@Operation(description = "list Git mirrors")
	@GET
	@Path("mirrors")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public List<MirrorState> mirrorList() {
		logger.info("Retrieved list of Git mirrors; path=[taxii]/admin/v1.0/mirrors");
		return mirror.mirrorList();
	}

	@Operation(description = "fetch, import, and pull an existing Git mirror (bring all mappings up to date)")
	@GET
	@Path("mirror/{uuid}/update")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public MirrorState mirrorUpdate(@PathParam("uuid") UUID uuid) {
		logger.info("Brought Git mirror up to date (Git pull); path=[taxii]/admin/v1.0/mirror/" + uuid + "/update");
		return mirror.mirrorUpdate(uuid);
	}

	@Operation(description = "status an existing Git mirror")
	@GET
	@Path("mirror/{uuid}")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public MirrorState mirrorRead(@PathParam("uuid") UUID uuid) {
		logger.info("Retrieved status of Git mirror; path=[taxii]/admin/v1.0/mirror/" + uuid);
		return mirror.mirrorRead(uuid);
	}

	@Operation(description = "remove and purge objects for a mapping of an existing Git mirror")
	@DELETE
	@Path("mirror/{uuid}/{mUuid}")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public MirrorState mirrorRemove(@PathParam("uuid") UUID uuid, @PathParam("mUuid") UUID mUuid) {
		logger.info("Removed all objects for mapping of Git mirror; path=[taxii]/admin/v1.0/mirror/" + uuid + "/" + mUuid);
		return mirror.mirrorRemove(uuid, mUuid);
	}

	@Operation(description = "remove and purge objects for an existing Git mirror")
	@DELETE
	@Path("mirror/{uuid}")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public Response mirrorRemove(@PathParam("uuid") UUID uuid) {
		logger.info("Removed all objects for Git mirror; path=[taxii]/admin/v1.0/mirror/" + uuid);
		GitHubRepos.remove(uuid);
		return Response.ok().build();
	}

	@Operation(description = "get a cached schema by id")
	@GET
	@Path("mirror/schema/{id}")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public JsonNode mirrorSchema(@PathParam("id") String id) {
		logger.info("Retrieved cached schema; path=[taxii]/admin/v1.0/mirror/schema/" + id);
		return mirror.mirrorSchema(id);
	}

}
