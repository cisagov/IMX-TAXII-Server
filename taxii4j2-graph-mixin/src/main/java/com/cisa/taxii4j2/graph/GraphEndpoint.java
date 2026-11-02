/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.graph;

import java.util.Collections;

import com.cisa.taxii4j2.auth.method.RootCollectionAdmin;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.impl.JSONBundle;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.method.response.EnvelopeResponse;
import com.cisa.taxii4j2.servlet.EndpointUtils;
import com.cisa.taxii4j2.servlet.Logged;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Singleton
@Path("/ext/v1.0/")
public class GraphEndpoint {

	private final Graph search;
	private final RootCollectionAdmin rcAdmin;

	@Inject
	public GraphEndpoint(Graph search, RootCollectionAdmin rcAdmin) {
		super();
		this.search = search;
		this.rcAdmin = rcAdmin;
	}

	@Tag(name = "Object Graph")
	@Operation(description = "collect object graph as TAXII envelope")
	@GET
	@Path("{api-root:.+}/collections/{cId}/graph/{id}")
	@Logged
	public Response _graph(@PathParam("api-root") String fragment, @PathParam("cId") String cId,
			@PathParam("id") String id, @DefaultValue("3") @QueryParam("n") int n) {
		try {
			return EndpointUtils.builder(graph(fragment, resolve(cId), id, n)).build();
		} catch (WebApplicationException e) {
			return EndpointUtils.error(e);
		} catch (Exception e) {
			return EndpointUtils.error(e);
		}
	}

	@Tag(name = "Object Graph")
	@Operation(description = "collect object graph as STIX bundle")
	@GET
	@Path("{api-root:.+}/collections/{cId}/graphBundle/{id}")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public STIXObject _graphBundle(@PathParam("api-root") String fragment, @PathParam("cId") String cId,
			@PathParam("id") String id, @DefaultValue("3") @QueryParam("n") int n) {
		Envelope envelope = graph(fragment, resolve(cId), id, n).ok;
		return (envelope != null) ? new JSONBundle(envelope) : new JSONBundle(Collections.emptyList());
	}

	private String resolve(String cId) {
		return rcAdmin.readCollection(cId).getId();
	}

	private EnvelopeResponse graph(String fragment, String cId, String id, int n) {
		return search.graph(fragment, cId, id, n);
	}


}
