/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job.remote;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.util.UUID;

import com.cisa.taxii4j2.client.admin.ClientJobAdmin;
import com.cisa.taxii4j2.client.job.misp.remote.MISPRemoteClientJob;
import com.cisa.taxii4j2.client.job.misp.remote.MISPRemoteConfiguration;
import com.cisa.taxii4j2.method.TAXII;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Singleton
@Path("/admin/v1.0/clientJob")
public class MISPClientJobEndpoint extends ClientJobEndpoint {

	@Inject
	public MISPClientJobEndpoint(ClientJobAdmin admin, TAXII taxii) {
		super(admin, taxii);
	}

	@POST
	@Path("misp")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	synchronized public Response create(MISPRemoteConfiguration configuration) {
		UUID uuid = configuration.getRemote().getUuid();
		if (jobs.containsKey(uuid)) {
			return Response.status(Response.Status.BAD_REQUEST).build();
		}
		try {
			jobs.put(uuid, new MISPRemoteClientJob(configuration, uriInfo.getBaseUri()));
		} catch (MalformedURLException e) {
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
		} catch (Exception e) {
			logger.fatal(e.getMessage());
			StringWriter s = new StringWriter();
			e.printStackTrace(new PrintWriter(s));
			return Response.status(Response.Status.BAD_REQUEST).encoding(MediaType.TEXT_PLAIN).entity(s.toString())
					.build();
		}
		return Response.ok(jobs.get(uuid).getConfiguration(), MediaType.APPLICATION_JSON).build();
	}


}
