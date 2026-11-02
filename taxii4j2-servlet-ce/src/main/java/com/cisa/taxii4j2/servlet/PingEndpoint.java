/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet;

import com.cisa.taxii4j2.method.TAXII;
import com.cisa.taxii4j2.method.response.DiscoveryResponse;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.UriInfo;

@Singleton
@Path("/ping")
public class PingEndpoint {

	@Context
	private UriInfo uriInfo;

	private final TAXII taxii;

	@Inject
	public PingEndpoint(TAXII taxii) {
		super();
		this.taxii = taxii;
	}

	@GET
	@Path("shallow")
	@Produces(MediaType.TEXT_PLAIN)
	public String shallow() {
		return "pong";
	}

	@GET
	@Path("deep")
	@Produces(MediaType.TEXT_PLAIN)
	public String deep() {
		StringBuffer s = new StringBuffer("pong...");
		boolean reachable = true;
		try {
			DiscoveryResponse dr = taxii.discover(uriInfo.getBaseUri());
			reachable = dr.ok != null;
		} catch (Exception e) {
			reachable = false;
		}
		s.append(reachable ? "reachable" : "UNREACHABLE");
		return s.toString();
	}

}
