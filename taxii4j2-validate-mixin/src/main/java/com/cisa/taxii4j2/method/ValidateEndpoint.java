/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;

@Singleton
@Path("admin/v1.0")
public class ValidateEndpoint {

	public static final Logger logger = LogManager.getLogger(ValidateEndpoint.class);

	private final STIXValidator validator;

	@Inject
	public ValidateEndpoint(STIXValidator validator) {
		super();
		this.validator = validator;
	}

	@GET
	@Path("schema/update")
	public Response update() {
		logger.info("Refreshed schema validator; path=[taxii]/admin/v1.0/schema/update");
		try {
			validator.update();
		} catch (IOException e) {
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
		}
		return Response.ok().build();
	}

}
