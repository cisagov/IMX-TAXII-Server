/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.UUID;

import com.cisa.cti4j2.Timestamp;

import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@Path("admin/v1.0/client")
public class ClientEndpoint {

	public static final Logger logger = LogManager.getLogger(ClientEndpoint.class);

	@GET
	@Path("list")
	@Produces(MediaType.APPLICATION_JSON)
	public Set<RemoteInfo> list() {
		return TAXIIClient.list();
	}

	// @Operation(description = "get read timeout setting for api-root")
	@GET
	@Path("{uuid}/readTimeout")
	@Produces(MediaType.APPLICATION_JSON)
	public int getReadTimeout(@PathParam("uuid") UUID uuid) {
		logger.info("Retrieved read timeout setting for api root; path=[taxii]/admin/v1.0/client/" + uuid + "/readTimeout");
		try {
			return TAXIIClient.instance(uuid).getReadTimeout();
		} catch (NullPointerException e) {
			throw new NotFoundException();
		}
	}

	// @Operation(description = "get connect timeout setting for api-root")
	@GET
	@Path("{uuid}/connectTimeout")
	@Produces(MediaType.APPLICATION_JSON)
	public int getConnectTimeout(@PathParam("uuid") UUID uuid) {
		logger.info("Retrieved connect timeout setting for api root; path=[taxii]/admin/v1.0/client/" + uuid + "/connectTimeout");
		try {
			return TAXIIClient.instance(uuid).getConnectTimeout();
		} catch (NullPointerException e) {
			throw new NotFoundException();
		}
	}

	// @Operation(description = "set connect timeout setting for api-root")
	@POST
	@Path("{uuid}/connectTimeout")
	@Produces(MediaType.APPLICATION_JSON)
	public int setConnectTimeout(@PathParam("uuid") UUID uuid, int value) {
		logger.info("Set connect timeout setting for api root; path=[taxii]/admin/v1.0/client/" + uuid + "/connectTimeout; input=" + value);
		try {
			return TAXIIClient.instance(uuid).setConnectTimeout(value);
		} catch (NullPointerException e) {
			throw new NotFoundException();
		}
	}

	// @Operation(description = "set read timeout setting for api-root")
	@POST
	@Path("{uuid}/readTimeout")
	@Produces(MediaType.APPLICATION_JSON)
	public int setReadTimeout(@PathParam("uuid") UUID uuid, int value) {
		logger.info("Set read timeout setting for api root; path=[taxii]/admin/v1.0/client/" + uuid + "/readTimeout; input=" + value);
		try {
			return TAXIIClient.instance(uuid).setReadTimeout(value);
		} catch (NullPointerException e) {
			throw new NotFoundException();
		}
	}

	private static final int defaultHealthHours = 4;

	protected static Response helper(TAXIIClient taxii, String end, String amount, String unit) {
		Timestamp _end = end.isEmpty() ? new Timestamp() : Timestamp.valueOf(end);
		int _amount = amount.isEmpty() ? defaultHealthHours : Integer.valueOf(amount);
		ChronoUnit _unit = unit.isEmpty() ? ChronoUnit.HOURS : ChronoUnit.valueOf(unit);
		return Response.ok().entity(taxii.getHealth(_end.instant, Duration.of(_amount, _unit))).build();
	}

	// @Operation(description = "get health info for api-root")
	@GET
	@Path("{uuid}/health")
	@Produces(MediaType.APPLICATION_JSON)
//	@Logged
	public Response getHealth(@PathParam("uuid") UUID uuid, @DefaultValue("") @QueryParam("end") String end,
			@DefaultValue("") @QueryParam("amount") String amount, @DefaultValue("") @QueryParam("unit") String unit) {
		logger.info("Retrieved health info for api root; path=[taxii]/admin/v1.0/client/health");
		return helper(TAXIIClient.instance(uuid), end, amount, unit);
	}

}
