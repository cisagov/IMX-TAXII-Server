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

import com.cisa.cti4j2.Timestamp;

import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("taxii")
public class LegacyClientEndpoint {

	@GET
	@Path("readTimeout")
	@Produces(MediaType.APPLICATION_JSON)
	public int getReadTimeout() {
		try {
			return TAXIIClient.instance().getReadTimeout();
		} catch (NullPointerException e) {
			throw new NotFoundException();
		}
	}

	@GET
	@Path("connectTimeout")
	@Produces(MediaType.APPLICATION_JSON)
	public int getConnectTimeout() {
		try {
			return TAXIIClient.instance().getConnectTimeout();
		} catch (NullPointerException e) {
			throw new NotFoundException();
		}
	}

	@POST
	@Path("connectTimeout")
	@Produces(MediaType.APPLICATION_JSON)
	public int setConnectTimeout(int value) {
		try {
			return TAXIIClient.instance().setConnectTimeout(value);
		} catch (NullPointerException e) {
			throw new NotFoundException();
		}
	}

	@POST
	@Path("readTimeout")
	@Produces(MediaType.APPLICATION_JSON)
	public int setReadTimeout(int value) {
		try {
			return TAXIIClient.instance().setReadTimeout(value);
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

	@GET
	@Path("health")
	@Produces(MediaType.APPLICATION_JSON)
//	@Logged
	public Response getHealth(@DefaultValue("") @QueryParam("end") String end,
			@DefaultValue("") @QueryParam("amount") String amount, @DefaultValue("") @QueryParam("unit") String unit) {
		return helper(TAXIIClient.instance(), end, amount, unit);
	}

}
