/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet;

import java.util.function.Supplier;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.cisa.cti4j2.CTIMediaType;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.data.Discovery;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.data.impl.CustomFields;
import com.cisa.taxii4j2.data.impl.FirstLast;
import com.cisa.taxii4j2.method.response.TAXIIResponse;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

public class EndpointUtils {

	private static final Logger logger = LogManager.getLogger(EndpointUtils.class);

	public static <T extends CustomFields> Response.ResponseBuilder builder(TAXIIResponse<T> r) {
		if(r.error != null) {
			return builder(Integer.valueOf(r.error.getHttp_status()), r);
		}
		return builder(Response.Status.OK, r);
	}

	public static <T extends CustomFields> Response.ResponseBuilder builder(Response.Status status,
			TAXIIResponse<T> r) {
		return builder(status.getStatusCode(), r);
	}

	public static <T extends CustomFields> Response.ResponseBuilder builder(int status,
			TAXIIResponse<T> r) {
		Response.ResponseBuilder b = Response.status(status);
		b = b.entity(r.getEntity());
		return userAgent(b.type(CTIMediaType.TAXII2_1));
	}

	public static <T extends FirstLast> Response.ResponseBuilder flBuilder(TAXIIResponse<T> r) {
		Response.ResponseBuilder builder = builder(r);
		T ok = r.ok;
		if (ok != null) {
			Timestamp t = ok.getFirst();
			if (t != null) {
				builder.header(FirstLast.dateAddedFirst, t.toString());
				builder.header(FirstLast.expose, FirstLast.dateAddedFirst);
			}
			t = ok.getLast();
			if (t != null) {
				builder.header(FirstLast.dateAddedLast, t.toString());
				builder.header(FirstLast.expose, FirstLast.dateAddedLast);
			}
		}
		return builder;
	}

	public static Response error(WebApplicationException e) {
		return error(e, e.getResponse().getStatus());
	}

	public static Response error(Exception e) {
		return error(e, Response.Status.BAD_REQUEST.getStatusCode());
	}

	private static Response error(Exception e, Integer status) {
		logger.log(Level.INFO, "", e);
		return error(new Error(e.getMessage(), null, null, null, status.toString(), null, null), status);
	}

	public static Response error(Error error) {
		return error(error, Integer.valueOf(error.getHttp_status()));
	}

	private static Response.ResponseBuilder userAgent(Response.ResponseBuilder builder) {
		return builder.header("User-Agent", Discovery.getInstance().getTitle());
	}

	private static Response error(Error error, Integer status) {
		return userAgent(Response.status(status).entity(error).type(CTIMediaType.TAXII2_1)).build();
	}

	private static Response ok(Object entity) {
		return userAgent(Response.ok(entity, CTIMediaType.TAXII2_1)).build();
	}

	public static <T> Response response(Supplier<T> supplier) {
		try {
			return EndpointUtils.ok(supplier.get());
		} catch (WebApplicationException e) {
			return EndpointUtils.error(e);
		} catch (Exception e) {
			return EndpointUtils.error(e);
		}
	}

}
