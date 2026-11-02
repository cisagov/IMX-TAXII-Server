/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.logging;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import org.apache.logging.log4j.core.util.IOUtils;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.Timestamp;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;

@JsonInclude(Include.NON_NULL)
public class LogEntry {

	public static final String event_idKey = "event_id";
	public static final String timestampKey = "timestamp";
	public static final String payloadKey = "payload";
	public static final String headersKey = "headers";
	public static final String typeKey = "type";

	@JsonProperty(event_idKey)
	private final int event_id;

	@JsonProperty(timestampKey)
	private final Timestamp timestamp;

	@JsonProperty(payloadKey)
	private String payload;

	@JsonProperty(typeKey)
	private final LogEntryType type;

	@JsonCreator
	public LogEntry(@JsonProperty(value = event_idKey, required = true) int event_id,
			@JsonProperty(value = timestampKey, required = true) Timestamp timestamp,
			@JsonProperty(value = payloadKey, required = true) String payload,
			@JsonProperty(value = typeKey, required = true) LogEntryType type) {
		super();
		this.event_id = event_id;
		this.timestamp = timestamp;
		this.payload = payload;
		this.type = type;
	}

	protected LogEntry(int event_id, ContainerRequestContext requestContext) throws IOException {
		super();
		this.event_id = event_id;
		timestamp = new Timestamp();
		payload = IOUtils.toString(new InputStreamReader(requestContext.getEntityStream()));
		requestContext.setEntityStream(new ByteArrayInputStream(payload.getBytes()));
		type = LogEntryType.REQUEST;

	}

	protected LogEntry(ContainerRequestContext requestContext, ContainerResponseContext responseContext)
			throws IOException {
		super();
		event_id = Integer.valueOf(requestContext.getHeaders().getFirst(event_idKey));
		timestamp = new Timestamp();
		Object entity = responseContext.getEntity();
		payload = (entity != null) ? JSON.writeValueAsString(entity) : null;
		type = LogEntryType.RESPONSE;
	}

	public int getEvent_id() {
		return event_id;
	}

	public Timestamp getTimestamp() {
		return timestamp;
	}

	public String getPayload() {
		return payload;
	}

	public LogEntryType getType() {
		return type;
	}

}
