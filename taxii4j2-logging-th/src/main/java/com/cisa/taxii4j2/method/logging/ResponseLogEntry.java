/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.logging;

import java.io.IOException;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.cisa.cti4j2.Timestamp;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

@JsonInclude(Include.NON_NULL)
public class ResponseLogEntry extends LogEntry {

	@JsonProperty(headersKey)
	@JsonDeserialize(as = MultivaluedHashMap.class)
	private final MultivaluedMap<String, Object> headers;

	@JsonCreator
	public ResponseLogEntry(@JsonProperty(value = event_idKey, required = true) int event_id,
			@JsonProperty(value = timestampKey, required = true) Timestamp timestamp,
			@JsonProperty(value = payloadKey, required = true) String payload,
			@JsonProperty(value = typeKey, required = true) LogEntryType type,
			@JsonProperty(value = headersKey, required = false) MultivaluedMap<String, Object> headers) {
		super(event_id, timestamp, payload, type);
		this.headers = headers;
	}

	public ResponseLogEntry(ContainerRequestContext requestContext, ContainerResponseContext responseContext)
			throws IOException {
		super(requestContext, responseContext);
		headers = new MultivaluedHashMap<>(responseContext.getHeaders());
	}

	public MultivaluedMap<String, Object> getHeaders() {
		return headers;
	}

}
