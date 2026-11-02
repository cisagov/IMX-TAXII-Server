/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.logging;

import java.io.IOException;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.auth.data.TAXIICredentials;
import com.cisa.taxii4j2.auth.data.User;
import com.cisa.taxii4j2.auth.method.UserAdmin;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@JsonInclude(Include.NON_NULL)
public class RequestLogEntry extends LogEntry {

	public static final Logger logger = LogManager.getLogger(RequestLogEntry.class);

	public static final String methodKey = "method";
	public static final String pathKey = "path";
	private static final String query_parametersKey = "query_parameters";
	public static final String user_nameKey = "user_name";
	public static final String rolesKey = "roles";

	@JsonProperty(headersKey)
	@JsonDeserialize(as = MultivaluedHashMap.class)
	private final MultivaluedMap<String, String> headers;

	@JsonProperty(methodKey)
	private final String method;

	@JsonProperty(pathKey)
	private final String path;

	@JsonProperty(query_parametersKey)
	@JsonDeserialize(as = MultivaluedHashMap.class)
	private final MultivaluedMap<String, String> query_parameters;

	@JsonProperty(user_nameKey)
	private final String user_name;

	@JsonProperty(rolesKey)
	private final Set<String> roles;

	@JsonCreator
	public RequestLogEntry(@JsonProperty(value = event_idKey, required = true) int event_id,
			@JsonProperty(value = timestampKey, required = true) Timestamp timestamp,
			@JsonProperty(value = payloadKey, required = true) String payload,
			@JsonProperty(value = typeKey, required = true) LogEntryType type,
			@JsonProperty(value = headersKey, required = false) MultivaluedMap<String, String> headers,
			@JsonProperty(value = methodKey, required = true) String method,
			@JsonProperty(value = pathKey, required = true) String path,
			@JsonProperty(value = query_parametersKey, required = false) MultivaluedMap<String, String> query_parameters,
			@JsonProperty(value = user_nameKey, required = true) String user_name,
			@JsonProperty(value = rolesKey, required = false) Set<String> roles) {
		super(event_id, timestamp, payload, type);
		this.headers = headers;
		this.method = method;
		this.path = path;
		this.query_parameters = query_parameters;
		this.user_name = user_name;
		this.roles = roles;
	}

	public RequestLogEntry(int event_id, ContainerRequestContext requestContext, UserAdmin userAdmin)
			throws IOException {
		super(event_id, requestContext);
		headers = new MultivaluedHashMap<>(requestContext.getHeaders());
		requestContext.getHeaders().add(event_idKey, Integer.toString(getEvent_id()));
		method = requestContext.getMethod();
		UriInfo uriInfo = requestContext.getUriInfo();
		path = uriInfo.getPath();
		query_parameters = uriInfo.getQueryParameters();

		User user = TAXIICredentials.getUser(headers.getFirst(HttpHeaders.AUTHORIZATION));
		user_name = user.getUser();
		//logger.info("User connected to taxii server; username=" + user_name);
		roles = user.getRoles();

		logger.info(String.format("%s %s /%s%s Roles: %s", user_name, method, path,
				(uriInfo.getRequestUri().getQuery() != null) ? "?" + uriInfo.getRequestUri().getQuery() : "", roles.toString()));
	}

	public MultivaluedMap<String, String> getHeaders() {
		return headers;
	}

	public String getMethod() {
		return method;
	}

	public String getPath() {
		return path;
	}

	public MultivaluedMap<String, String> getQuery_parameters() {
		return query_parameters;
	}
}
