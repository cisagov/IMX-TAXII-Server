/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.SocketTimeoutException;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.cti4j2.Dictionary;
import com.cisa.taxii4j2.data.impl.CustomFields;

import jakarta.ws.rs.core.Response;

@JsonInclude(Include.NON_NULL)
public class Error extends CustomFields {

	private static final String titleKey = "title";
	private static final String descriptionKey = "description";
	private static final String error_idKey = "error_id";
	private static final String error_codeKey = "error_code";
	private static final String http_statusKey = "http_status";
	private static final String external_detailsKey = "external_details";
	private static final String detailsKey = "details";

	@JsonProperty(titleKey)
	private final String title;

	@JsonProperty(descriptionKey)
	private String description;

	@JsonProperty(error_idKey)
	private String error_id;

	@JsonProperty(error_codeKey)
	private String error_code;

	@JsonProperty(http_statusKey)
	private String http_status;

	@JsonProperty(external_detailsKey)
	private String external_details;

	@JsonProperty(detailsKey)
	private Dictionary details;

	public Error(String title, Response.Status status) {
		this(title, status.getStatusCode());
	}

	public Error(String title, Integer code) {
		this(title, null, null, null, code.toString(), null, null);
	}

	@JsonIgnore
	public int getStatusCode() {
		try {
			return Integer.valueOf(http_status);
		} catch(Exception e) {
			return Response.Status.INTERNAL_SERVER_ERROR.getStatusCode();
		}
	}

	/*
	 * these here to minimize bloat from adding an HTTP jar...
	 */
	private static final int SC_INTERNAL_SERVER_ERROR = 500;
	private static final int SC_REQUEST_TIMEOUT = 408;

	public Error(Exception e) {
		super(Error.class);
		title = e.getMessage();
		StringWriter s = new StringWriter();
		e.printStackTrace(new PrintWriter(s));
		description = s.toString();
		Integer http_status = SC_INTERNAL_SERVER_ERROR;
		if ((e instanceof SocketTimeoutException)
				|| ((e.getCause() != null) && (e.getCause() instanceof SocketTimeoutException))) {
			http_status = SC_REQUEST_TIMEOUT;
		}
		this.http_status = http_status.toString();
	}

	@JsonCreator
	public Error(@JsonProperty(value = titleKey, required = true) String title,
			@JsonProperty(value = descriptionKey, required = false) String description,
			@JsonProperty(value = error_idKey, required = false) String error_id,
			@JsonProperty(value = error_codeKey, required = false) String error_code,
			@JsonProperty(value = http_statusKey, required = false) String http_status,
			@JsonProperty(value = external_detailsKey, required = false) String external_details,
			@JsonProperty(value = detailsKey, required = false) Dictionary details) {
		super(Error.class);
		this.title = title;
		this.description = description;
		this.error_id = error_id;
		this.error_code = error_code;
		this.http_status = http_status;
		this.details = details;
	}

	public String getTitle() {
		return title;
	}

	public String getDescription() {
		return description;
	}

	public String getError_id() {
		return error_id;
	}

	public String getError_code() {
		return error_code;
	}

	public String getHttp_status() {
		return http_status;
	}

	public String getExternal_details() {
		return external_details;
	}

	public Dictionary getDetails() {
		return details;
	}
}
