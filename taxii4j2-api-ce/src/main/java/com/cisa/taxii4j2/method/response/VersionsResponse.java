/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.response;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.data.Versions;

public class VersionsResponse extends TAXIIResponseFed<Versions> {

	@JsonCreator
	public VersionsResponse(@JsonProperty(value = errorKey, required = false) Error error,
			@JsonProperty(value = okKey, required = false) Versions ok,
			@JsonProperty(value = fedKey, required = false) Map<String, TAXIIResponse<Versions>> fed
			) {
		super(error, ok, fed);
	}

	public VersionsResponse(Error error) {
		super(error);
	}

	public VersionsResponse(Versions ok) {
		super(ok);
	}

	public VersionsResponse(Map<String, TAXIIResponse<Versions>> fed) {
		super(fed);
	}

	public static VersionsResponse valueOf(String json) {
		return new VersionsResponse(readValue(json, Error.class), readValue(json, Versions.class), null);
	}

}
