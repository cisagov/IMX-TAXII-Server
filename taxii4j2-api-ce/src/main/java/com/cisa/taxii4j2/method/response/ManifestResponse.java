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
import com.cisa.taxii4j2.data.Manifest;

public class ManifestResponse extends TAXIIResponseFed<Manifest> {

	@JsonCreator
	public ManifestResponse(@JsonProperty(value = errorKey, required = false) Error error,
			@JsonProperty(value = okKey, required = false) Manifest ok,
		@JsonProperty(value = fedKey, required = false) Map<String, TAXIIResponse<Manifest>> fed) {
		super(error, ok, fed);
	}

	public ManifestResponse(Manifest ok) {
		super(ok);
	}

	public ManifestResponse(Error error) {
		super(error);
	}

	public ManifestResponse(Map<String, TAXIIResponse<Manifest>> results) {
		super(results);
	}

	public static ManifestResponse valueOf(String json) {
		return new ManifestResponse(readValue(json, Error.class), readValue(json, Manifest.class), null);
	}

}
