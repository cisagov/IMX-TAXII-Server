/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.response;


import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.taxii4j2.data.Collections;
import com.cisa.taxii4j2.data.Error;

public class CollectionsResponse extends TAXIIResponse<Collections> {

	@JsonCreator
	public CollectionsResponse(@JsonProperty(value = errorKey, required = false) Error error,
			@JsonProperty(value = okKey, required = false) Collections ok) {
		super(error, ok);
	}

	public CollectionsResponse(Collections ok) {
		super(ok);
	}

	public CollectionsResponse(Error error) {
		super(error);
	}

	public static CollectionsResponse valueOf(String json) {
		return new CollectionsResponse(readValue(json, Error.class), readValue(json, Collections.class));
	}

}
