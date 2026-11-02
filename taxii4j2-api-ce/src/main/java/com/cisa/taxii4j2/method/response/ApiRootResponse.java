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
import com.cisa.taxii4j2.data.ApiRoot;
import com.cisa.taxii4j2.data.Error;

public class ApiRootResponse extends TAXIIResponse<ApiRoot> {

	@JsonCreator
	public ApiRootResponse(@JsonProperty(value = errorKey, required = false) Error error,
			@JsonProperty(value = okKey, required = false) ApiRoot ok) {
		super(error, ok);
	}

	public ApiRootResponse(ApiRoot ok) {
		super(ok);
	}

	public ApiRootResponse(Error error) {
		super(error);
	}

	public static ApiRootResponse valueOf(String json) {
		return new ApiRootResponse(readValue(json, Error.class), readValue(json, ApiRoot.class));
	}

}
