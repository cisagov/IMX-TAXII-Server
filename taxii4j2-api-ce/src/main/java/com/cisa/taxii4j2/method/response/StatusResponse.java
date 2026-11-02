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
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.data.Status;

public class StatusResponse extends TAXIIResponse<Status> {

	@JsonCreator
	public StatusResponse(@JsonProperty(value = errorKey, required = false) Error error,
			@JsonProperty(value = okKey, required = false) Status ok) {
		super(error, ok);
	}

	public StatusResponse(Status ok) {
		super(ok);
	}

	public StatusResponse(Error error) {
		super(error);
	}

	public static StatusResponse valueOf(String json) {
		return new StatusResponse(readValue(json, Error.class), readValue(json, Status.class));
	}


}
