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
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Error;

public class EnvelopeResponse extends TAXIIResponseFed<Envelope> {

	@JsonCreator
	public EnvelopeResponse(@JsonProperty(value = errorKey, required = false) Error error,
			@JsonProperty(value = okKey, required = false) Envelope ok,
			@JsonProperty(value = fedKey, required = false) Map<String, TAXIIResponse<Envelope>> fed) {
		super(error, ok, fed);
	}

	public EnvelopeResponse(Envelope ok) {
		super(ok);
	}

	public EnvelopeResponse(Error error) {
		super(error);
	}

	public EnvelopeResponse(Map<String, TAXIIResponse<Envelope>> fed) {
		super(fed);
	}

	public static EnvelopeResponse valueOf(String json) {
		return new EnvelopeResponse(readValue(json, Error.class), readValue(json, Envelope.class), null);
	}

}
