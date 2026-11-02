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
import com.cisa.taxii4j2.data.Collections.Collection;
import com.cisa.taxii4j2.data.Error;

public class CollectionResponse extends TAXIIResponse<Collection> {

	@JsonCreator
	public CollectionResponse(@JsonProperty(value = errorKey, required = false) Error error,
			@JsonProperty(value = okKey, required = false) Collection ok) {
		super(error, ok);
	}

	public CollectionResponse(Collection ok) {
		super(ok);
	}

	public CollectionResponse(Error error) {
		super(error);
	}

	public static CollectionResponse valueOf(String json) {
		return new CollectionResponse(readValue(json, Error.class), readValue(json, Collection.class));
	}

}
