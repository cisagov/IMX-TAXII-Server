/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.response;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.data.impl.CustomFields;

@JsonInclude(Include.NON_NULL)
public class TAXIIResponseFed<T extends CustomFields> extends TAXIIResponse<T> {

	protected static final String fedKey = "fed";

	@JsonProperty(fedKey)
	public final Map<String, TAXIIResponse<T>> fed;

	@Override
	public Object getEntity() {
		Object entity = super.getEntity();
		return (entity != null) ? entity : fed;
	}

	protected TAXIIResponseFed(Error error, T ok, Map<String, TAXIIResponse<T>> fed) {
		super(error, ok);
		this.fed = fed;
	}

	public TAXIIResponseFed(Error error) {
		super(error, null);
		this.fed = null;
	}

	public TAXIIResponseFed(T ok) {
		super(null, ok);
		this.fed = null;
	}

	public TAXIIResponseFed(Map<String, TAXIIResponse<T>> results) {
		super(null, null);
		this.fed = results;
	}

	@Override
	public String toString() {
		return JSON.convertValue(this, JsonNode.class).toPrettyString();
	}

}
