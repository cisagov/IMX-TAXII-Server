/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data.impl;

import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;

@JsonInclude(Include.NON_NULL)
public class CustomFields {

	public static final String customPrefix = "x_";

	private Map<String, Object> fields = new HashMap<>();

	public CustomFields(String className) {
		super();
	}

	public CustomFields(Class<?> clazz) {
		this(clazz.getName());
	}

	@JsonAnyGetter
	public Map<String, Object> getFields() {
		return fields;
	}

	@JsonIgnore
	public Object getField(String key) {
		return fields.get(key);
	}

	@JsonAnySetter
	public void setField(String key, Object value) {
		if(!key.startsWith(customPrefix)) {
			throw new IllegalArgumentException();
		}
		fields.put(key, value);
	}

	@Override
	public String toString() {
		return JSON.convertValue(this, JsonNode.class).toPrettyString();
	}

}
