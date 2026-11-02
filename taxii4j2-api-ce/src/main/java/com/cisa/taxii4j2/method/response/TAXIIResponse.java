/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.response;

import java.io.IOException;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.data.impl.CustomFields;

@JsonInclude(Include.NON_NULL)
@JsonSerialize(using = TAXIIResponse.Serializer.class)
public class TAXIIResponse<T extends CustomFields> {

	protected static final String errorKey = "error";
	protected static final String okKey = "ok";

	@JsonProperty(errorKey)
	public final Error error;

	@JsonProperty(okKey)
	public final T ok;

	@JsonIgnore
	public Object getEntity() {
		return (ok != null) ? ok : error;
	}

	protected TAXIIResponse(Error error, T ok) {
		super();
		this.error = (ok != null) ? null : error;
		this.ok = ok;
	}

	public TAXIIResponse(Error error) {
		this(error, null);
	}

	public TAXIIResponse(T ok) {
		this(null, ok);
	}

	@Override
	public String toString() {
		return JSON.convertValue(this, JsonNode.class).toPrettyString();
	}

	@SuppressWarnings("rawtypes")
	public static class Serializer extends StdSerializer<TAXIIResponse> {

		private static final long serialVersionUID = 1L;

		public Serializer() {
			super(TAXIIResponse.class);
		}

		@Override
		public void serialize(TAXIIResponse value, JsonGenerator gen, SerializerProvider provider) throws IOException {
			gen.writeObject(value.getEntity());
		}

	}

	public static <T> T readValue(String json, Class<T> clazz) {
		try {
			return JSON.readValue(json, clazz);
		} catch (Exception e) {
			return null;
		}
	}

}
