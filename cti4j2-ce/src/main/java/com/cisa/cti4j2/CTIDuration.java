/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.cti4j2;

import java.io.IOException;
import java.time.Duration;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

@JsonSerialize(using = CTIDuration.Serializer.class)
@JsonDeserialize(using = CTIDuration.Deserializer.class)
public class CTIDuration {

	public final Duration duration;

	public final static CTIDuration ZERO = valueOf(Duration.ZERO);
	public final static CTIDuration ONE_NANO = valueOf(Duration.ofNanos(1));

	public static final CTIDuration ONE_SECOND = valueOf(Duration.ofSeconds(1));

	private CTIDuration(Duration duration) {
		super();
		this.duration = duration;
	}

	public static CTIDuration ofSeconds(long seconds) {
		return valueOf(Duration.ofSeconds(seconds));
	}

	@Override
	public String toString() {
		return duration.toString();
	}

	public static CTIDuration valueOf(Duration duration) {
		return new CTIDuration(duration);
	}

	public static CTIDuration valueOf(String s) {
		return new CTIDuration(Duration.parse(s));
	}

	public static class Serializer extends StdSerializer<CTIDuration> {

		private static final long serialVersionUID = 1L;

		public Serializer() {
			super(CTIDuration.class);
		}

		@Override
		public void serialize(CTIDuration value, JsonGenerator gen, SerializerProvider provider) throws IOException {
			gen.writeString(value.toString());
		}
	}

	public static class Deserializer extends StdDeserializer<CTIDuration> {

		private static final long serialVersionUID = 1L;

		public Deserializer() {
			super(CTIDuration.class);
		}

		@Override
		public CTIDuration deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
			return valueOf(p.getText());
		}
	}

}
