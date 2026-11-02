/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.cti4j2;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

/**
 * Nanosecond resolution using {@link Instant}.
 * HOWEVER...{@link Instant#toString()} is overridden to ALWAYS have 9 digit
 * resolution so that lexicographic comparison is guaranteed to work. The
 * default date time formatter for instants only includes 3, 6, or 9 digit
 * resolution as necessary. Bad juju.
 */
@JsonSerialize(using = Timestamp.Serializer.class)
@JsonDeserialize(using = Timestamp.Deserializer.class)
public class Timestamp implements Comparable<Timestamp> {

	public final Instant instant;

	@JsonIgnore
	public static final Timestamp epoch = new Timestamp(Instant.EPOCH);

	@JsonIgnore
	public static final DateTimeFormatter dtf = new DateTimeFormatterBuilder().appendInstant(6).toFormatter();

	public Timestamp() {
		this(Instant.now());
	}

	public static Timestamp now() {
		return new Timestamp();
	}

	public Timestamp(Instant instant) {
		super();
		this.instant = instant;
	}

	@Override
	public String toString() {
		return dtf.format(instant);
	}

	/**
	 * Even though {@link #toString()} ALWAYS has 9 digit resolution, incoming
	 * values (e.g. from STIX bundles) may not. So we DO NOT use our strict date
	 * time format for incoming conversion and rely on default
	 * {@link Instant#parse(CharSequence)}.
	 *
	 * @param s
	 * @return
	 */
	public static Timestamp valueOf(String s) {
		return new Timestamp(Instant.parse(s));
	}

	public static Timestamp valueOf(double v) {
		long seconds = (long) v;
		return new Timestamp(Instant.ofEpochSecond(seconds, (long) ((v - seconds) * 1.0e9)));
	}

	public static String normalize(String s) {
		return Timestamp.valueOf(s).toString();
	}

	public double seconds() {
		return instant.getEpochSecond() + instant.getNano() / 1.0e9;
	}

	public static class Serializer extends StdSerializer<Timestamp> {

		private static final long serialVersionUID = 1L;

		public Serializer() {
			super(Timestamp.class);
		}

		@Override
		public void serialize(Timestamp value, JsonGenerator gen, SerializerProvider provider) throws IOException {
			gen.writeString(value.toString());
		}

	}

	public static class Deserializer extends StdDeserializer<Timestamp> {

		private static final long serialVersionUID = 1L;

		public Deserializer() {
			super(Timestamp.class);
		}

		@Override
		public Timestamp deserialize(JsonParser p, DeserializationContext ctxt)
				throws IOException, JsonProcessingException {
			return valueOf(p.getText());
		}

	}

	@Override
	public int compareTo(Timestamp arg0) {
		return instant.compareTo(arg0.instant);
	}

	public Timestamp minus(CTIDuration duration) {
		return new Timestamp(instant.minus(duration.duration));
	}

	public Timestamp plus(CTIDuration duration) {
		return new Timestamp(instant.plus(duration.duration));
	}

}
