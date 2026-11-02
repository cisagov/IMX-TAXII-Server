/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.data;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;

import org.reflections.Reflections;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

@JsonDeserialize(using = Lenient.Deserializer.class)
public interface Lenient {

	public static final Set<Class<? extends Lenient>> subTypes = new Reflections("com.cisa.taxii4j2")
			.getSubTypesOf(Lenient.class);

	public static Lenient factory(String value) {
		for (Class<? extends Lenient> clazz : subTypes) {
			try {
				Method method = clazz.getMethod("valueOf", String.class);
				try {
					return (Lenient) method.invoke(null, value);
				} catch (Exception e) {

				}
			} catch (NoSuchMethodException | SecurityException e) {
				// can't happen ?!?
			}
		}
		throw new IllegalArgumentException(String.format("%s is not a valid leniency", value));
	}

	public static Set<String> list() {
		Set<String> names = new TreeSet<>();
		for (Class<? extends Lenient> clazz : subTypes) {
			Arrays.stream(clazz.getEnumConstants()).forEach(e -> names.add(e.toString()));
		}
		return names;
	}

	public boolean test(Set<Lenient> lenients);

	public static class Deserializer extends StdDeserializer<Lenient> {

		private static final long serialVersionUID = 1L;

		public Deserializer() {
			super(Lenient.class);
		}

		@Override
		public Lenient deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
			return factory(p.getValueAsString());
		}

	}

}
