/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jvnet.hk2.annotations.Contract;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.cisa.taxii4j2.auth.data.Lenient;
import com.cisa.taxii4j2.data.impl.STIXObject;

@Contract
public interface STIXValidator extends AutoCloseable {

	public static final Logger logger = LogManager.getLogger(STIXValidator.class);

	public static final String prefix = "stixValidator";

	public static class Error {

		public String id;
		public String message;

		public Error() {
			super();
		}

		public Error(String id, String message) {
			super();
			this.id = id;
			this.message = message;
		}

	}

	@JsonSerialize(using = STIXValidator.Serializer.class)
	@JsonDeserialize(using = STIXValidator.Deserializer.class)
	public static class Result {

		public List<Error> errors;
		public boolean is_valid;
		public JsonNode source;

		public Result() {
			super();
		}

		public Result(List<Error> errors, boolean is_valid, JsonNode source) {
			super();
			this.errors = errors;
			this.is_valid = is_valid;
			this.source = source;
		}

		@JsonIgnore
		public String prettyErrors() {
			Map<String, List<String>> sorted = new HashMap<>();
			for (Error error : errors) {
				sorted.computeIfAbsent(error.id, id -> new ArrayList<>()).add(error.message);
			}
			StringBuilder s = new StringBuilder();
			sorted.forEach((k, vs) -> {
				s.append(k);
				s.append('\n');
				vs.forEach(v -> {
					s.append('\t');
					s.append(v);
					s.append('\n');
				});
			});
			return s.toString();
		}

	}

	public static class Serializer extends StdSerializer<Result> {

		private static final long serialVersionUID = 1L;

		public Serializer() {
			super(Result.class);
		}

		@Override
		public void serialize(Result value, JsonGenerator gen, SerializerProvider provider) throws IOException {
			gen.writeStartObject();
			gen.writeArrayFieldStart("errors");
			for (Error error : value.errors) {
				gen.writeObject(error);
			}
			gen.writeEndArray();
			gen.writeBooleanField("is_valid", value.is_valid);
			gen.writeObjectField("source", value.source);
			gen.writeEndObject();
		}
	}

	public static final ObjectMapper om = new ObjectMapper();

	public static class Deserializer extends StdDeserializer<Result> {

		private static final long serialVersionUID = 1L;

		public Deserializer() {
			super(Result.class);
		}

		@Override
		public Result deserialize(JsonParser p, DeserializationContext ctxt)
				throws IOException, JsonProcessingException {
			Result result = new Result();
			JsonNode root = p.readValueAsTree();
			result.errors = new ArrayList<>();
			Iterator<JsonNode> iError = root.withArray("errors").iterator();
			while (iError.hasNext()) {
				result.errors.add(om.convertValue(iError.next(), Error.class));
			}
			// Add the warnings also
			// If we are not doing strict validation, we still want to see the messages.
			Iterator<JsonNode> iWarn = root.withArray("warnings").iterator();
			while (iWarn.hasNext()) {
				result.errors.add(om.convertValue(iWarn.next(), Error.class));
			}
			result.is_valid = root.get("is_valid").asBoolean();
			result.source = root.get("source");
			return result;
		}
	}

	public Result validate(STIXObject o, Options options);

	@Override
	default void close() throws Exception {

	}

	@JsonInclude(Include.NON_NULL)
	public static class Options {

		private static final String strictKey = "strict";
		private static final String strict_typesKey = "strict_types";
		private static final String strict_propertiesKey = "strict_properties";
		private static final String schema_dirKey = "schema_dir";

		@JsonProperty(strictKey)
		private final Boolean strict;

		@JsonProperty(strict_typesKey)
		private final Boolean strict_types;

		@JsonProperty(strict_propertiesKey)
		private final Boolean strict_properties;

		@JsonProperty(schema_dirKey)
		private final String schema_dir;

		public Options(@JsonProperty(value = strictKey, required = false) Boolean strict,
				@JsonProperty(value = strict_typesKey, required = false) Boolean strict_types,
				@JsonProperty(value = strict_propertiesKey, required = false) Boolean strict_properties,
				@JsonProperty(value = schema_dirKey, required = false) String schema_dir) {
			super();
			this.strict = ((strict != null) && strict) ? true : null;
			this.strict_types = ((strict_types != null) && strict_types) ? true : null;
			this.strict_properties = ((strict_properties != null) && strict_properties) ? true : null;
			this.schema_dir = schema_dir;
		}

		private static final String dirKey = "SCHEMA_DIR";
		private static final String defaultDir = "/opt/schema";

		public Boolean getStrict() {
			return strict;
		}

		public Boolean getStrict_types() {
			return strict_types;
		}

		public Boolean getStrict_properties() {
			return strict_properties;
		}

		public String getSchema_dir() {
			return schema_dir;
		}

		@JsonIgnore
		public boolean isStrict() {
			return (strict != null) ? strict : false;
		}

		@JsonIgnore
		public boolean isStrict_types() {
			return (strict_types != null) ? strict_types : false;
		}

		@JsonIgnore
		public boolean isStrict_properties() {
			return (strict_properties != null) ? strict_properties : false;
		}

	}

	public int configure(Options config);

	public static Options optionsFactory(Set<Lenient> lenients) {
		String schema_dir = System.getenv().containsKey(Options.dirKey) ? System.getenv(Options.dirKey)
				: Options.defaultDir;
		if (lenients == null) {
			return new Options(false, true, true, schema_dir);
		}
		if (lenients.contains(Lenient.factory("DONT_EXTENSION_VALIDATE"))) {
			schema_dir = null;
		}
		boolean strict_types = !lenients.contains(Lenient.factory("DONT_CHECK_CUSTOM_OBJECTS"));
		boolean strict_properties = !lenients.contains(Lenient.factory("DONT_CHECK_CUSTOM_PROPERTIES"));
		// Strict was defaulting to false, concerned that allowing it to be true might cause unwanted failures. EOS-5664
		//boolean strict = !((strict_types && lenients.contains(Lenient.factory("DONT_FAIL_CUSTOM_OBJECTS")))
		//		|| (strict_properties && lenients.contains(Lenient.factory("DONT_FAIL_CUSTOM_PROPERTIES"))));

		// Followup: this did cause the taxii server to reject more than it should, since it was also enforcing all of the
		// SHOULD requirements in the specification. Setting back to always false for now, may need to address again later.
		boolean strict = false;
		return new Options(strict, strict_types, strict_properties, schema_dir);
	}

	public void update() throws IOException;

}
