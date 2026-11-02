/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.cti4j2;

import java.io.IOException;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

public class JSON {

	@JsonSerialize(using = Integer.Serializer.class)
	@JsonDeserialize(using = Integer.Deserializer.class)
	public static class Integer extends Number {

		private static final long serialVersionUID = 1L;

		public static final long MAX_VALUE = (1L << 53) - 1;
		public static final long MIN_VALUE = -(1L << 53) + 1;

		private static long value(long value) {
			if ((value < MIN_VALUE) || (value > MAX_VALUE)) {
				throw new IllegalArgumentException("invalid I-JSON integer");
			}
			return value;
		}

		private final long value;

		public static Integer valueOf(String s) {
			return valueOf(Long.valueOf(s));
		}

		public static Integer valueOf(long l) {
			return new Integer(l);
		}

		public Integer(long value) {
			super();
			this.value = value(value);
		}

		public long getValue() {
			return value;
		}

		public static class Serializer extends StdSerializer<Integer> {

			private static final long serialVersionUID = 1L;

			public Serializer() {
				super(Integer.class);
			}

			@Override
			public void serialize(Integer value, JsonGenerator gen, SerializerProvider provider) throws IOException {
				gen.writeNumber(value.getValue());
			}

		}

		public static class Deserializer extends StdDeserializer<Integer> {

			private static final long serialVersionUID = 1L;

			public Deserializer() {
				super(Integer.class);
			}

			@Override
			public Integer deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
				return Integer.valueOf(p.getLongValue());
			}

		}

		@Override
		public double doubleValue() {
			return Double.valueOf(value).doubleValue();
		}

		@Override
		public float floatValue() {
			return Float.valueOf(value).floatValue();
		}

		@Override
		public int intValue() {
			return Integer.valueOf(value).intValue();
		}

		@Override
		public long longValue() {
			return value;
		}

	}

	public static JsonNodeFactory factory = new JsonNodeFactory() {

		private static final long serialVersionUID = 1L;

		@Override
		public ObjectNode objectNode() {
			return new ObjectNode(this, new TreeMap<String, JsonNode>());
		}

	};

	private static final ObjectMapper objectMapper = JsonMapper.builder().nodeFactory(factory).build();
//			new ObjectMapper();

	public static String writeValueAsString(Object value) throws IOException {
		return objectMapper.writeValueAsString(value);
	}

	public static JsonNode toJsonNode(Object item) {
		return objectMapper.convertValue(item, JsonNode.class);
	}

	public static void writeTree(Writer out, JsonNode rootNode) throws IOException {
		objectMapper.writeTree(objectMapper.createGenerator(out), rootNode);
	}

	public static String writeTreeAsString(JsonNode rootNode) throws IOException {
		StringWriter out = new StringWriter();
		objectMapper.writeTree(objectMapper.createGenerator(out), rootNode);
		return out.toString();
	}

	public static <T> T readValue(String json, Class<T> clazz) throws IOException {
		return objectMapper.reader().with(StreamReadFeature.STRICT_DUPLICATE_DETECTION).readValue(json, clazz);
	}

	public static <T> T readValue(Reader in, Class<T> clazz) throws IOException {
		return objectMapper.reader().with(StreamReadFeature.STRICT_DUPLICATE_DETECTION).readValue(in, clazz);
	}

	public static JsonNode readTree(Reader in) throws IOException {
		return objectMapper.reader().with(StreamReadFeature.STRICT_DUPLICATE_DETECTION).readTree(in);
	}

	public static JsonNode readTree(String in) throws IOException {
		return objectMapper.reader().with(StreamReadFeature.STRICT_DUPLICATE_DETECTION).readTree(in);
	}

	public static <T> T readValue(JsonNode node, Class<T> clazz) throws IOException {
		return objectMapper.reader().with(StreamReadFeature.STRICT_DUPLICATE_DETECTION).readValue(node.toString(),
				clazz); // node.traverse(), clazz);
	}

	public static <T> T convertValue(Object root, Class<T> clazz) {
		return objectMapper.convertValue(root, clazz);
	}

	public static JsonNode subsumes(JsonNode bigger, JsonNode smaller) {
		if (!bigger.isObject() || !smaller.isObject()) {
			return null;
		}
		ArrayNode errors = subsumes(bigger, smaller, factory.arrayNode());
		ObjectNode result = factory.objectNode().set("errors", errors);
		result.set("is_valid", factory.booleanNode(errors.isEmpty()));
		return result;
	}

	public static ArrayNode subsumes(JsonNode bigger, JsonNode smaller, ArrayNode errors) {
		Iterator<Map.Entry<String, JsonNode>> iField = smaller.fields();
		while (iField.hasNext()) {
			Map.Entry<String, JsonNode> field = iField.next();
			String fieldName = field.getKey();
			JsonNode biggerNode = bigger.get(fieldName);
			if (biggerNode != null) {
				subsumes(biggerNode, field.getValue(), errors, fieldName);
			} else {
				errors.add(String.format("subsumer missing field \"%s\"", fieldName));
			}
		}
		return errors;
	}

	public static ArrayNode subsumes(JsonNode bigger, JsonNode smaller, ArrayNode errors, String fieldName) {
		JsonNodeType type = bigger.getNodeType();
		if (type == smaller.getNodeType()) {
			switch (type) {
			case ARRAY:
				if (bigger.size() == smaller.size()) {
					Iterator<JsonNode> iBig = bigger.iterator();
					Iterator<JsonNode> iSmall = smaller.iterator();
					while (iBig.hasNext()) {
						subsumes(iBig.next(), iSmall.next(), errors, fieldName);
					}
				} else {
					errors.add(String.format("\"%s\": ARRAY size conflict: %d != %d", fieldName, bigger.size(),
							smaller.size()));
				}
				break;
			case BINARY:
				try {
					if (Arrays.compare(bigger.binaryValue(), smaller.binaryValue()) != 0) {
						errors.add(String.format("\"%s\": BINARY value conflict", fieldName));
					}
				} catch (IOException e) {
					errors.add(String.format("\"%s\": BINARY value exception: %s", fieldName, e.getMessage()));
				}
				break;
			case BOOLEAN:
				if (bigger.asBoolean() != smaller.asBoolean()) {
					errors.add(String.format("\"%s\": BOOLEAN value conflict: %s != %s", fieldName, bigger.asBoolean(),
							smaller.asBoolean()));
				}
				break;
			case MISSING:
				break;
			case NULL:
				break;
			case NUMBER:
				if (!bigger.numberValue().equals(smaller.numberValue())) {
					errors.add(String.format("\"%s\": NUMBER value conflict: %s != %s", fieldName, bigger.numberValue(),
							smaller.numberValue()));
				}
				break;
			case OBJECT:
				subsumes(bigger, smaller, errors);
				break;
			case POJO:
				break;
			case STRING:
				if (!bigger.asText().equals(smaller.asText())) {
					errors.add(String.format("\"%s\": STRING value conflict: %s != %s", fieldName, bigger.asText(),
							smaller.asText()));
				}
				break;
			default:
				break;
			}
		} else {
			errors.add(String.format("node type conflict: %s != %s", type, smaller.getNodeType()));
		}
		return errors;
	}

//	public static JsonNode readTree(URL url) throws IOException {
//		return objectMapper.readTree(url);
//	}

}
