/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.cti4j2;

import java.io.IOException;
import java.util.HashMap;
import java.util.function.Function;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;

public class Dictionary extends HashMap<String, JsonNode> {

	private static final long serialVersionUID = 1L;

	public static Dictionary of(String key, JsonNode value) {
		Dictionary d = new Dictionary();
		d.put(key, value);
		return d;
	}

	private <T> T get(String key, Function<JsonNode, T> f) {
		JsonNode node = get(key);
		return (node != null) && !node.isNull() ? f.apply(node) : null;
	}

	public Boolean getBoolean(String key) {
		return get(key, n -> n.asBoolean());
	}

	public Double getDouble(String key) {
		return get(key, n -> n.asDouble());
	}

	public Integer getInt(String key) {
		return get(key, n -> n.asInt());
	}

	public Long getLong(String key) {
		return get(key, n -> n.asLong());
	}

	public String getText(String key) {
		return get(key, n -> n.asText());
	}

	public <T> T getObject(String key, Class<T> clazz) throws IOException {
		JsonNode node = get(key);
		return (node != null) ? JSON.readValue(node, clazz) : null;
	}

	private static final JsonNodeFactory factory = JSON.factory;

	private <T> JsonNode put(String key, T value, Function<T, JsonNode> f) {
		return put(key, (value != null) ? f.apply(value) : factory.nullNode());
	}

	public JsonNode put(String key, Boolean value) {
		return put(key, value, v -> factory.booleanNode(v));
	}

	public JsonNode put(String key, Double value) {
		return put(key, value, v -> factory.numberNode(v));
	}

	public JsonNode put(String key, Integer value) {
		return put(key, value, v -> factory.numberNode(v));
	}

	public JsonNode put(String key, Long value) {
		return put(key, value, v -> factory.numberNode(v));
	}

	public JsonNode put(String key, String value) {
		return put(key, value, v -> factory.textNode(v));
	}

	public JsonNode put(String key, Object value) {
		return put(key, JSON.convertValue(value, JsonNode.class));
	}

}
