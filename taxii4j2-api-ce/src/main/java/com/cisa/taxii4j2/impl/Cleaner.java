/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.impl;

import java.io.Reader;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.Map;
import java.util.function.UnaryOperator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.cisa.cti4j2.JSON;

public class Cleaner implements UnaryOperator<JsonNode> {

	public static class X_Objects implements UnaryOperator<JsonNode> {

		@Override
		public JsonNode apply(JsonNode root) {
			if (root.isObject()) {
				Iterator<JsonNode> iValue = root.elements();
				while (iValue.hasNext()) {
					apply(iValue.next());
				}
			} else if (root.isArray()) {
				Iterator<JsonNode> iElement = root.elements();
				while (iElement.hasNext()) {
					JsonNode element = iElement.next();
					if (element.isObject()) {
						JsonNode type = element.get("type");
						if ((type != null) && (type.asText().startsWith("x-"))) {
							iElement.remove();
							continue;
						}
					}
					apply(element);
				}
			}
			return root;
		}

	}

	public static class EmptyArrays implements UnaryOperator<JsonNode> {

		@Override
		public JsonNode apply(JsonNode root) {
			if (root.isObject()) {
				Iterator<Map.Entry<String, JsonNode>> iField = root.fields();
				while (iField.hasNext()) {
					Map.Entry<String, JsonNode> field = iField.next();
					JsonNode value = field.getValue();
					if ((value.isArray()) && value.isEmpty()) {
						iField.remove();
					} else {
						apply(value);
					}
				}
			} else if (root.isArray()) {
				Iterator<JsonNode> iElement = root.elements();
				while (iElement.hasNext()) {
					apply(iElement.next());
				}
			}
			return root;
		}

	}

	public static class X_Properties implements UnaryOperator<JsonNode> {

		@Override
		public JsonNode apply(JsonNode root) {
			if (root.isObject()) {
				Iterator<Map.Entry<String, JsonNode>> iField = root.fields();
				while (iField.hasNext()) {
					Map.Entry<String, JsonNode> field = iField.next();
					String key = field.getKey();
					if (key.startsWith("x_")) {
						iField.remove();
					} else {
						apply(field.getValue());
					}
				}
			} else if (root.isArray()) {
				Iterator<JsonNode> iElement = root.elements();
				while (iElement.hasNext()) {
					apply(iElement.next());
				}
			}
			return root;
		}

	}

	public static class EmptyObjects implements UnaryOperator<JsonNode> {

		@Override
		public JsonNode apply(JsonNode root) {
			if (root.isObject()) {
				Iterator<Map.Entry<String, JsonNode>> iField = root.fields();
				while (iField.hasNext()) {
					apply(iField.next().getValue());
				}
			} else if (root.isArray()) {
				Iterator<JsonNode> iElement = root.elements();
				while (iElement.hasNext()) {
					JsonNode element = iElement.next();
					if ((element.isObject()) && element.isEmpty()) {
						iElement.remove();
					} else {
						apply(element);
					}
				}
			}
			return root;
		}

	}

	public static class Trim implements UnaryOperator<JsonNode> {

		@Override
		public JsonNode apply(JsonNode root) {
			if (root.isObject()) {
				Iterator<Map.Entry<String, JsonNode>> iField = root.fields();
				while (iField.hasNext()) {
					Map.Entry<String, JsonNode> field = iField.next();
					JsonNode value = field.getValue();
					if (value.isTextual()) {
						ObjectNode.class.cast(root).put(field.getKey(), value.asText().trim());
					} else {
						apply(value);
					}
				}
			} else if (root.isArray()) {
				Iterator<JsonNode> iElement = root.elements();
				while (iElement.hasNext()) {
					apply(iElement.next());
				}
			}
			return root;
		}

	}

	private final UnaryOperator<JsonNode> x_objects = new X_Objects();
	private final UnaryOperator<JsonNode> emptyArrays = new EmptyArrays();
	private final UnaryOperator<JsonNode> x_properties = new X_Properties();
	private final UnaryOperator<JsonNode> emptyObjects = new EmptyObjects();
	private final UnaryOperator<JsonNode> trim = new Trim();

	@Override
	public JsonNode apply(JsonNode root) {
		return trim.apply(emptyObjects.apply(x_properties.apply(emptyArrays.apply(x_objects.apply(root)))));
	}

	public static void main(String[] args) {
		try (Reader in = Files.newBufferedReader(Paths.get(args[0]));
				Writer out = Files.newBufferedWriter(Paths.get(args[1]))) {
			out.write(new Cleaner().apply(JSON.readTree(in)).toPrettyString());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
