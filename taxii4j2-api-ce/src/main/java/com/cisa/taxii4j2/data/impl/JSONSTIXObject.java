/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data.impl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.cisa.cti4j2.CommonProperty;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.STIXIdentifier;
import com.cisa.cti4j2.Timestamp;
import com.cisa.cti4j2.Type;

public class JSONSTIXObject extends STIXObject {

	protected ObjectNode object;

	public JSONSTIXObject() {
		this(JSON.factory.objectNode());
	}

	public JSONSTIXObject(JsonNode root) {
		this(ObjectNode.class.cast(root));
	}

	public JSONSTIXObject(ObjectNode object) {
		super();
		this.object = object;
	}

	protected String text(CommonProperty property) {
		return object.get(property.getJsonKey()).asText();
	}

	protected List<String> texts(CommonProperty property) {
		List<String> texts = new ArrayList<>();
		Iterator<JsonNode> iText = object.get(property.getJsonKey()).elements();
		while (iText.hasNext()) {
			JsonNode text = iText.next();
			if (!text.isTextual()) {
				throw new IllegalArgumentException();
			}
			texts.add(text.asText());
		}
		return texts;
	}

	@Override
	public String getId() {
		return text(CommonProperty.ID);
	}

	@Override
	public String getVersion() {
		try {
			return text(CommonProperty.MODIFIED);
		} catch (NullPointerException e) {
			try {
				return text(CommonProperty.CREATED);
			} catch (NullPointerException e1) {
				return Timestamp.epoch.toString();
			}
		}
	}

	@Override
	public Timestamp getDate_added(String cId) {
		JsonNode node = object.get(STIXObject.date_addedKey(cId));
		return ((node != null) && !node.isNull()) ? Timestamp.valueOf(node.asText()) : null;
	}

	@Override
	public STIXObject setDate_added(String cId, Timestamp dateAdded) {
		String key = date_addedKey(cId);
		if (dateAdded != null) {
			object.put(key, dateAdded.toString());
		} else {
			object.putNull(key);
		}
		return this;
	}

	@Override
	public ObjectNode asObjectNode() {
		return object;
	}

	@Override
	public String toString() {
		return object.toPrettyString();
	}

	@Override
	public String getStixType() {
		try {
			return text(CommonProperty.TYPE);
		} catch (NullPointerException e) {
			return super.getStixType();
		}
	}

	protected STIXObject removeX_(JsonNode node, Predicate<String> p) {
		Iterator<Map.Entry<String, JsonNode>> iField = node.fields();
		while (iField.hasNext()) {
			Map.Entry<String, JsonNode> field = iField.next();
			if (p.test(field.getKey())) {
				iField.remove();
			} else {
				removeX_(field.getValue(), p);
			}
		}
		return this;
	}

	protected List<String> removeCustomProperties(List<String> message, JsonNode root, String prefix) {
		if (root.isObject()) {
			Iterator<Map.Entry<String, JsonNode>> iField = root.fields();
			while (iField.hasNext()) {
				Map.Entry<String, JsonNode> field = iField.next();
				String key = String.format("%s.%s", prefix, field.getKey());
				JsonNode value = field.getValue();
				if (field.getKey().startsWith("x_")) {
					iField.remove();
					message.add(String.format("custom property %s removed", key));
				} else {
					removeCustomProperties(message, value, key);
				}
			}
		} else if (root.isArray()) {
			int i = 0;
			Iterator<JsonNode> iElement = root.elements();
			while (iElement.hasNext()) {
				removeCustomProperties(message, iElement.next(), String.format("%s[%d]", prefix, i++));
			}
		}
		return message;
	}

	protected List<String> removeEmptyArrays(List<String> message, JsonNode root, String prefix) {
		if (root.isObject()) {
			Iterator<Map.Entry<String, JsonNode>> iField = root.fields();
			while (iField.hasNext()) {
				Map.Entry<String, JsonNode> field = iField.next();
				String key = String.format("%s.%s", prefix, field.getKey());
				JsonNode value = field.getValue();
				if (value.isArray() && value.isEmpty()) {
					iField.remove();
					message.add(String.format("empty array field %s removed", key));
				} else {
					removeEmptyArrays(message, value, key);
				}
			}
		} else if (root.isArray()) {
			int i = 0;
			Iterator<JsonNode> iElement = root.elements();
			while (iElement.hasNext()) {
				removeEmptyArrays(message, iElement.next(), String.format("%s[%d]", prefix, i++));
			}
		}
		return message;
	}

	protected List<String> trimTexts(List<String> message, JsonNode root, String prefix) {
		if (root.isObject()) {
			Iterator<Map.Entry<String, JsonNode>> iField = root.fields();
			while (iField.hasNext()) {
				Map.Entry<String, JsonNode> field = iField.next();
				String key = String.format("%s.%s", prefix, field.getKey());
				JsonNode value = field.getValue();
				if (value.isTextual()) {
					String text = value.asText();
					String trimmed = text.trim();
					if (text.length() != trimmed.length()) {
						ObjectNode.class.cast(root).put(field.getKey(), trimmed);
						message.add(String.format("field %s required trimming", key));
					}
				} else {
					trimTexts(message, value, key);
				}
			}
		} else if (root.isArray()) {
			int i = 0;
			Iterator<JsonNode> iElement = root.elements();
			while (iElement.hasNext()) {
				trimTexts(message, iElement.next(), String.format("%s[%d]", prefix, i++));
			}
		}
		return message;
	}

	@Override
	public STIXObject setVersion(Timestamp version) {
		if (getType().isNa(CommonProperty.MODIFIED)) {
			throw new IllegalArgumentException();
		}
		object.put(CommonProperty.MODIFIED.getJsonKey(), version.toString());
		return this;
	}

	@Override
	public String getSpec_version() {
		try {
			return text(CommonProperty.SPEC_VERSION);
		} catch (NullPointerException e) {
			return super.getSpec_version();
		}
	}

	@Override
	public STIXObject removeX_(Predicate<String> p) {
		return removeX_(object, p);
	}

	@Override
	public String getCreated_by_ref() {
		try {
			return text(CommonProperty.CREATED_BY_REF);
		} catch (NullPointerException e) {
			return super.getCreated_by_ref();
		}
	}

	@Override
	public Set<String> getCIds() {
		Set<String> cIds = new HashSet<>();
		Iterator<Map.Entry<String, JsonNode>> iField = this.asObjectNode().fields();
		while (iField.hasNext()) {
			Map.Entry<String, JsonNode> field = iField.next();
			if (!field.getValue().isNull()) {
				String cId = STIXObject.getCId(field.getKey());
				if (cId != null) {
					cIds.add(cId);
				}
			}
		}
		return cIds;
	}

	@Override
	public List<String> checkHasNa() {

		// TODO - for now, custom objects have a "get out of jail free" card...
		Type type = null;
		try {
			type = getType();
		} catch (IllegalArgumentException e) {
			return Collections.emptyList();
		}

		return type.checkHasNa(object);
	}

	@Override
	public List<String> removeCustomProperties(List<String> message, String prefix) {
		return removeCustomProperties(message, object, prefix);
	}

	@Override
	public List<String> removeEmptyArrays(List<String> message, String prefix) {
		return removeEmptyArrays(message, object, prefix);
	}

	@Override
	public List<String> trimTexts(List<String> message, String prefix) {
		return trimTexts(message, object, prefix);
	}

	@Override
	public List<String> checkMissing() {
		return getType().checkMissing(object);
	}

	@Override
	public boolean isRevoked() {
		try {
			return Boolean.valueOf(text(CommonProperty.REVOKED));
		} catch (NullPointerException e) {
			return super.isRevoked();
		}
	}

	@Override
	public List<String> getLabels() {
		try {
			return texts(CommonProperty.LABELS);
		} catch (NullPointerException e) {
			return super.getLabels();
		}
	}

	@Override
	public Integer getConfidence() {
		try {
			return Integer.valueOf(text(CommonProperty.CONFIDENCE));
		} catch (NullPointerException e) {
			return super.getConfidence();
		}
	}

	@Override
	public String getLang() {
		try {
			return text(CommonProperty.LANG);
		} catch (NullPointerException e) {
			return super.getLang();
		}
	}

	@Override
	public List<String> getObject_marking_refs() {
		try {
			return texts(CommonProperty.OBJECT_MARKING_REFS);
		} catch (NullPointerException e) {
			return super.getObject_marking_refs();
		}
	}

	@Override
	public boolean getDefanged() {
		try {
			return Boolean.valueOf(text(CommonProperty.DEFANGED));
		} catch (NullPointerException e) {
			return super.getDefanged();
		}
	}

	@Override
	public String getCreated() {
		try {
			return text(CommonProperty.CREATED);
		} catch (NullPointerException e) {
			return super.getCreated();
		}
	}

	@Override
	public String getModified() {
		try {
			return text(CommonProperty.MODIFIED);
		} catch (NullPointerException e) {
			return super.getModified();
		}
	}

	@Override
	public Set<String> mentionedIds() {
		return mentionedIds(object, new HashSet<>());
	}

	private Set<String> mentionedIds(JsonNode object, Set<String> refs) {
		if (object.isObject()) {
			Iterator<Map.Entry<String, JsonNode>> iField = object.fields();
			while (iField.hasNext()) {
				Map.Entry<String, JsonNode> field = iField.next();
				String key = field.getKey();
				if (STIXIdentifier.isAny(key)) {
					refs.add(key);
				}
				mentionedIds(field.getValue(), refs);
			}
		} else if (object.isArray()) {
			Iterator<JsonNode> iElement = object.elements();
			while (iElement.hasNext()) {
				mentionedIds(iElement.next(), refs);
			}
		} else if (object.isTextual()) {
			String id = object.asText();
			if (STIXIdentifier.isAny(id)) {
				refs.add(id);
			}
		}
		return refs;
	}

	@Override
	public STIXObject deepCopy() {
		ObjectNode object = asObjectNode().deepCopy();
		String id = STIXIdentifier.encode(getStixType(), UUID.randomUUID());
		object.put(CommonProperty.ID.getJsonKey(), id);
		if (!getType().isSCO()) {
			String version = new Timestamp().toString();
			object.put(CommonProperty.CREATED.getJsonKey(), version);
			object.put(CommonProperty.MODIFIED.getJsonKey(), version);
		}
		return new JSONSTIXObject(object);
	}

}
