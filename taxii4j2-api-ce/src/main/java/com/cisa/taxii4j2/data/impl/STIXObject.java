/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data.impl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.cisa.cti4j2.CTIMediaType;
import com.cisa.cti4j2.CommonProperty;
import com.cisa.cti4j2.ExtensionType;
import com.cisa.cti4j2.Group;
import com.cisa.cti4j2.STIXIdentifier;
import com.cisa.cti4j2.Timestamp;
import com.cisa.cti4j2.Type;

/**
 * This interface introduces STIX-specific properties which either (a) have
 * values and/or (b) require checking for applicability. It includes utilities
 * for object-level validation and/or remediation. Some getters were added so
 * that core code could access properties via the interface (rather than e.g.
 * concrete implementations based on JSON encoding).
 */
@JsonSerialize(using = STIXObject.Serializer.class)
@JsonDeserialize(using = STIXObject.Deserializer.class)
public abstract class STIXObject extends Storable {

	public abstract STIXObject deepCopy();

	public abstract Set<String> mentionedIds();

	public STIXObject setVersionToNow() {
		return setVersion(new Timestamp());
	}

	public abstract STIXObject setVersion(Timestamp version);

	public abstract ObjectNode asObjectNode();

	public abstract Timestamp getDate_added(String cId);

	public abstract STIXObject setDate_added(String cId, Timestamp dateAdded);

	public static class Serializer extends StdSerializer<STIXObject> {

		private static final long serialVersionUID = 1L;

		public Serializer() {
			super(STIXObject.class);
		}

		@Override
		public void serialize(STIXObject value, JsonGenerator gen, SerializerProvider provider) throws IOException {
			gen.writeTree(value.asObjectNode());
		}

	}

	public static class Deserializer extends StdDeserializer<STIXObject> {

		private static final long serialVersionUID = 1L;

		public Deserializer() {
			super(STIXObject.class);
		}

		@Override
		public STIXObject deserialize(JsonParser p, DeserializationContext ctxt)
				throws IOException, JsonProcessingException {
			try {
				JsonNode root = p.readValueAsTree();
				Class<? extends STIXObject> clazz = JSONSTIXObject.class;
				return clazz.getConstructor(JsonNode.class).newInstance(root);
			} catch (Exception e) {
				throw new IOException(e);
			}
		}

	}

	public boolean isNA(CommonProperty property) {
		return getType().isNa(property);
	}

	private void checkNA(CommonProperty property) {
		if (isNA(property)) {
			throw new IllegalArgumentException();
		}
	}

	public String getStixType() {
		return STIXIdentifier.getStixType(getId());
	}

	public Type getType() {
		return Type.fromSTIXType(getStixType());
	}

	public String getSpec_version() {
		checkNA(CommonProperty.SPEC_VERSION);
		return CTIMediaType.SPEC_VERSION;
	}

	public String getCreated_by_ref() {
		checkNA(CommonProperty.CREATED_BY_REF);
		return null;
	}

	public boolean isRevoked() {
		checkNA(CommonProperty.REVOKED);
		return false;
	}

	public List<String> getLabels() {
		checkNA(CommonProperty.LABELS);
		return null;
	}

	public Integer getConfidence() {
		checkNA(CommonProperty.CONFIDENCE);
		return null;
	}

	public String getLang() {
		checkNA(CommonProperty.LANG);
		return Locale.ENGLISH.getLanguage();
	}

	public List<String> getObject_marking_refs() {
		checkNA(CommonProperty.OBJECT_MARKING_REFS);
		return null;
	}

	public boolean getDefanged() {
		checkNA(CommonProperty.DEFANGED);
		return false;
	}

	public String getCreated() {
		checkNA(CommonProperty.CREATED);
		return null;
	}

	public String getModified() {
		checkNA(CommonProperty.MODIFIED);
		return null;
	}

	@Override
	public String getMedia_type() {
		return String.format("%s;version=%s", CTIMediaType.STIX, getSpec_version());
	}

	public STIXObject removeMyX_() {
		return removeX_(k -> TAXIIConfig.isMyX_(k));
	}

	public STIXObject removeX_() {
		return removeX_(k -> TAXIIConfig.isX_(k));
	}

	public abstract STIXObject removeX_(Predicate<String> p);

	public static String date_addedKey(String cId) {
		return TAXIIConfig.x_(cId);
	}

	public static String getCId(String key) {
		if (TAXIIConfig.isMyX_(key)) {
			String cId = TAXIIConfig.unX_(key).replaceAll("_", "-");
			try {
				UUID.fromString(cId);
				return cId;
			} catch (IllegalArgumentException e) {
				// not a UUID (a collection id), fall through
			}
		}
		return null;
	}

	public abstract Set<String> getCIds();

	public List<String> isCustom() {
		return getStixType().startsWith("x-")
				? Collections.singletonList(String.format("%s/%s is a custom objects", getId(), getVersion()))
				: Collections.emptyList();

	}

	public abstract List<String> checkHasNa();

	public List<String> removeCustomProperties() {
		return removeCustomProperties(new ArrayList<>(), "");
	}

	public abstract List<String> removeCustomProperties(List<String> message, String prefix);

	public List<String> removeEmptyArrays() {
		return removeEmptyArrays(new ArrayList<>(), "");
	}

	public abstract List<String> removeEmptyArrays(List<String> message, String prefix);

	public List<String> trimTexts() {
		return trimTexts(new ArrayList<>(), "");
	}

	public abstract List<String> trimTexts(List<String> message, String prefix);

	public abstract List<String> checkMissing();

	public String indexQualifier() {
		return getType().indexQualifier();
	}

	@JsonIgnore
	public boolean isSCO() {
		return isA(Group.SCO, ExtensionType.NEW_SCO);
	}

	@JsonIgnore
	public boolean isSDO() {
		return isA(Group.SDO, ExtensionType.NEW_SDO);
	}

	@JsonIgnore
	public boolean isSRO() {
		return isA(Group.SRO, ExtensionType.NEW_SRO);
	}

	private boolean isA(Group group, ExtensionType type) {
		try {
			return getType().getGroup() == group;
		} catch (IllegalArgumentException e) {
			JsonNode extensions = asObjectNode().get(CommonProperty.EXTENSIONS.getJsonKey());
			if (extensions != null) {
				Iterator<Map.Entry<String, JsonNode>> iField = extensions.fields();
				while (iField.hasNext()) {
					try {
						ExtensionType unknown = ExtensionType
								.create(iField.next().getValue().get("extension_type").asText());
						if (type == unknown) {
							return true;
						}
					} catch (IllegalArgumentException e1) {
						// NOP
					}
				}
			}
		}
		return false;
	}

	@JsonIgnore
	public boolean isOrphan() {
		return getCIds().isEmpty();
	}

}
