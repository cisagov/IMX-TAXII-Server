/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.cti4j2;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.webpki.jcs.JsonCanonicalizer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

public enum Type {

	ATTACK_PATTERN(Group.SDO), CAMPAIGN(Group.SDO), COURSE_OF_ACTION(Group.SDO), GROUPING(Group.SDO),
	IDENTITY(Group.SDO), INCIDENT(Group.SDO), INDICATOR(Group.SDO), INFRASTRUCTURE(Group.SDO), INTRUSION_SET(Group.SDO),
	LOCATION(Group.SDO), MALWARE(Group.SDO), MALWARE_ANALYSIS(Group.SDO), NOTE(Group.SDO), OBSERVED_DATA(Group.SDO),
	OPINION(Group.SDO), REPORT(Group.SDO), THREAT_ACTOR(Group.SDO), TOOL(Group.SDO), VULNERABILITY(Group.SDO), //
//
	RELATIONSHIP(Group.SRO), SIGHTING(Group.SRO), //
//
	ARTIFACT(Group.SCO, "payload_bin", "hashes"), AUTONOMOUS_SYSTEM(Group.SCO, "number"), DIRECTORY(Group.SCO, "path"),
	DOMAIN_NAME(Group.SCO, "value"), EMAIL_ADDR(Group.SCO, "value"),
	EMAIL_MESSAGE(Group.SCO, "from_ref", "subject", "body"),
	FILE(Group.SCO, "hashes", "name", CommonProperty.EXTENSIONS.getJsonKey(), "parent_directory_ref"),
	IPV4_ADDR(Group.SCO, "value"), IPV6_ADDR(Group.SCO, "value"), MAC_ADDR(Group.SCO, "value"),
	MUTEX(Group.SCO, "name"),
	NETWORK_TRAFFIC(Group.SCO, "start", "end", "src_ref", "dst_ref", "src_port", "dst_port", "protocols",
			CommonProperty.EXTENSIONS.getJsonKey()),
	PROCESS(Group.SCO), SOFTWARE(Group.SCO, "name", "cpe", "swid", "vendor", "version"), URL(Group.SCO, "value"),
	USER_ACCOUNT(Group.SCO, "account_type", "user_id", "account_login"),
	WINDOWS_REGISTRY_KEY(Group.SCO, "key", "values"), X509_CERTIFICATE(Group.SCO, "hashes", "serial_number"), //
//
	LANGUAGE_CONTENT(Group.LANGUAGE), MARKING_DEFINITION(Group.MARKINGS), EXTENSION_DEFINITION(Group.EXTENSION),
	BUNDLE(Group.BUNDLE);

	private static final UUID SCO_NAMESPACE = UUID.fromString("00abedb4-aa42-466c-9c01-fed23315a9b7");

	private final Group group;
	private final String[] idcps;

	private Type(Group group, String... idcps) {
		this.group = group;
		this.idcps = idcps;
	}

	public UUID getUuid(JsonNode root) {
		if ((idcps == null) || (idcps.length == 0)) {
			return UUID.randomUUID();
		}
		JsonNode name = getUuid5Name(root);
		if (name.isEmpty()) {
			return UUID.randomUUID();
		}
		try {
//			return UUID5.fromUTF8(SCO_NAMESPACE, JSON.writeTreeAsString(name));
			JsonCanonicalizer jc = new JsonCanonicalizer(JSON.writeTreeAsString(name));
			return UUID5.fromUTF8(SCO_NAMESPACE, jc.getEncodedString());
		} catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	private static JsonNode properties;
	private static final Map<String, Set<Type>> byProperty = new HashMap<>();
	static {
		try (InputStream in = Type.class.getResourceAsStream("properties.json")) {

			properties = JSON.readTree(new InputStreamReader(in));

			Iterator<Map.Entry<String, JsonNode>> iField = ObjectNode.class.cast(properties).fields();
			while (iField.hasNext()) {
				Map.Entry<String, JsonNode> field = iField.next();
				Type type = fromSTIXType(field.getKey());
				Iterator<JsonNode> iProperty = field.getValue().elements();
				while (iProperty.hasNext()) {
					byProperty.computeIfAbsent(iProperty.next().asText(), k -> new HashSet<>()).add(type);
				}
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static Set<Type> getTypes(String property) {
		return byProperty.get(property);
	}

	public List<String> getProperties() {
		return getProperties(this);
	}

	@SuppressWarnings("unchecked")
	public static List<String> getProperties(Type type) {
		return JSON.convertValue(properties.get(type.toSTIXType()), List.class);
	}

	public static final String hashesKey = "hashes";

	private JsonNode getUuid5Name(JsonNode root) {
		ObjectNode name = JSON.factory.objectNode();
		for (String key : idcps) {
			JsonNode value = root.get(key);
			if (value == null) {
				continue;
			}
			if (key.equals(hashesKey)) {
				for (HashAlgorithmOV alg : HashAlgorithmOV.values()) {
					String hashKey = alg.toString();
					JsonNode hash = value.get(hashKey);
					if (hash != null) {
//						name.set(hashKey, hash);
						name.set(hashesKey, JSON.factory.objectNode().set(hashKey, hash));
						break;
					}
				}
			} else {
				name.set(key, value);
			}
		}
		return name;
	}

	public String toSTIXType() {
		return name().toLowerCase().replace('_', '-');
	}

	public static Type fromSTIXType(String type) {
		for (Type t : values()) {
			if (type.equals(t.toSTIXType())) {
				return t;
			}
		}
		throw new IllegalArgumentException();
	}

	public boolean isNa(CommonProperty property) {
		return group.isNa(property);
	}

	public List<String> checkHasNa(ObjectNode object) {
		return group.checkHasNa(object);
	}

	public List<String> checkMissing(ObjectNode object) {
		return group.checkMissing(object);
	}

	public boolean isSCO() {
		return group == Group.SCO;
	}

	public String indexQualifier() {
		return group.name().toLowerCase();
	}

	public Group getGroup() {
		return group;
	}

}
