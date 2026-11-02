/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.cti4j2;

import java.util.UUID;

import com.fasterxml.jackson.databind.JsonNode;

public class STIXIdentifier {

	private enum Parts {
		TYPE, UUID
	};

	public static String encode(JsonNode root) {
		return encode(root.get(CommonProperty.TYPE.getJsonKey()).asText(), root);
	}

	public static String encode(String stixType, JsonNode root) {
		try {
			return encode(Type.fromSTIXType(stixType), root);
		} catch (IllegalArgumentException e) {
			return encode(stixType, UUID.randomUUID());
		}
	}

	public static String encode(Type type, JsonNode root) {
		return encode(type.toSTIXType(), type.getUuid(root));
	}

	public static String encode(String stixType, UUID uuid) {
		return String.format("%s--%s", stixType, uuid);
	}

	public static boolean isAny(String id) {
		try {
			parts(id);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	public static boolean isKnown(String id) {
		try {
			getType(id);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	private static String[] parts(String id) {
		String[] parts = id.split("--", 2);
		UUID.fromString(parts[Parts.UUID.ordinal()]);
		return parts;
	}

	public static String getStixType(String id) {
		return parts(id)[Parts.TYPE.ordinal()];
	}

	public static Type getType(String id) {
		return Type.fromSTIXType(getStixType(id));
	}

	public static UUID getUuid(String id) {
		return UUID.fromString(parts(id)[Parts.UUID.ordinal()]);
	}

}
