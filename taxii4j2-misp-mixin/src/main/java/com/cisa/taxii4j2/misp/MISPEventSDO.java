/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.misp;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

import org.webpki.jcs.JsonCanonicalizer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.cisa.cti4j2.CTIMediaType;
import com.cisa.cti4j2.CommonProperty;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.STIXIdentifier;
import com.cisa.cti4j2.Timestamp;
import com.cisa.cti4j2.UUID5;
import com.cisa.taxii4j2.data.impl.JSONSTIXObject;

public class MISPEventSDO extends JSONSTIXObject {

	private static final String type = "misp-event";
	private static final UUID namespace = UUID.fromString("ec7638d3-17b8-4d82-b44b-8dc6d9c0bf65");
	private static final String extension_definition = STIXIdentifier.encode("extension-definition", namespace);
	private static JsonNode extensions = JSON.factory.objectNode().set(extension_definition,
			JSON.factory.objectNode().put("extension_type", "new-sdo"));
	public static final String EventKey = "Event";
	public static final String timestampKey = "timestamp";
	public static final String idKey = "id";

	public MISPEventSDO(JsonNode Event) {
		super(JSON.factory.objectNode());
		object.put(CommonProperty.TYPE.getJsonKey(), type);
		object.put(CommonProperty.SPEC_VERSION.getJsonKey(), CTIMediaType.SPEC_VERSION);
		Timestamp created = new Timestamp(Instant.ofEpochSecond(Event.get(timestampKey).asLong()));
		object.put(CommonProperty.CREATED.getJsonKey(), created.toString());

		UUID uuid = UUID.randomUUID();
		try {
			ObjectNode name = JSON.factory.objectNode().put(timestampKey, Event.get(timestampKey).asLong()).put(idKey,
					Event.get(idKey).asInt());
			JsonCanonicalizer jc = new JsonCanonicalizer(JSON.writeTreeAsString(name));
			uuid = UUID5.fromUTF8(namespace, jc.getEncodedString());
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}

		object.put(CommonProperty.ID.getJsonKey(), STIXIdentifier.encode(type, uuid));
		object.set(CommonProperty.EXTENSIONS.getJsonKey(), extensions);
		object.set(EventKey, Event);
	}

}
