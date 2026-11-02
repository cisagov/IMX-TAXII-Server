/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data.impl;

import java.io.IOException;
import java.io.Reader;
import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.cisa.cti4j2.CommonProperty;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.STIXIdentifier;
import com.cisa.cti4j2.Type;
import com.cisa.taxii4j2.data.Envelope;

public class JSONBundle extends JSONSTIXObject {

	public static final String objectsKey = "objects";

	public JSONBundle(JsonNode root) {
		super(root);
	}

	public JSONBundle() {
		this((List<STIXObject>) null);
	}

	public JSONBundle(List<STIXObject> objects) {
		super();
		ObjectNode object = asObjectNode();
		object.put(CommonProperty.TYPE.getJsonKey(), Type.BUNDLE.toSTIXType());
		object.put(CommonProperty.ID.getJsonKey(), STIXIdentifier.encode(Type.BUNDLE, object));
		if ((objects != null) && !objects.isEmpty()) {
			object.set(objectsKey, JSON.convertValue(objects, JsonNode.class));
		}
	}

	public JSONBundle(Envelope envelope) {
		this(envelope.getObjects());
	}

	public JSONBundle(Reader in) throws IOException {
		super(JSON.readTree(in));
	}

	@SuppressWarnings("unchecked")
	public List<STIXObject> getObjects() {
		JsonNode objects = asObjectNode().get(objectsKey);
		return (objects != null) ? JSON.convertValue(objects, List.class) : Collections.emptyList();
	}

}
