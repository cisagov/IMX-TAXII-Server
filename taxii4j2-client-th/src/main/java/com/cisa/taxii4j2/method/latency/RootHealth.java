/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.latency;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;

public class RootHealth {

	public static final String collectionsKey = "collections_endpoint";
	public static final String objectsKey = "objects_endpoint";

	@JsonProperty(collectionsKey)
	private EndpointHealth collections;

	@JsonProperty(objectsKey)
	private List<EndpointHealth> objects;

	public RootHealth(@JsonProperty(value = collectionsKey, required = true) EndpointHealth collections,
			@JsonProperty(value = objectsKey, required = true) List<EndpointHealth> objects) {
		super();
		this.collections = collections;
		this.objects = objects;
	}

	public EndpointHealth getCollections() {
		return collections;
	}

	public List<EndpointHealth> getObjects() {
		return objects;
	}

	@Override
	public String toString() {
		return JSON.convertValue(this, JsonNode.class).toPrettyString();
	}

}
