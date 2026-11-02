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
import com.cisa.cti4j2.Timestamp;

public class Health {

	public static final String taxii2Key = "taxii2_endpoint";
	public static final String rootsKey = "roots";

	@JsonProperty(LatencyBase.timestampKey)
	private final Timestamp timestamp;

	@JsonProperty(taxii2Key)
	private final EndpointHealth taxii2;

	@JsonProperty(rootsKey)
	private final List<RootHealth> roots;

	public Health(@JsonProperty(value = LatencyBase.timestampKey, required = true) Timestamp timestamp,
			@JsonProperty(value = taxii2Key, required = true) EndpointHealth taxii2,
			@JsonProperty(value = rootsKey, required = true) List<RootHealth> roots) {
		super();
		this.timestamp = timestamp;
		this.taxii2 = taxii2;
		this.roots = roots;
	}

	public Timestamp getTimestamp() {
		return timestamp;
	}

	public EndpointHealth getTaxii2() {
		return taxii2;
	}

	public List<RootHealth> getRoots() {
		return roots;
	}

	@Override
	public String toString() {
		return JSON.convertValue(this, JsonNode.class).toPrettyString();
	}
}
