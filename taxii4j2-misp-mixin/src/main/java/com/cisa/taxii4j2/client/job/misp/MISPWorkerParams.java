/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job.misp;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.client.job.WorkerParams;
import com.cisa.taxii4j2.misp.MISPClient;

@JsonInclude(Include.NON_NULL)
public class MISPWorkerParams extends WorkerParams {

	public static final int limit = 32;

	@JsonProperty(MISPClient.timestampKey)
	private Timestamp timestamp;

	@JsonCreator
	public MISPWorkerParams(@JsonProperty(value = beginKey, required = true) Timestamp begin,
			@JsonProperty(value = endKey, required = true) Timestamp end,
			@JsonProperty(value = MISPClient.timestampKey, required = false) Timestamp timestamp) {
		super(begin, end);
		if (timestamp == null) {
			timestamp = begin;
		}
		this.timestamp = timestamp;
	}

	public MISPWorkerParams(Timestamp begin, Timestamp end) {
		this(begin, end, null);
	}

	public Timestamp getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(Timestamp timestamp) {
		this.timestamp = timestamp;
	}

	@JsonIgnore
	public ObjectNode getPayload() {
		return JSON.factory.objectNode().put(MISPClient.timestampKey, timestamp.instant.getEpochSecond())
				.put(MISPClient.limitKey, limit);
	}

}
