/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.latency;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.Timestamp;

public class LatencyBase implements Comparable<LatencyBase> {

	public static final String timestampKey = "timestamp";
	public static final String connectWaitMillisKey = "connectWaitMillis";
	public static final String readWaitMillisKey = "readWaitMillis";
	public static final String labelKey = "label";

	@JsonProperty(timestampKey)
	private Timestamp timestamp;

	@JsonProperty(connectWaitMillisKey)
	private int connectWaitMillis;

	@JsonProperty(readWaitMillisKey)
	private int readWaitMillis;

	@JsonProperty(labelKey)
	private String label;

	public LatencyBase(String label) {
		this(null, Integer.MIN_VALUE, Integer.MIN_VALUE, label);
	}

	public LatencyBase(int connectWaitMillis, int readWaitMillis, String label) {
		this(null, connectWaitMillis, readWaitMillis, label);
	}

	protected LatencyBase() {
		this(null, Integer.MIN_VALUE, Integer.MIN_VALUE, null);
	}

	protected LatencyBase(Timestamp timestamp) {
		this(timestamp, Integer.MIN_VALUE, Integer.MIN_VALUE, null);
	}

	@JsonCreator
	public LatencyBase(@JsonProperty(value = timestampKey, required = true) Timestamp timestamp,
			@JsonProperty(value = connectWaitMillisKey, required = true) int connectWaitMillis,
			@JsonProperty(value = readWaitMillisKey, required = true) int readWaitMillis,
			@JsonProperty(value = labelKey, required = true) String label) {
		super();
		this.timestamp = timestamp;
		this.connectWaitMillis = connectWaitMillis;
		this.readWaitMillis = readWaitMillis;
		this.label = label;
	}

	public Timestamp getTimestamp() {
		return timestamp;
	}

	public String getLabel() {
		return label;
	}

	public int getConnectWaitMillis() {
		return connectWaitMillis;
	}

	public int getReadWaitMillis() {
		return readWaitMillis;
	}

	@JsonIgnore
	public void set(Timestamp timestamp) {
		this.timestamp = timestamp;
	}

	@JsonIgnore
	public void set(LatencySample sample) {
		set(sample.getTimestamp());
		connectWaitMillis = Integer.max(sample.getConnectWaitMillis(), connectWaitMillis);
		readWaitMillis = Integer.max(sample.getReadWaitMillis(), readWaitMillis);
		label = sample.getLabel();
	}

	@Override
	public String toString() {
		return JSON.convertValue(this, JsonNode.class).toPrettyString();
	}

	@Override
	public int compareTo(LatencyBase o) {
		return timestamp.compareTo(o.timestamp);
	}

}
