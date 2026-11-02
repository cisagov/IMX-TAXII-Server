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
import com.cisa.cti4j2.Timestamp;

public class LatencySample extends LatencyBase {

	private static final String millisKey = "millis";
	private static final String errorKey = "error";

	@JsonProperty(millisKey)
	private int millis = -1;

	@JsonProperty(errorKey)
	private String error = null;

	public LatencySample(Timestamp timestamp) {
		super(timestamp);

	}
	public LatencySample(int connectWaitMillis, int readWaitMillis, String label) {
		super(connectWaitMillis, readWaitMillis, label);
	}

	@JsonCreator
	public LatencySample(@JsonProperty(value = timestampKey, required = true) Timestamp timestamp,
			@JsonProperty(value = connectWaitMillisKey, required = true) int connectWaitMillis,
			@JsonProperty(value = readWaitMillisKey, required = true) int readWaitMillis,
			@JsonProperty(value = labelKey, required = true) String label,
			@JsonProperty(value = millisKey, required = true) int millis,
			@JsonProperty(value = errorKey, required = false) String error) {
		super(timestamp, connectWaitMillis, readWaitMillis, label);
		this.millis = millis;
		this.error = error;
	}

	public int getMillis() {
		return millis;
	}

	public String getError() {
		return error;
	}

	@JsonIgnore
	public void set(Timestamp timestamp, int millis, String error) {
		super.set(timestamp);
		this.millis = millis;
		this.error = error;
	}
}
