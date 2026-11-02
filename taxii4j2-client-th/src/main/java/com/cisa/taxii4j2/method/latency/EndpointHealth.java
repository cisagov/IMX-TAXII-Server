/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.latency;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.Timestamp;

public class EndpointHealth extends LatencyBase {

	private static final String minResponseMillisKey = "minResponseMillis";
	private static final String maxResponseMillisKey = "maxResponseMillis";
	private static final String sumResponseMillisKey = "sumResponseMillis";
	private static final String nKey = "n";
	private static final String errorsKey = "errors";

	@JsonProperty(minResponseMillisKey)
	private int minResponseMillis = Integer.MAX_VALUE;

	@JsonProperty(maxResponseMillisKey)
	private int maxResponseMillis = Integer.MIN_VALUE;

	@JsonProperty(sumResponseMillisKey)
	private long sumResponseMillis = 0;

	@JsonProperty(nKey)
	private int n = 0;

	@JsonProperty(errorsKey)
	private Map<String, Integer> errors = new HashMap<>();

	public EndpointHealth(String label) {
		super(label);
	}

	@JsonCreator
	public EndpointHealth(@JsonProperty(value = LatencyBase.timestampKey, required = true) Timestamp timestamp,
			@JsonProperty(value = connectWaitMillisKey, required = true) int connectWaitMillis,
			@JsonProperty(value = readWaitMillisKey, required = true) int readWaitMillis,
			@JsonProperty(value = labelKey, required = true) String label,
			@JsonProperty(value = minResponseMillisKey, required = true) int minResponseMillis,
			@JsonProperty(value = maxResponseMillisKey, required = true) int maxResponseMillis,
			@JsonProperty(value = sumResponseMillisKey, required = true) long sumResponseMillis,
			@JsonProperty(value = nKey, required = true) int n,
			@JsonProperty(value = errorsKey, required = true) Map<String, Integer> errors) {
		super(timestamp, connectWaitMillis, readWaitMillis, label);
		this.minResponseMillis = minResponseMillis;
		this.maxResponseMillis = maxResponseMillis;
		this.sumResponseMillis = sumResponseMillis;
		this.n = n;
		this.errors = errors;
	}

	public static EndpointHealth create(Stream<LatencySample> samples) {
		EndpointHealth eh = new EndpointHealth(samples);
		return eh.isValid() ? eh : null;
	}

	@JsonIgnore
	public boolean isValid() {
		return (n > 0) || !errors.isEmpty();
	}

	private EndpointHealth(Stream<LatencySample> samples) {
		super();
		samples.forEach(s -> set(s));
	}

	@JsonIgnore
	public void set(LatencySample sample) {
		super.set(sample);
		String error = sample.getError();
		if (error == null) {
			int millis = sample.getMillis();
			minResponseMillis = Integer.min(millis, minResponseMillis);
			maxResponseMillis = Integer.max(millis, maxResponseMillis);
			sumResponseMillis += millis;
			++n;
			errors.clear();
		} else {
			minResponseMillis = Integer.MAX_VALUE;
			maxResponseMillis = Integer.MIN_VALUE;
			sumResponseMillis = 0;
			n = 0;
			errors.merge(error, 1, (prev, curr) -> prev + curr);
		}
	}

	@JsonIgnore
	public long getAvgResponseMillis() {
		return (n > 0) ? sumResponseMillis / n : -1;
	}

	public long getMinResponseMillis() {
		return minResponseMillis;
	}

	public long getMaxResponseMillis() {
		return maxResponseMillis;
	}

	public Map<String, Integer> getErrors() {
		return java.util.Collections.unmodifiableMap(errors);
	}

	public long getSumResponseMillis() {
		return sumResponseMillis;
	}

	public int getN() {
		return n;
	}

	@Override
	public String toString() {
		return JSON.convertValue(this, JsonNode.class).toPrettyString();
	}

}
