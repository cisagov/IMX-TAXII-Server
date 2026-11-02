/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job;

import java.io.IOException;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.cti4j2.CTIDuration;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.client.RemoteInfo;

@JsonInclude(Include.NON_NULL)
public class Configuration {

	protected static final String infoKey = "info";
	protected static final String workerCountKey = "workerCount";
	protected static final String workerDurationKey = "workerDuration";
	protected static final String nextWorkerKey = "nextWorker";

	@JsonProperty(infoKey)
	private final RemoteInfo info;

	@JsonProperty(workerCountKey)
	private final int workerCount;

	@JsonProperty(workerDurationKey)
	private final CTIDuration workerDuration;

	@JsonProperty(nextWorkerKey)
	private final Timestamp nextWorker;

	@JsonCreator
	public Configuration(@JsonProperty(value = infoKey, required = true) RemoteInfo info,
			@JsonProperty(value = workerCountKey, required = true) int workerCount,
			@JsonProperty(value = workerDurationKey, required = true) CTIDuration workerDuration,
			@JsonProperty(value = nextWorkerKey, required = false) Timestamp nextWorker) {
		super();
		this.info = info;
		this.workerCount = workerCount;
		this.workerDuration = workerDuration;
		this.nextWorker = nextWorker;
	}

	public RemoteInfo getInfo() {
		return info;
	}

	public int getWorkerCount() {
		return workerCount;
	}

	public CTIDuration getWorkerDuration() {
		return workerDuration;
	}

	public Timestamp getNextWorker() {
		return nextWorker;
	}

	@Override
	public String toString() {
		try {
			return JSON.writeValueAsString(this);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

}
