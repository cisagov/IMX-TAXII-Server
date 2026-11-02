/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job;

import java.io.IOException;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.Timestamp;

@JsonInclude(Include.NON_NULL)
public abstract class Snapshot {

	protected static final String workerParamsKey = "workerParams";
	protected static final String nextWorkerKey = "nextWorker";

	@JsonProperty(nextWorkerKey)
	private final Timestamp nextWorker;

	@JsonCreator
	public Snapshot(@JsonProperty(value = nextWorkerKey, required = true) Timestamp nextWorker) {
		super();
		this.nextWorker = nextWorker;
	}

	public Timestamp getNextWorker() {
		return nextWorker;
	}

	public abstract Set<? extends WorkerParams> getWorkerParams();

	public abstract boolean hasWorkerParams();

	@Override
	public String toString() {
		try {
			return JSON.writeValueAsString(this);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

}
