/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job.taxii;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.client.job.Snapshot;
import com.cisa.taxii4j2.client.job.WorkerParams;

@JsonInclude(Include.NON_NULL)
public class TAXIISnapshot extends Snapshot {

	@JsonProperty(workerParamsKey)
	private final Set<TAXIIWorkerParams> workerParams;

	@JsonIgnore
	private final boolean hasWorkerParams;

	@JsonCreator
	public TAXIISnapshot(@JsonProperty(value = workerParamsKey, required = false) Set<TAXIIWorkerParams> workerParams,
			@JsonProperty(value = nextWorkerKey, required = true) Timestamp nextWorker) {
		super(nextWorker);
		this.hasWorkerParams = (workerParams != null) && !workerParams.isEmpty();
		this.workerParams = this.hasWorkerParams ? workerParams : null;
	}

	@Override
	public Set<? extends WorkerParams> getWorkerParams() {
		return workerParams;
	}

	public boolean hasWorkerParams() {
		return hasWorkerParams;
	}

}
