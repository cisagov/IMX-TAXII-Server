/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job.taxii.remote;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.client.job.remote.RemoteSnapshot;
import com.cisa.taxii4j2.client.job.taxii.TAXIISnapshot;
import com.cisa.taxii4j2.client.job.taxii.TAXIIWorkerParams;
import com.cisa.taxii4j2.data.Status;

@JsonInclude(Include.NON_NULL)
public class TAXIIRemoteSnapshot extends TAXIISnapshot implements RemoteSnapshot {

	public static final String statusKey = "status";

	@JsonProperty(RemoteSnapshot.uuidKey)
	private final UUID uuid;

	@JsonProperty(statusKey)
	private Status status;

	public TAXIIRemoteSnapshot(TAXIISnapshot src, UUID uuid) {
		this((src.getWorkerParams() != null)
				? src.getWorkerParams().stream().map(wp -> TAXIIWorkerParams.class.cast(wp)).collect(Collectors.toSet())
				: null, src.getNextWorker(), uuid, null);
	}

	@JsonCreator
	public TAXIIRemoteSnapshot(
			@JsonProperty(value = workerParamsKey, required = false) Set<TAXIIWorkerParams> workerParams,
			@JsonProperty(value = nextWorkerKey, required = true) Timestamp nextWorker,
			@JsonProperty(value = RemoteSnapshot.uuidKey, required = true) UUID uuid,
			@JsonProperty(value = statusKey, required = false) Status status) {
		super(workerParams, nextWorker);
		this.uuid = uuid;
		this.status = status;
	}

	@Override
	public UUID getUuid() {
		return uuid;
	}

	public Status getStatus() {
		return status;
	}

	public void setStatus(Status status) {
		this.status = status;
	}

}
