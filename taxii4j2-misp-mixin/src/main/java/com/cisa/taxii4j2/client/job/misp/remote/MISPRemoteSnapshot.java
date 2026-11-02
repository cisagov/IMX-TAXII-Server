/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job.misp.remote;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.client.job.misp.MISPSnapshot;
import com.cisa.taxii4j2.client.job.misp.MISPWorkerParams;
import com.cisa.taxii4j2.client.job.remote.RemoteSnapshot;

public class MISPRemoteSnapshot extends MISPSnapshot implements RemoteSnapshot {

	@JsonProperty(uuidKey)
	private final UUID uuid;

	@JsonCreator
	public MISPRemoteSnapshot(
			@JsonProperty(value = workerParamsKey, required = false) Set<MISPWorkerParams> workerParams,
			@JsonProperty(value = nextWorkerKey, required = true) Timestamp nextWorker,
			@JsonProperty(value = uuidKey, required = true) UUID uuid) {
		super(workerParams, nextWorker);
		this.uuid = uuid;
	}

	public MISPRemoteSnapshot(MISPSnapshot src, UUID uuid) {
		this((src.getWorkerParams() != null)
				? src.getWorkerParams().stream().map(wp -> MISPWorkerParams.class.cast(wp)).collect(Collectors.toSet())
				: null, src.getNextWorker(), uuid);
	}

	@Override
	public UUID getUuid() {
		return uuid;
	}

}
