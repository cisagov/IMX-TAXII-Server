/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job.misp.remote;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.cisa.cti4j2.CTIDuration;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.client.RemoteInfo;
import com.cisa.taxii4j2.client.job.Configuration;
import com.cisa.taxii4j2.client.job.remote.RemoteConfiguration;

@JsonInclude(Include.NON_NULL)
public class MISPRemoteConfiguration extends Configuration {

	private static final String remoteKey = "remote";

	@JsonProperty(remoteKey)
	private final RemoteConfiguration remote;

	@JsonCreator
	public MISPRemoteConfiguration(@JsonProperty(value = infoKey, required = true) RemoteInfo info,
			@JsonProperty(value = workerCountKey, required = true) int workerCount,
			@JsonProperty(value = workerDurationKey, required = true) CTIDuration workerDuration,
			@JsonProperty(value = nextWorkerKey, required = false) Timestamp nextWorker,
			@JsonProperty(value = remoteKey, required = true) RemoteConfiguration remote
			) {
		super(info, workerCount, workerDuration, nextWorker);
		this.remote = remote;
	}

	public MISPRemoteConfiguration(Configuration src, RemoteConfiguration remote) {
		this(src.getInfo(), src.getWorkerCount(), src.getWorkerDuration(), src.getNextWorker(), remote);
	}

	public RemoteConfiguration getRemote() {
		return remote;
	}


}
