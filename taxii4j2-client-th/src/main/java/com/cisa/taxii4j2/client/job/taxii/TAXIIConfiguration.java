/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job.taxii;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.cti4j2.CTIDuration;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.client.RemoteInfo;
import com.cisa.taxii4j2.client.job.Configuration;

@JsonInclude(Include.NON_NULL)
public class TAXIIConfiguration extends Configuration {

	protected static final String fragmentKey = "fragment";
	protected static final String cIdKey = "cId";
	protected static final String readTimeoutKey = "readTimeout";

	@JsonProperty(fragmentKey)
	private final String fragment;

	@JsonProperty(cIdKey)
	private final String cId;

	@JsonProperty(readTimeoutKey)
	private final Integer readTimeout;

	public TAXIIConfiguration(Configuration config, String fragment, String cId, Integer readTimeout) {
		this(config.getInfo(), fragment, cId, config.getWorkerCount(), config.getWorkerDuration(),
				config.getNextWorker(), readTimeout);
	}

	@JsonCreator
	public TAXIIConfiguration(@JsonProperty(value = infoKey, required = true) RemoteInfo info,
			@JsonProperty(value = fragmentKey, required = true) String fragment,
			@JsonProperty(value = cIdKey, required = true) String cId,
			@JsonProperty(value = workerCountKey, required = true) int workerCount,
			@JsonProperty(value = workerDurationKey, required = true) CTIDuration workerDuration,
			@JsonProperty(value = nextWorkerKey, required = false) Timestamp nextWorker,
			@JsonProperty(value = readTimeoutKey, required = false) Integer readTimeout) {
		super(info, workerCount, workerDuration, nextWorker);
		this.fragment = fragment;
		this.cId = cId;
		this.readTimeout = readTimeout;
	}

	public String getFragment() {
		return fragment;
	}

	public String getcId() {
		return cId;
	}

	public Integer getReadTimeout() {
		return readTimeout;
	}

}
