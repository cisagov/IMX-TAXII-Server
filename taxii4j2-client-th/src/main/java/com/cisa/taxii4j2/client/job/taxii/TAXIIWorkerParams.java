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
import com.cisa.taxii4j2.client.job.WorkerParams;
import com.cisa.taxii4j2.data.Filters;

@JsonInclude(Include.NON_NULL)
public class TAXIIWorkerParams extends WorkerParams {

	private static final String filtersKey = "filters";

	@JsonProperty(filtersKey)
	private Filters filters;

	public static final int limit = 64;

	@JsonCreator
	public TAXIIWorkerParams(@JsonProperty(value = beginKey, required = true) Timestamp begin,
			@JsonProperty(value = endKey, required = true) Timestamp end,
			@JsonProperty(value = filtersKey, required = false) Filters filters) {
		super(begin, end);
		if (filters == null) {
			filters = new Filters().setAdded_after(begin.minus(CTIDuration.ONE_NANO)).setVersion(true, Filters.allKey)
					.setLimit(limit);
		}
		this.filters = filters;
	}

	public TAXIIWorkerParams(Timestamp begin, Timestamp end) {
		this(begin, end, null);
	}

	public Filters getFilters() {
		return filters;
	}

}
