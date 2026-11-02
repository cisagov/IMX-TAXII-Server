/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.impl;

import java.io.Closeable;
import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Filters;

public interface Nexts extends Closeable {

	public static final String prefix = "nexts";

	public static final Logger logger = LogManager.getLogger(Nexts.class);

	@Override
	default void close() throws IOException {

	}

	public Envelope create(boolean more, Timestamp last, String cId, Filters filters);

	public static class Entry {

		public static final String cIdKey = "cId";
		public static final String filtersKey = "filters";

		@JsonProperty(cIdKey)
		private final String cId;

		@JsonProperty(filtersKey)
		private final Filters filters;

		@JsonCreator
		public Entry(@JsonProperty(value = cIdKey, required = true) String cId,
				@JsonProperty(value = filtersKey, required = true) Filters filters) {
			super();
			this.cId = cId;
			this.filters = filters;
		}

		public String getcId() {
			return cId;
		}

		public Filters getFilters() {
			return filters;
		}

	}

	public Entry read(String next);

}
