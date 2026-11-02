/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.search;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.data.impl.STIXObject;

public interface Search {

	public static class Found {

		private final Double score;
		private final STIXObject object;
		private final Map<String, Set<String>> fcPairs;

		public Found(Double score, STIXObject object, Map<String, Set<String>> fcPairs) {
			super();
			this.score = score;
			this.object = object;
			this.fcPairs = fcPairs;
		}

		public Double getScore() {
			return score;
		}

		public STIXObject getObject() {
			return object;
		}

		public Map<String, Set<String>> getFcPairs() {
			return fcPairs;
		}

	}

	@JsonInclude(Include.NON_NULL)
	public static class PagedQuery {

		private static final String queryKey = "query";
		private static final String fromKey = "from";
		private static final String sizeKey = "size";

		@JsonProperty(queryKey)
		private final String query;

		@JsonProperty(fromKey)
		private final Integer from;

		@JsonProperty(sizeKey)
		private final Integer size;

		@JsonCreator
		public PagedQuery(@JsonProperty(value = queryKey, required = true) String query,
				@JsonProperty(value = fromKey, required = false) Integer from,
				@JsonProperty(value = sizeKey, required = false) Integer size) {
			super();
			this.query = query;
			this.from = from;
			this.size = size;
		}

		public String getQuery() {
			return query;
		}

		public Integer getFrom() {
			return from;
		}

		public Integer getSize() {
			return size;
		}

	}

	public static class Founds {

		private final Map<String, Set<String>> fcPairs;
		private final Filters filters;
		private final PagedQuery query;
		private final long total;
		private final boolean truncated;
		private final List<Found> founds;

		public Founds(Map<String, Set<String>> fcPairs, Filters filters, PagedQuery query, long total,
				boolean truncated, List<Found> founds) {
			super();
			this.fcPairs = fcPairs;
			this.filters = filters;
			this.query = query;
			this.total = total;
			this.truncated = truncated;
			this.founds = founds;
		}

		public long getTotal() {
			return total;
		}

		public Map<String, Set<String>> getFcPairs() {
			return fcPairs;
		}

		public Filters getFilters() {
			return filters;
		}

		public PagedQuery getQuery() {
			return query;
		}

		public boolean isTruncated() {
			return truncated;
		}

		public List<Found> getFounds() {
			return founds;
		}
	}

	// TODO - these don't respect version restrictions (yet)...

	default public Founds search(String fragment, String cId, Filters filters, PagedQuery query) {
		return search(Map.of(fragment, Collections.singleton(cId)), filters, query);
	}

	public Founds search(Map<String, Set<String>> fcPairs, Filters filters, PagedQuery query);

}
