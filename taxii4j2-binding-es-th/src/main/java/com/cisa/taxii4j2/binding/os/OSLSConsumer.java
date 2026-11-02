/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.binding.os;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;

import org.opensearch.client.json.JsonData;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.OpenSearchException;
import org.opensearch.client.opensearch._types.SortOrder;
import org.opensearch.client.opensearch.core.SearchResponse;

import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.method.latency.LSConsumer;
import com.cisa.taxii4j2.method.latency.LatencyBase;
import com.cisa.taxii4j2.method.latency.LatencySample;
import com.cisa.taxii4j2.servlet.store.DbBase;

import jakarta.inject.Inject;

public class OSLSConsumer implements LSConsumer {

	private String index;

	private final DbBase db;

	@Inject
	public OSLSConsumer(DbBase db) {
		super();
		this.db = db;
	}

	@Override
	public void configure(Properties properties) {
		String value = properties.getProperty(NAME);
		if (value == null) {
			throw new IllegalArgumentException("ESHealthConsumer.configure: NAME must be specified");
		}
		index = db.createIndex(db.localizeIndexName(value));
	}

	@Override
	public void accept(LatencySample t) {
		db.put(t, index, t.getTimestamp().toString());
	}

	@Override
	public List<LatencySample> read(Instant end, Duration duration) {
		try {
			SearchResponse<LatencySample> samples = db.client(OpenSearchClient.class).search(s -> s.index(index).size(4096)
					.sort(t -> t.field(f -> f.field(LatencyBase.timestampKey).order(SortOrder.Asc)))
					.query(q -> q.range(r -> r.field(LatencyBase.timestampKey)
							.gte(JsonData.of(new Timestamp(end.minus(duration)))).lt(JsonData.of(new Timestamp(end))))),
					LatencySample.class);
			return samples.hits().hits().stream().map(s -> s.source()).collect(Collectors.toList());
		} catch (OpenSearchException | IOException e) {
			return Collections.emptyList();
		}
	}

}
