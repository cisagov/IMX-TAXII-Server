/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.binding.os;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.apache.hc.core5.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.json.JsonData;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.FieldValue;
import org.opensearch.client.opensearch._types.OpenSearchException;
import org.opensearch.client.opensearch._types.SortOrder;
import org.opensearch.client.opensearch._types.query_dsl.BoolQuery;
import org.opensearch.client.opensearch._types.query_dsl.RangeQuery;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.core.search.HitsMetadata;

import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.method.logging.LogEntry;
import com.cisa.taxii4j2.method.logging.LogEntryConnector;
import com.cisa.taxii4j2.method.logging.LogEntryFilter;
import com.cisa.taxii4j2.method.logging.LogEntryType;
import com.cisa.taxii4j2.method.logging.RequestLogEntry;
import com.cisa.taxii4j2.method.logging.ResponseLogEntry;
import com.cisa.taxii4j2.servlet.store.DbBase;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.InternalServerErrorException;

@Singleton
public class OSLoggedConnector implements LogEntryConnector {

	private final AtomicInteger event_id;

	private final String requestIndex;
	private final String responseIndex;

	private static final Logger logger = LogManager.getLogger(OSLoggedConnector.class);

	private final DbBase db;

	@Inject
	public OSLoggedConnector(DbBase db) throws IOException {

		super();

		this.db = db;
		requestIndex = db.localizeIndexName("request-log-entries");
		responseIndex = db.localizeIndexName("response-log-entries");

		logger.info(String.format("requestIndex: %s, responseIndex: %s", requestIndex, responseIndex));
		int _event_id = 0;
		try {
			SearchResponse<RequestLogEntry> response = db.client(OpenSearchClient.class)
					.search(c -> c.index(requestIndex).size(1)
							.sort(s -> s.field(f -> f.field(RequestLogEntry.event_idKey).order(SortOrder.Desc))),
							RequestLogEntry.class);
			HitsMetadata<RequestLogEntry> hits = response.hits();
			if (hits.total().value() > 0) {
				_event_id = hits.hits().get(0).source().getEvent_id();
			}
		} catch (OpenSearchException e) {
			if (e.status() != HttpStatus.SC_NOT_FOUND) {
				e.printStackTrace();
			}
		}
		event_id = new AtomicInteger(_event_id);

	}

	@Override
	public void append(LogEntry t) {
		String index = (t.getType() == LogEntryType.REQUEST) ? requestIndex : responseIndex;
		try {
			db.put(t, index, Integer.toString(t.getEvent_id()));
		} catch (Exception e) {
			logger.error("Error writing log message to " + index, e);
		}
	}

	@Override
	public int getEvent_id() {
		return event_id.incrementAndGet();
	}

	@Override
	public List<RequestLogEntry> readRequestLogEntry(LogEntryFilter filter) {
		try {
			BoolQuery.Builder query = new BoolQuery.Builder();
			String user_name = filter.getUser_name();
			if (user_name != null) {
				query = query
						.must(q -> q.term(t -> t.field(db.keyword(RequestLogEntry.user_nameKey)).value(FieldValue.of(user_name))));
			}
			Timestamp t0 = filter.getT0();
			Timestamp t1 = filter.getT1();
			if ((t0 != null) || (t1 != null)) {
				RangeQuery.Builder range = new RangeQuery.Builder().field(LogEntry.timestampKey);
				if (t0 != null) {
					range = range.gte(JsonData.of(t0));
				}
				if (t1 != null) {
					range = range.lt(JsonData.of(t1));
				}
				query = query.must(range.build().toQuery());
			}
			String path = filter.getPath();
			if (path != null) {
				query = query.must(q -> q.match(m -> m.field(RequestLogEntry.pathKey).query(FieldValue.of(path))));
			}
			String method = filter.getMethod();
			if (method != null) {
				query = query.must(q -> q.term(t -> t.field(db.keyword(RequestLogEntry.methodKey)).value(FieldValue.of(method))));
			}
			SearchRequest.Builder request = new SearchRequest.Builder().index(requestIndex).size(filter.getSize())
					.sort(s -> s.field(f -> f.field(LogEntry.timestampKey).order(SortOrder.Desc)))
					.query(query.build().toQuery());
			Integer from = filter.getFrom();
			if (from != null) {
				request = request.from(from);
			}
			SearchResponse<RequestLogEntry> response = db.client(OpenSearchClient.class).search(request.build(), RequestLogEntry.class);
			return response.hits().hits().stream().map(h -> h.source()).collect(Collectors.toList());
		} catch(OpenSearchException e) {
			int status = e.status();
			if(status == HttpStatus.SC_NOT_FOUND) {
				return Collections.emptyList();
			}
			throw new ClientErrorException(status, e);
		} catch (IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public List<ResponseLogEntry> readResponseLogEntry(int... event_ids) {
		if (event_ids.length == 0) {
			return Collections.emptyList();
		}
		if (event_ids.length > LogEntryFilter.maxSize) {
			throw new IllegalArgumentException();
		}
		try {
			BoolQuery.Builder builder = new BoolQuery.Builder();
			for (int event_id : event_ids) {
				builder = builder
						.should(q -> q.term(t -> t.field(LogEntry.event_idKey).value(FieldValue.of(event_id))));
			}
			BoolQuery query = builder.build();
			SearchResponse<ResponseLogEntry> response = db.client(OpenSearchClient.class)
					.search(s -> s.index(responseIndex).query(query.toQuery())
							.sort(o -> o.field(f -> f.field(LogEntry.timestampKey).order(SortOrder.Asc))),
							ResponseLogEntry.class);
			return response.hits().hits().stream().map(h -> h.source()).collect(Collectors.toList());
		} catch(OpenSearchException e) {
			int status = e.status();
			if(status == HttpStatus.SC_NOT_FOUND) {
				return Collections.emptyList();
			}
			throw new ClientErrorException(status, e);
		} catch (IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

}
