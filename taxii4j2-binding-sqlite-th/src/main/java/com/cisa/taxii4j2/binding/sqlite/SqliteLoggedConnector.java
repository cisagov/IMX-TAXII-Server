/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.binding.sqlite;

import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import com.cisa.cti4j2.JSON;
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
import jakarta.ws.rs.InternalServerErrorException;

@Singleton
public class SqliteLoggedConnector implements LogEntryConnector {

	private final AtomicInteger event_id;

	private final String requestIndex;
	private final String responseIndex;

	private final DbBase db;

	@Inject
	public SqliteLoggedConnector(DbBase db) throws IOException {

		super();

		this.db = db;
		requestIndex = db.createIndex(db.localizeIndexName("request-log-entries"));
		responseIndex = db.createIndex(db.localizeIndexName("response-log-entries"));
		logger.debug(String.format("requestIndex: %s, responseIndex: %s", requestIndex, responseIndex));

		int _event_id = 0;
		try (Statement statement = db.client(Connection.class).createStatement()) {
			String query = String.format("select max(cast(%s as int)) from %s", SqliteBase.Column.ID, requestIndex);
			logger.debug(query);
			try (ResultSet rs = statement.executeQuery(query)) {
				if (rs.next()) {
					_event_id = Integer.valueOf(rs.getString(1));
					logger.debug(String.format("selected event_id as %d...", _event_id));
				} else {
					logger.debug("empty select result set");
				}
			} catch (Exception e) {
				logger.debug(String.format("execption %s on select event_id...", e.getMessage()));
			}
		} catch (SQLException e) {
			throw new InternalServerErrorException(e);
		}
		logger.debug(String.format("setting event_id to %d...", _event_id));
		event_id = new AtomicInteger(_event_id);

	}

	@Override
	public int getEvent_id() {
		return event_id.incrementAndGet();
	}

	@Override
	public void append(LogEntry t) {
		String index = (t.getType() == LogEntryType.REQUEST) ? requestIndex : responseIndex;
		db.put(t, index, Integer.toString(t.getEvent_id()));
	}

	private static final String prefix = "t0";

	@Override
	public List<RequestLogEntry> readRequestLogEntry(LogEntryFilter filter) {
		StringBuilder where = new StringBuilder();
		String user_name = filter.getUser_name();
		if (user_name != null) {
			where = SqliteBase.conjunct(where, prefix, RequestLogEntry.user_nameKey, user_name);
		}
		Timestamp t0 = filter.getT0();
		Timestamp t1 = filter.getT1();
		if ((t0 != null) || (t1 != null)) {
			if (t0 != null) {
				where = SqliteBase.conjunct(where, prefix, LogEntry.timestampKey, " >= ", t0.toString());
			}
			if (t1 != null) {
				where = SqliteBase.conjunct(where, prefix, LogEntry.timestampKey, " < ", t1.toString());
			}
		}
		String path = filter.getPath();
		if (path != null) {
			where = SqliteBase.conjunct(where, prefix, RequestLogEntry.pathKey, path);
		}
		String method = filter.getMethod();
		if (method != null) {
			where = SqliteBase.conjunct(where, prefix, RequestLogEntry.methodKey, method);
		}
		String suffix = String.format("order by %s.%s ->> '$.%s' desc limit %d", prefix, SqliteBase.Column.SOURCE,
				LogEntry.timestampKey, filter.getSize());
		Integer from = filter.getFrom();
		if (from != null) {
			suffix += String.format(" offset %d", from);
		}
		try (Statement statement = db.client(Connection.class).createStatement()) {
			String query = String.format("select %s.%s from %s as %s where %s %s", prefix, SqliteBase.Column.SOURCE,
					requestIndex, prefix, where, suffix);
			logger.debug(query);
			try (ResultSet rs = statement.executeQuery(query)) {
				List<RequestLogEntry> entries = new ArrayList<>();
				while (rs.next()) {
					entries.add(JSON.readValue(rs.getString(1), RequestLogEntry.class));
				}
				return entries;
			}
		} catch (SQLException | IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public List<ResponseLogEntry> readResponseLogEntry(int... event_ids) {
		String in = String.format("(%s)", String.join(",",
				Arrays.stream(event_ids).mapToObj(id -> String.format("'%d'", id)).collect(Collectors.toList())));
		try (Statement statement = db.client(Connection.class).createStatement()) {
			String query = String.format("select %s from %s where %s in %s", SqliteBase.Column.SOURCE, responseIndex,
					SqliteBase.Column.ID, in);
			logger.debug(query);
			try (ResultSet rs = statement.executeQuery(query)) {
				List<ResponseLogEntry> entries = new ArrayList<>();
				while (rs.next()) {
					entries.add(JSON.readValue(rs.getString(1), ResponseLogEntry.class));
				}
				return entries;
			}
		} catch (SQLException | IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

}
