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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.method.latency.LSConsumer;
import com.cisa.taxii4j2.method.latency.LatencyBase;
import com.cisa.taxii4j2.method.latency.LatencySample;
import com.cisa.taxii4j2.servlet.store.DbBase;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.InternalServerErrorException;

@Singleton
public class SqliteLSConsumer implements LSConsumer {

	private String index;
	private final DbBase db;

	@Inject
	public SqliteLSConsumer(DbBase db) {
		super();
		this.db = db;
	}

	@Override
	public void configure(Properties properties) {
		String value = properties.getProperty(NAME);
		if (value == null) {
			throw new IllegalArgumentException("SqliteHealthConsumer.configure: NAME must be specified");
		}
		index = db.createIndex(db.localizeIndexName(value));
	}

	@Override
	public void accept(LatencySample t) {
		db.put(t, index, t.getTimestamp().toString());
	}

	@Override
	public List<LatencySample> read(Instant end, Duration duration) {
		StringBuilder where = SqliteBase.conjunct(new StringBuilder(), "", LatencyBase.timestampKey, " < ",
				SqliteBase.quote(new Timestamp(end).toString()));
		where = SqliteBase.conjunct(where, "", LatencyBase.timestampKey, " >= ",
				SqliteBase.quote(new Timestamp(end.minus(duration)).toString()));
		try (Statement statement = db.client(Connection.class).createStatement()) {
			String query = String.format("select %s from %s where %s order by %s ->> '$.%s'", SqliteBase.Column.SOURCE,
					index, where, SqliteBase.Column.SOURCE, LatencyBase.timestampKey);
			logger.debug(query);
			try (ResultSet rs = statement.executeQuery(query)) {
				List<LatencySample> samples = new ArrayList<>();
				while (rs.next()) {
					samples.add(JSON.readValue(rs.getString(1), LatencySample.class));
				}
				return samples;
			}
		} catch (SQLException | IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

}
