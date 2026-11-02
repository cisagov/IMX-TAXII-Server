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
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import org.apache.commons.lang3.math.NumberUtils;
import org.apache.commons.lang3.tuple.Pair;

import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.data.impl.TAXIIConfig;
import com.cisa.taxii4j2.servlet.store.DbBase;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotFoundException;

@Singleton
public class SqliteBase implements DbBase {

	public static enum Column {
		ID, SOURCE
	};

	private final Connection conn;
	private final String prefix;

	@Inject
	public SqliteBase() {
		super();
		try {
			conn = DriverManager.getConnection(SqliteConfig.getUrl());
		} catch (SQLException e) {
			throw new InternalServerErrorException(e);
		}
		prefix = legalizeIndexName(TAXIIConfig.taxii4j2UUID());
	}

	@Override
	public void close() throws Exception {
		conn.close();
	}

	@Override
	public <T> T client(Class<T> clazz) {
		return clazz.cast(conn);
	}

	@Override
	public String deleteIndex(String index) {
		try (Statement s = conn.createStatement()) {
			s.execute(String.format("drop table if exists %s", index));
			return index;
		} catch (SQLException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public String legalizeIndexName(String in) {
		return String.format("t_%s", in.replaceAll("[^a-zA-Z0-9_]", "_"));
	}

	@Override
	public String localizeIndexName(String index) {
		return legalizeIndexName(String.format("%s_%s", TAXIIConfig.taxii4j2UUID(), index));
	}

	@Override
	public String createIndex(String name) {
		try (Statement s = conn.createStatement()) {
			s.execute(String.format("create table if not exists %s (%s text, %s text, primary key(%s))", name,
					Column.ID, Column.SOURCE, Column.ID));
			return name;
		} catch (SQLException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public <T> T get(String id, String index, Class<T> clazz) {
		try (PreparedStatement s = conn
				.prepareStatement(String.format("select %s from %s where %s=?", Column.SOURCE, index, Column.ID))) {
			s.setString(1, id);
			logger.debug(s.toString());
			try (ResultSet rs = s.executeQuery()) {
				if (rs.next()) {
					return JSON.readValue(rs.getString(1), clazz);
				} else {
					throw new NotFoundException(String.format("id \"%s\" not found in index \"%s\"", id, index));
				}
			}
		} catch (IOException | SQLException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public <T> T put(T info, String index, String id, boolean create) {
		String qualifier = String.format("or %s", create ? "fail" : "replace");
		try (PreparedStatement s = conn
				.prepareStatement(String.format("insert %s into %s values(?,?)", qualifier, index))) {
			s.setString(1, id);
			s.setString(2, JSON.writeValueAsString(info));
			s.executeUpdate();
			return info;
		} catch (IOException | SQLException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public <T> T delete(String id, String index, Class<T> clazz) {
		try (PreparedStatement s = conn.prepareStatement(
				String.format("delete from %s where %s=? returning %s", index, Column.ID, Column.SOURCE))) {
			s.setString(1, id);
			logger.debug(s.toString());
			try (ResultSet rs = s.executeQuery()) {
				return rs.next() ? JSON.readValue(rs.getString(1), clazz) : null;
			}
		} catch (IOException | SQLException e) {
			throw new InternalServerErrorException(e);
		}
	}

	private static final int limit = 1024;

	@Override
	public <T> Map<String, T> map(String index, Class<T> clazz, Integer size) {
		Map<String, T> kvs = new HashMap<>();
		try (Statement s = conn.createStatement()) {
			String query = String.format("select %s,%s from %s order by %s limit %d", Column.ID, Column.SOURCE, index,
					Column.ID, (size != null) ? size : limit);
			logger.debug(query);
			try (ResultSet rs = s.executeQuery(query)) {
				while (rs.next()) {
					kvs.put(rs.getString(1), JSON.readValue(rs.getString(2), clazz));
				}
				return kvs;
			}
		} catch (IOException | SQLException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public <T, C extends Collection<T>> C collect(String index, Class<T> clazz, Supplier<C> ts, Integer size) {
		C c = ts.get();
		try (Statement s = conn.createStatement()) {
			String query = String.format("select %s from %s order by %s limit %d", Column.SOURCE, index, Column.ID,
					(size != null) ? size : limit);
			logger.debug(query);
			try (ResultSet rs = s.executeQuery(query)) {
				while (rs.next()) {
					c.add(JSON.readValue(rs.getString(1), clazz));
				}
				return c;
			}
		} catch (IOException | SQLException e) {
			throw new InternalServerErrorException(e);
		}
	}

	public static final String AND = " and ";
	public static final String OR = " or ";
	public static final String IN = " in ";

	public static StringBuilder conjunct(StringBuilder where, String prefix, String key, String value) {
		return where(where, AND, prefix, key, "=", value);
	}

	public static StringBuilder disjunct(StringBuilder where, String prefix, String key, String value) {
		return where(where, OR, prefix, key, "=", value);
	}

	public static StringBuilder conjunct(StringBuilder where, String prefix, String key, String op, String value) {
		return where(where, AND, prefix, key, op, value);
	}

	public static StringBuilder disjunct(StringBuilder where, String prefix, String key, String op, String value) {
		return where(where, OR, prefix, key, op, value);
	}

	public static StringBuilder conjunct(StringBuilder where, String clause) {
		return where(where, AND, clause);
	}

	public static StringBuilder disjunct(StringBuilder where, String clause) {
		return where(where, OR, clause);
	}

	public static StringBuilder where(StringBuilder where, String junct, String clause) {
		if (where.length() > 0) {
			where.append(junct);
		}
		return where.append(String.format("(%s)", clause));
	}

	private static final String TRUE = "1";
	private static final String FALSE = "0";

	public static String quote(String suffix) {
		if (suffix.equalsIgnoreCase(Boolean.TRUE.toString())) {
			return TRUE;
		}
		if (suffix.equalsIgnoreCase(Boolean.FALSE.toString())) {
			return FALSE;
		}
		return NumberUtils.isCreatable(suffix) ? suffix : String.format("'%s'", suffix.replaceAll("'", "''"));
	}

	public static StringBuilder where(StringBuilder where, String junct, String prefix, String key, String op,
			String value) {
		return where(where, junct,
				String.format("%s%s ->> '$.%s' %s %s", prefix, SqliteBase.Column.SOURCE, key, op, value));
	}

	@Override
	public <T> List<T> search(Map<String, String> kvs, Class<T> clazz, int from, int size, Collection<String> indices) {
		StringBuilder where = new StringBuilder();
		kvs.forEach((k, v) -> conjunct(where, "", k, SqliteBase.quote(v)));
		List<T> ts = new ArrayList<>();
		try (Statement statement = conn.createStatement()) {
			for (String table : indices) {
				String query = String.format("select %s from %s where %s", Column.SOURCE, table, where);
				logger.debug(query);
				try (ResultSet rs = statement.executeQuery(query)) {
					while (rs.next()) {
						ts.add(JSON.readValue(rs.getString(1), clazz));
					}
				}
			}
		} catch (IOException | SQLException e) {
			throw new InternalServerErrorException(e);
		}
		return ts;
	}

	@Override
	public <T> List<T> searchWithRange(Map<String, String> kvs, Map<String, Pair<Integer, Integer>> ranges,
			Class<T> clazz, int _size, Collection<String> indices) {
		StringBuilder where = new StringBuilder();
		kvs.forEach((k, v) -> conjunct(where, "", k, SqliteBase.quote(v)));
		ranges.forEach((k,v) -> conjunct(where, String.format("%s between %d and %d", k, v.getLeft(), v.getRight())));
		List<T> ts = new ArrayList<>();
		try (Statement statement = conn.createStatement()) {
			for (String table : indices) {
				String query = String.format("select %s from %s where %s", Column.SOURCE, table, where);
				logger.debug(query);
				try (ResultSet rs = statement.executeQuery(query)) {
					while (rs.next()) {
						ts.add(JSON.readValue(rs.getString(1), clazz));
					}
				}
			}
		} catch (IOException | SQLException e) {
			throw new InternalServerErrorException(e);
		}
		return ts;
	}

	@Override
	public void refresh(String... index) {

	}

	@Override
	public Set<String> allIndices() {
		Set<String> allIndices = new HashSet<>();
		try {
			try (ResultSet rs = conn.getMetaData().getTables(null, null, null, null)) {
				while (rs.next()) {
					String name = rs.getString("TABLE_NAME");
					if (name.startsWith(prefix)) {
						allIndices.add(name);
					}
				}
			}
		} catch (SQLException e) {
			throw new InternalServerErrorException(e);
		}
		return allIndices;
	}

}
