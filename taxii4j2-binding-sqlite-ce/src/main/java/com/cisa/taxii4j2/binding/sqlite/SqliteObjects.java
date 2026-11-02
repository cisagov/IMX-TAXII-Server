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
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.apache.commons.lang3.math.NumberUtils;
import org.apache.logging.log4j.Level;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.CommonProperty;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.STIXIdentifier;
import com.cisa.cti4j2.Timestamp;
import com.cisa.cti4j2.Type;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.data.impl.Storable;
import com.cisa.taxii4j2.data.impl.TAXIIConfig;
import com.cisa.taxii4j2.method.impl.Nexts;
import com.cisa.taxii4j2.method.impl.ObjectsBase;
import com.cisa.taxii4j2.servlet.store.DbTaxii;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotFoundException;

@Singleton
public class SqliteObjects extends ObjectsBase {

	@Inject
	public SqliteObjects(DbTaxii dbTaxii, Nexts nexts) {
		super(dbTaxii, nexts);
	}

	@Override
	public Envelope read(String cId, Filters filters, long max_content_length) {

		try {
			UUID.fromString(cId);
		} catch (IllegalArgumentException e) {
			throw new InternalServerErrorException(String.format("SqliteObjects.read: %s not UUID", cId), e);
		}

		try (Statement statement = dbBase.client(Connection.class).createStatement()) {

			int limit = filters.getLimit();
			List<STIXObject> objects = new ArrayList<>();
			Comparator<STIXObject> by_date_added = (o0, o1) -> o0.getDate_added(cId).compareTo(o1.getDate_added(cId));

			/*
			 * narrow tables to only those which could possibly return matches... these will
			 * be eaten away as tables return empty result sets...
			 */
			Set<String> names = filters.getN(Filters.typeKey);
			if ((names == null) || names.isEmpty()) {
				names = new HashSet<>(dbTaxii.allObjectIndices());
			}
			Set<String> ids = filters.getId();
			if ((ids != null) && !ids.isEmpty()) {
				names.retainAll(ids.stream().map(id -> STIXIdentifier.getStixType(id)).collect(Collectors.toSet()));
			}
			for (Map.Entry<String, Set<String>> entry : filters) {
				String property = Filters.unmatch(entry.getKey());
				if ((property == null) || property.equals(Filters.versionKey)) {
					continue;
				}
				String[] parts = Filters.parts(property);
				if (parts != null) {
					property = parts[0];
				}
				Set<Type> forProperty = Type.getTypes(property);
				if (forProperty != null) {
					names.retainAll(forProperty.stream().map(t -> t.toSTIXType()).collect(Collectors.toSet()));
					if (names.isEmpty()) {
						break;
					}
				}
			}
			if (names.isEmpty()) {
				return new Envelope(null);
			}

			String suffix = String.format("order by t0.%s ->> '$.%s' asc limit %d", SqliteBase.Column.SOURCE,
					STIXObject.date_addedKey(cId), limit << 1);

			/*
			 * these are the added_after filter parameters for each table. they will be
			 * eaten away as tables return empty result sets...
			 */
			Map<String, Timestamp> added_afters = new HashMap<>();
			Timestamp added_after = filters.getAdded_after();
			if (added_after != null) {
				for (String name : names) {
					added_afters.put(name, added_after);
				}
			}

			while (!names.isEmpty() && (objects.size() < limit)) {
				Iterator<String> iType = names.iterator();
				while (iType.hasNext()) {

					String type = iType.next();
					String query = query(cId, filters, type, added_afters.remove(type), suffix);
					logger.info(query);
					added_after = null;
					try (ResultSet rs = statement.executeQuery(query)) {
						while (rs.next()) {
							STIXObject object = JSON.readValue(rs.getString(1), STIXObject.class);
							added_after = object.getDate_added(cId);
							List<STIXObject> filtered = filters.retainVersion(read(cId, object.getId()));
							if ((filtered == null) || filtered.isEmpty()
									|| !filtered.stream().anyMatch(o -> o.getVersion().equals(object.getVersion()))) {
								continue;
							}
							objects.add(object);
						}
					}

					if (added_after != null) {
						/*
						 * there was at least one result
						 */
						added_afters.put(type, added_after);
					} else {
						/*
						 * table exhausted
						 */
						iType.remove();
					}
				}
			}

			Collections.sort(objects, by_date_added);
			int size = objects.size();
			return new Envelope(size >= limit, null, objects.subList(0, Math.min(limit, size)), cId);

		} catch (IOException | SQLException e) {
			logger.log(Level.WARN, "SqliteObjects.read", e);
			return new Envelope(null);
		}
	}

	private String query(String cId, Filters filters, String table, Timestamp added_after, String suffix) {

		List<String> tables = new ArrayList<>();
		tables.add(table);

		StringBuilder where = new StringBuilder();
		if (added_after != null) {
			where = SqliteBase.conjunct(where, "t0.", STIXObject.date_addedKey(cId), ">",
					SqliteBase.quote(added_after.toString()));
		}

		for (Map.Entry<String, Set<String>> entry : filters) {
			String key = entry.getKey();
			Set<String> values = entry.getValue();
			if (key.equals(Filters.added_afterKey)) {
				continue;
			}
			String unmatched = Filters.unmatch(key);
			if ((unmatched == null) || unmatched.equals(Filters.versionKey) || unmatched.equals(Filters.typeKey)) {
				continue;
			}
			if (Filters.tier3.containsKey(unmatched)) {
				where = build(Filters.tier3.get(unmatched), values, where);
				continue;
			}
			if (Filters.tier3Array.containsKey(unmatched)) {
				String[] parts = Filters.tier3Array.get(unmatched).split("\\.", 2);
				build(parts[0], parts[1], values, where, tables);
				continue;
			}
			if (Filters.tier0.contains(unmatched) || Filters.tier1.contains(unmatched)) {
				where = build(unmatched, values, where);
				continue;
			}
			if (Filters.tier2.contains(unmatched)) {
				build(unmatched, values, where, tables);
				continue;
			}
			if (unmatched.equals(Filters.relationships_allKey)) {
				where = build(values, where);
				continue;
			}
			String[] parts = Filters.parts(unmatched);
			if (parts != null) {
				where = build(parts, values, where);
				continue;
			}
		}

		String from = String.join(",", IntStream.range(0, tables.size())
				.mapToObj(i -> String.format("%s as t%d", tables.get(i), i)).collect(Collectors.toList()));
		return String.format("select distinct t0.%s from %s where %s %s", SqliteBase.Column.SOURCE, from, where,
				suffix);

	}

	private void build(String head, String tail, Set<String> values, StringBuilder where, List<String> tables) {
		int i = tables.size();
		tables.add(String.format("json_each(t0.%s ->> '$.%s')", SqliteBase.Column.SOURCE, head));
		where = SqliteBase.conjunct(where,
				String.format("t%d.value ->> '$.%s' %s %s", i, tail, SqliteBase.IN, build(values)));
	}

	/**
	 * any-of match
	 *
	 * @param unmatched key with array value
	 * @param values    match any
	 * @param where     clause to build on
	 * @param tables    joins
	 */
	private void build(String unmatched, Set<String> values, StringBuilder where, List<String> tables) {
		int i = tables.size();
		tables.add(String.format("json_each(t0.%s ->> '$.%s')", SqliteBase.Column.SOURCE, unmatched));
		where = SqliteBase.conjunct(where, String.format("t%d.value %s %s", i, SqliteBase.IN, build(values)));
	}

	/**
	 * Calculated match
	 *
	 * @param parts  field and operator
	 * @param values any of
	 * @param query  working query
	 * @return working query with new constraints
	 */
	private StringBuilder build(String[] parts, Set<String> values, StringBuilder queries) {

		if (values.isEmpty()) {
			throw new IllegalArgumentException("calculated filter must have at least one value...");
		}

		String key = parts[0];
		String op = parts[1];
		Optional<? extends Object> value = null;

		try {
			Stream<Number> numbers = values.stream().map(v -> NumberUtils.createNumber(v));
			Comparator<Number> c = (a, b) -> Double.compare(a.doubleValue(), b.doubleValue());
			if (op.equalsIgnoreCase(Filters.GTE)) {
				value = numbers.min(c);
			} else if (op.equals(Filters.LTE)) {
				value = numbers.max(c);
			} else {
				throw new IllegalArgumentException("bad/unknown calculated filter operator");
			}
		} catch (NumberFormatException e) {
			Comparator<String> c = (a, b) -> a.compareTo(b);
			if (op.equalsIgnoreCase(Filters.GTE)) {
				value = values.stream().min(c);
			} else if (op.equals(Filters.LTE)) {
				value = values.stream().max(c);
			} else {
				throw new IllegalArgumentException("bad/unknown calculated filter operator");
			}
		}

		return SqliteBase.conjunct(queries, "t0.", key, op.equalsIgnoreCase(Filters.GTE) ? " >= " : " <= ",
				SqliteBase.quote(value.get().toString()));
	}

	/**
	 * create list of SQL-safe values (presumably for imminent use of IN)
	 *
	 * @param values
	 * @return (quote(v0), quote(v1), ...)
	 */
	private String build(Set<String> values) {
		return String.format("(%s)",
				String.join(",", values.stream().map(v -> SqliteBase.quote(v)).collect(Collectors.toSet())));
	}

	/**
	 * Reference match
	 *
	 * @param values any of
	 * @param query  working query
	 * @return working query with new constraints
	 */
	private StringBuilder build(Set<String> values, StringBuilder queries) {
		String in = build(values);
		StringBuilder disjunct = new StringBuilder();
		for (String ref : Filters.refs) {
			StringBuilder clause = SqliteBase.where(new StringBuilder(), "", "t0.", ref, SqliteBase.IN, in.toString());
			SqliteBase.disjunct(disjunct, clause.toString());
		}
		return SqliteBase.conjunct(queries, disjunct.toString());
	}

	/**
	 * Value match
	 *
	 * @param key    field
	 * @param values any of
	 * @param query  working query
	 * @return working query with new constraints
	 */
	private StringBuilder build(String key, Set<String> values, StringBuilder queries) {
		StringBuilder clause = SqliteBase.where(new StringBuilder(), "", "t0.", key, SqliteBase.IN, build(values));
		return SqliteBase.conjunct(queries, clause.toString());
	}

	@Override
	public List<STIXObject> read(String cId, String oId) {
		String table = dbTaxii.objectIndexName(STIXIdentifier.getStixType(oId));
		int limit = TAXIIConfig.limitMax();
		StringBuilder where = SqliteBase.conjunct(new StringBuilder(), "", CommonProperty.ID.getJsonKey(),
				SqliteBase.quote(oId));
		List<STIXObject> objects = new ArrayList<>();
		int offset = 0;
		try (Statement statement = dbBase.client(Connection.class).createStatement()) {
			while (true) {
				String query = String.format("select %s from %s where %s limit %d offset %d", SqliteBase.Column.SOURCE,
						table, where, limit, offset);
				logger.info(query);
				try (ResultSet rs = statement.executeQuery(query)) {
					while (rs.next()) {
						objects.add(JSON.readValue(rs.getString(1), STIXObject.class));
					}
					int newSize = objects.size();
					if (newSize == offset) {
						return objects;
					}
					offset = newSize;
				}
			}
		} catch (IOException | SQLException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public boolean create(STIXObject storable, String cId, boolean replace) {

		String id = storable.getId();
		String version = storable.getVersion();
		String encodedId = Storable.encodeId(id, version);
		String index = dbTaxii.objectIndexName(storable);
		Timestamp date_added = new Timestamp();

		STIXObject prevObject = null;
		try {
			prevObject = dbBase.get(encodedId, index, STIXObject.class);
		} catch (NotFoundException e) {
			// OK
		}

		if (prevObject == null) {
			storable.setDate_added(cId, date_added);
			dbBase.put(storable, index, encodedId, true);
			return true;
		}

		if (replace && storable.isSCO()) {
			Iterator<Map.Entry<String, JsonNode>> iField = prevObject.asObjectNode().fields();
			while (iField.hasNext()) {
				Map.Entry<String, JsonNode> field = iField.next();
				String key = field.getKey();
				if (STIXObject.getCId(key) != null) {
					storable.asObjectNode().set(key, field.getValue());
				}
			}
			storable.setDate_added(cId, date_added);
			dbBase.put(storable, index, encodedId, false);
			return true;
		}

		if (prevObject.getDate_added(cId) != null) {
			return false;
		}

		try (Statement statement = dbBase.client(Connection.class).createStatement()) {
			String sql = String.format("update %s set %s=json_insert(%s,'$.%s','%s') where %s='%s'", index,
					SqliteBase.Column.SOURCE, SqliteBase.quote(JSON.writeValueAsString(prevObject)),
					STIXObject.date_addedKey(cId), date_added, SqliteBase.Column.ID, encodedId);
			logger.info(sql);
			int n = statement.executeUpdate(sql);
			if (n != 1) {
				throw new InternalServerErrorException(String.format("update %s failed?", encodedId));
			}
			return true;
		} catch (IOException | SQLException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public void delete(String cId, List<STIXObject> objects) {
		String key = STIXObject.date_addedKey(cId);
		try (Statement statement = dbBase.client(Connection.class).createStatement()) {
			objects.forEach(o -> {
				try {
					StringBuilder where = SqliteBase.conjunct(new StringBuilder(), "", CommonProperty.ID.getJsonKey(),
							o.getId());
					statement.executeUpdate(String.format(
							"update or ignore %s set %s=json_remove('%s','$.%s') where %s", dbTaxii.objectIndexName(o),
							SqliteBase.Column.SOURCE, JSON.writeValueAsString(o), key, where));
				} catch (IOException | SQLException e) {
					logger.log(Level.WARN, String.format("SqliteObjects.delete %s", Storable.encodeId(o)), e);
				}
			});
		} catch (SQLException e) {
			throw new InternalServerErrorException(e);
		}
	}

}
