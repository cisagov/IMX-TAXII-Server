/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.binding.os;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.lang3.math.NumberUtils;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.logging.log4j.Level;
import org.opensearch.client.json.JsonData;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.BuiltinScriptLanguage;
import org.opensearch.client.opensearch._types.FieldValue;
import org.opensearch.client.opensearch._types.OpenSearchException;
import org.opensearch.client.opensearch._types.ScriptLanguage;
import org.opensearch.client.opensearch._types.SortOrder;
import org.opensearch.client.opensearch._types.query_dsl.BoolQuery;
import org.opensearch.client.opensearch._types.query_dsl.MatchAllQuery;
import org.opensearch.client.opensearch._types.query_dsl.Query;
import org.opensearch.client.opensearch._types.query_dsl.RangeQuery;
import org.opensearch.client.opensearch.core.PutScriptResponse;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.core.search.Hit;
import org.opensearch.client.opensearch.core.search.HitsMetadata;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.CommonProperty;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.STIXIdentifier;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.data.impl.Storable;
import com.cisa.taxii4j2.data.impl.TAXIIConfig;
import com.cisa.taxii4j2.method.impl.Nexts;
import com.cisa.taxii4j2.method.impl.ObjectsBase;
import com.cisa.taxii4j2.servlet.store.DbBase;
import com.cisa.taxii4j2.servlet.store.DbTaxii;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotFoundException;

@Singleton
public class OSObjects extends ObjectsBase {

	@Inject
	public OSObjects(DbTaxii dbTaxii, Nexts nexts) {
		super(dbTaxii, nexts);
		logger.info("OSObjects<init>");
	}

	private static final int size = 128;

	@Override
	public Envelope read(String cId, Filters filters, long max_content_length) {

		try {
			UUID.fromString(cId);
		} catch (IllegalArgumentException e) {
			throw new InternalServerErrorException(String.format("OSObjects.read: %s not UUID", cId), e);
		}

		try {

			int limit = filters.getLimit();

			/*
			 * objects JSON going to be < 90% of max_content_length (to leave room for other
			 * decorators)...
			 */
			max_content_length /= 10;
			max_content_length *= 9;
			long content_length = 0;

			List<STIXObject> objects = new ArrayList<>();
			while (true) {

				Query query = groupQuery(build(dbBase, filters, new MatchAllQuery.Builder().build().toQuery(), cId));
				SearchResponse<STIXObject> response = dbBase.client(OpenSearchClient.class)
						.search(c -> c.index(new ArrayList<>(indices(filters))).query(query).size(size)
								.sort(s -> s.field(f -> f.field(STIXObject.date_addedKey(cId)).order(SortOrder.Asc))),
								STIXObject.class);
				HitsMetadata<STIXObject> hits = response.hits();
				if (hits.total().value() == 0) {
					return new Envelope(false, null, objects, cId);
				}

				Timestamp last = null;
				for (Hit<STIXObject> hit : hits.hits()) {

					STIXObject object = hit.source();
					List<STIXObject> filtered = filters.retainVersion(read(cId, object.getId()));

					if ((filtered != null) && !filtered.isEmpty()
							&& filtered.stream().anyMatch(o -> o.getVersion().equals(object.getVersion()))) {

						long hit_length = JSON.writeValueAsString(object).length();
						if (hit_length > max_content_length) {
							throw new IllegalArgumentException(String.format("%s/%s is %d - won't ever fit...",
									object.getId(), object.getVersion(), hit_length));
						}
						if (content_length + hit_length > max_content_length) {
							return new Envelope(true, null, objects, cId);
						}

						objects.add(object);
						if (objects.size() >= limit) {
							return new Envelope(true, null, objects, cId);
						}

						content_length += hit_length;

					}

					last = object.getDate_added(cId);

				}

				filters.setAdded_after(last);

			}
		} catch (OpenSearchException e) {
			logger.warn(e.response().toString());
			return new Envelope(null);
		} catch (Exception e) {
			logger.log(Level.WARN, "OSObjects.read", e);
			return new Envelope(null);
		}
	}

	/**
	 * Build out interop tiers 0, 1, 2, and 3; ref/refs; and calculated query
	 *
	 * @param cId     for added_after constraint
	 * @param filters query parameter map
	 * @param query   working query
	 * @return working query with new constraints
	 */
	public static Query build(DbBase dbBase, Filters filters, Query query, String... cIds) {
		Timestamp added_after = Timestamp.epoch;
		for (Map.Entry<String, Set<String>> entry : filters) {
			String key = entry.getKey();
			Set<String> values = entry.getValue();
			if (key.equals(Filters.added_afterKey)) {
				added_after = Timestamp.valueOf(values.iterator().next());
				continue;
			}
			String unmatched = Filters.unmatch(key);
			if ((unmatched == null) || unmatched.equals("version")) {
				continue;
			}
			if (Filters.tier3.containsKey(unmatched)) {
				query = build(dbBase, Filters.tier3.get(unmatched), values, query);
				continue;
			}
			if (Filters.tier0.contains(unmatched) || Filters.tier1.contains(unmatched)
					|| Filters.tier2.contains(unmatched)) {
				query = build(dbBase, unmatched, values, query);
				continue;
			}
			if (unmatched.equals(Filters.relationships_allKey)) {
				query = build(dbBase, values, query);
				continue;
			}
			String[] parts = Filters.parts(unmatched);
			if (parts != null) {
				query = build(parts, values, query);
				continue;
			}
		}
		BoolQuery.Builder builder = new BoolQuery.Builder().must(query);
		JsonData jsonData = JsonData.of(added_after);
		BoolQuery.Builder disjunct = new BoolQuery.Builder();
		for (String cId : cIds) {
			disjunct = disjunct.should(r -> r.range(d -> d.field(STIXObject.date_addedKey(cId)).gt(jsonData)));
		}
		return builder.must(disjunct.build().toQuery()).build().toQuery();
	}

	private static final Map<String, String> ops = Map.of("gte", "gte", "lte", "lte");

	/**
	 * Calculated match
	 *
	 * @param parts  field and operator
	 * @param values any of
	 * @param query  working query
	 * @return working query with new constraints
	 */
	public static Query build(String[] parts, Set<String> values, Query query) {
		try {
			Method method = RangeQuery.Builder.class.getMethod(ops.get(parts[1]), JsonData.class);
			String name = parts[0];
			BoolQuery.Builder disjunct = new BoolQuery.Builder();
			for (String value : values) {
				RangeQuery.Builder rqb = new RangeQuery.Builder().field(name);
				rqb = (RangeQuery.Builder) method.invoke(rqb, JsonData.of(value));
				disjunct = disjunct.should(rqb.build().toQuery());
			}
			return new BoolQuery.Builder().must(query).must(disjunct.build().toQuery()).build().toQuery();
		} catch (NoSuchMethodException | IllegalAccessException | IllegalArgumentException
				| InvocationTargetException e) {
			logger.log(Level.WARN, "OSObjects.build", e);
			return query;
		}
	}

	/**
	 * Value match
	 *
	 * @param key    field
	 * @param values any of
	 * @param query  working query
	 * @return working query with new constraints
	 */
	public static Query build(DbBase dbBase, String key, Set<String> values, Query query) {
		BoolQuery.Builder disjunct = new BoolQuery.Builder();
		for (String value : values) {
			disjunct = disjunct.should(
					d -> d.term(t -> t.field(NumberUtils.isCreatable(value) ? key : dbBase.keyword(key)).value(FieldValue.of(value))));
		}
		return new BoolQuery.Builder().must(query).must(disjunct.build().toQuery()).build().toQuery();
	}

	/**
	 * Reference match
	 *
	 * @param values any of
	 * @param query  working query
	 * @return working query with new constraints
	 */
	public static Query build(DbBase dbBase, Set<String> values, Query query) {
		BoolQuery.Builder disjunct = new BoolQuery.Builder();
		for (String ref : Filters.refs) {
			String name = dbBase.keyword(ref);
			for (String value : values) {
				disjunct = disjunct.should(d -> d.term(t -> t.field(name).value(FieldValue.of(value))));
			}
		}
		return new BoolQuery.Builder().must(query).must(disjunct.build().toQuery()).build().toQuery();
	}

	private static final String csParam = "date_added";

	private String createScriptId(String cId) {
		return String.format("c-%s", cId);
	}

	@Override
	public boolean create(STIXObject storable, String cId, boolean replace) {
		try {

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

			String scriptId = createScriptId(cId);
			try {
				create(prevObject, scriptId, date_added);
				return true;
			} catch (Exception e) {
				try {
					PutScriptResponse psr = dbBase.client(OpenSearchClient.class)
							.putScript(p -> p.id(scriptId)
									.script(s -> s.lang(ScriptLanguage.builder().builtin(BuiltinScriptLanguage.Painless).build())
											.source(String.format("ctx._source.%s = params['%s'];",
													STIXObject.date_addedKey(cId), csParam))));
					if (!psr.acknowledged()) {
						throw new InternalServerErrorException(
								String.format("OSObjects.delete[]: couldn't put delete script for %s", cId));
					}
					create(prevObject, scriptId, date_added);
					return true;
				} catch (Exception e1) {
					throw new InternalServerErrorException(e1);
				}
			}

		} catch (Exception e) {
			throw new InternalServerErrorException(e);
		}
	}

	private void create(STIXObject object, String scriptId, Timestamp date_added)
			throws OpenSearchException, IOException {
		dbBase.client(OpenSearchClient.class)
				.update(u -> u.index(dbTaxii.objectIndexName(object)).id(Storable.encodeId(object))
						.script(s -> s.stored(c -> c.id(scriptId).params(csParam, JsonData.of(date_added)))),
						STIXObject.class);
	}

	private String deleteScriptId(String cId) {
		return String.format("d-%s", cId);
	}

	private void delete(STIXObject o, String scriptId) throws OpenSearchException, IOException {
		dbBase.client(OpenSearchClient.class).update(u -> u.index(dbTaxii.objectIndexName(o))
				.id(Storable.encodeId(o)).script(s -> s.stored(ssId -> ssId.id(scriptId))), STIXObject.class);
	}

	@Override
	public void delete(String cId, List<STIXObject> objects) {
		String scriptId = deleteScriptId(cId);
		objects.stream().forEach(o -> {
			try {
				delete(o, scriptId);
			} catch (Exception e) {
				try {
					PutScriptResponse psr = dbBase.client(OpenSearchClient.class)
							.putScript(p -> p.id(scriptId)
									.script(s -> s.lang(ScriptLanguage.builder().builtin(BuiltinScriptLanguage.Painless).build())
									.source(String.format("ctx._source.%s = null;", STIXObject.date_addedKey(cId)))));
					if (!psr.acknowledged()) {
						throw new InternalServerErrorException(
								String.format("OSObjects.delete[]: couldn't put delete script for %s", cId));
					}
					delete(o, scriptId);
				} catch (Exception e1) {
					throw new InternalServerErrorException(e1);
				}
			}
		});
	}

	@Override
	public List<STIXObject> read(String cId, String oId) {
		try {
			List<String> indices = Arrays.asList(dbTaxii.objectIndexName(STIXIdentifier.getStixType(oId)));
			int size = TAXIIConfig.limitMax();
			BoolQuery.Builder builder = new BoolQuery.Builder();
			builder = builder
					.must(o -> o.term(t -> t.field(dbBase.keyword(CommonProperty.ID.getJsonKey())).value(FieldValue.of(oId))));
			builder = builder
					.must(d -> d.range(r -> r.field(STIXObject.date_addedKey(cId)).gte(JsonData.of(Timestamp.epoch))));
			Query query = groupQuery(builder.build().toQuery());
			List<STIXObject> objects = new ArrayList<>();
			while (true) {
				SearchResponse<STIXObject> response = dbBase.client(OpenSearchClient.class)
						.search(s -> s.index(indices).from(objects.size()).size(size).query(query), STIXObject.class);
				List<Hit<STIXObject>> hits = response.hits().hits();
				if (hits.isEmpty()) {
					java.util.Collections.sort(objects, (o0, o1) -> o0.getVersion().compareTo(o1.getVersion()));
					return objects;
				}
				hits.stream().map(h -> h.source()).forEach(o -> objects.add(o));
			}
		} catch (OpenSearchException e) {
			int status = e.status();
			if (status == HttpStatus.SC_NOT_FOUND) {
				return Collections.emptyList();
			}
			throw new ClientErrorException(status, e);
		} catch (IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

	protected Query groupQuery(Query query) {
		return query;
	}

}
