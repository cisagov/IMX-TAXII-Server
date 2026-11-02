/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.search;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.OpenSearchException;
import org.opensearch.client.opensearch._types.query_dsl.BoolQuery;
import org.opensearch.client.opensearch._types.query_dsl.MatchAllQuery;
import org.opensearch.client.opensearch._types.query_dsl.Query;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.core.search.Hit;
import org.opensearch.client.opensearch.core.search.HitsMetadata;
import org.opensearch.client.opensearch.core.search.TotalHits;
import org.opensearch.client.opensearch.core.search.TotalHitsRelation;

import com.cisa.taxii4j2.binding.os.OSObjects;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.servlet.store.DbBase;
import com.cisa.taxii4j2.servlet.store.DbTaxii;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.BadRequestException;

@Singleton
public class OSSearch implements Search {

	private final DbBase dbBase;
	private final DbTaxii dbTaxii;

	@Inject
	public OSSearch(DbTaxii dbTaxii) {
		super();
		this.dbTaxii = dbTaxii;
		this.dbBase = dbTaxii.getDb();
	}

	@Override
	public Founds search(Map<String, Set<String>> fcPairs, Filters filters, PagedQuery pqIn) {
		try {

			String[] cIds = fcPairs.values().stream().map(s -> s.stream()).flatMap(c -> c).collect(Collectors.toSet())
					.toArray(String[]::new);
			Query query = OSObjects.build(dbBase, filters, new MatchAllQuery.Builder().build().toQuery(), cIds);

			Integer from = pqIn.getFrom();
			if (from == null) {
				from = 0;
			} else if (from < 0) {
				throw new BadRequestException(String.format("from < 0"));
			}

			int limit = filters.getLimit();
			Integer size = pqIn.getSize();
			if((size == null) || (size > limit)) {
				size = limit;
			} else if(size < 0) {
				throw new BadRequestException(String.format("size < 0"));
			}

			PagedQuery pqOut = new PagedQuery(pqIn.getQuery(), from, size);

			query = new BoolQuery.Builder().must(query).must(q -> q.queryString(s -> s.query(pqOut.getQuery()))).build()
					.toQuery();
			final Query _query = query;
			SearchResponse<STIXObject> result = dbBase.client(OpenSearchClient.class)
					.search(c -> c.index(new ArrayList<>(OSObjects.indices(dbTaxii, filters))).query(_query)
							.from(pqOut.getFrom()).size(pqOut.getSize()), STIXObject.class);

			HitsMetadata<STIXObject> hits = result.hits();
			List<Found> founds = new ArrayList<>();
			for (Hit<STIXObject> hit : hits.hits()) {
				STIXObject object = hit.source();
				Map<String, Set<String>> hitFcPairs = new HashMap<>();
				for (String cId : object.getCIds()) {
					for (Map.Entry<String, Set<String>> fcPair : fcPairs.entrySet()) {
						if (fcPair.getValue().contains(cId)) {
							hitFcPairs.computeIfAbsent(fcPair.getKey(), k -> new HashSet<>()).add(cId);
						}
					}
				}
				founds.add(new Found(hit.score(), object.removeMyX_(), hitFcPairs));
			}

			TotalHits totalHits = hits.total();
			long total = totalHits.value();
			boolean truncated = totalHits.relation().equals(TotalHitsRelation.Gte);
			return new Founds(fcPairs, filters, pqOut, total, truncated, founds);

		} catch (OpenSearchException | IOException e) {
			throw new BadRequestException(e);
		}
	}

}
