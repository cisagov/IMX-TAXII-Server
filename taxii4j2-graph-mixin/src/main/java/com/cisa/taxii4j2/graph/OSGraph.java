/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.graph;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.FieldValue;
import org.opensearch.client.opensearch._types.query_dsl.BoolQuery;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.core.search.Hit;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.data.impl.Storable;
import com.cisa.taxii4j2.method.impl.Objects;
import com.cisa.taxii4j2.method.response.EnvelopeResponse;
import com.cisa.taxii4j2.servlet.store.DbBase;
import com.cisa.taxii4j2.servlet.store.DbTaxii;

import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;

public class OSGraph implements Graph {

	private final Objects objects;
	private final DbTaxii db;

	@Inject
	public OSGraph(Objects objects, DbTaxii db) {
		super();
		this.objects = objects;
		this.db = db;
	}

	@Override
	public EnvelopeResponse graph(String fragment, String cId, String oId, int n) {
		if (n <= 0) {
			return new EnvelopeResponse(new Error("n must be greater than 0", Response.Status.BAD_REQUEST));
		}
		try {
			return new EnvelopeResponse(
					new Envelope(false, null, traverse(new ArrayList<STIXObject>(), cId, last(cId, oId), n, 0), cId));
		} catch (Exception e) {
			return new EnvelopeResponse(new Error(e.getMessage(), Response.Status.BAD_REQUEST));
		}
	}

	private STIXObject last(String cId, String oId) {
		List<STIXObject> versions = objects.read(cId, oId);
		return !versions.isEmpty() ? versions.get(versions.size() - 1) : null;
	}

	private List<STIXObject> traverse(List<STIXObject> objects, String cId, STIXObject object, int n, int i)
			throws IOException {

		if (object == null) {
			/*
			 * must not have been able to find pointed-to object...
			 */
			return objects;
		}

		int index = Collections.binarySearch(objects, object);
		if (index >= 0) {
			/*
			 * been here, done that...
			 */
			return objects;
		}

		if (!collectionContains(cId, object)) {
			/*
			 * not in the specified collection
			 */
			return objects;
		}

		/*
		 * add
		 */
		objects.add(-index - 1, object.removeMyX_());

		/*
		 * attempt to prevent explosion from broadly shared objects...
		 */
		if ((++i > n) || Graph.terminal.contains(object.getStixType())) {
			return objects;
		}

		/*
		 * forward chain (objects that oId points to)
		 */
		JsonNode root = object.asObjectNode();
		for (String ref : Filters.refs) {
			JsonNode refNode = root.get(ref);
			if (refNode == null) {
				continue;
			}
			if (refNode.isArray()) {
				Iterator<JsonNode> iRef = refNode.elements();
				while (iRef.hasNext()) {
					traverse(objects, cId, last(cId, iRef.next().asText()), n, i);
				}
			} else {
				traverse(objects, cId, last(cId, refNode.asText()), n, i);
			}
		}

		/*
		 * backward chain (objects that point to oId)
		 */
		String oId = object.getId();
		BoolQuery.Builder builder = new BoolQuery.Builder();
		for (String ref : Filters.refs) {
			builder = builder.should(t -> t.term(f -> f.field(db.getDb().keyword(ref)).value(FieldValue.of(oId))));
		}
		BoolQuery query = builder.build();
		SearchResponse<STIXObject> response = db.getDb().client(OpenSearchClient.class).search(
				s -> s.index(new ArrayList<>(db.allObjectIndices())).query(query.toQuery()).size(DbBase.maxSize),
				STIXObject.class);
		for (Hit<STIXObject> hit : response.hits().hits()) {
			Storable pointsAtMe = hit.source();
			traverse(objects, cId, last(cId, pointsAtMe.getId()), n, i);
		}

		return objects;
	}

	private boolean collectionContains(String cId, STIXObject object) {
		return object.getDate_added(cId) != null;
	}

}
