/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.binding.os;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.util.Iterator;
import java.util.Map;

import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.OpenSearchException;
import org.opensearch.client.opensearch._types.mapping.TypeMapping;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.servlet.store.DbBase;
import com.cisa.taxii4j2.servlet.store.DbTaxiiBase;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
public class OSTaxii extends DbTaxiiBase {

	private ObjectNode mappings;

	@Inject
	public OSTaxii(DbBase db) throws IOException {

		super(db);

		mappings = JSON.factory.objectNode();
		try (InputStream in = OSTaxii.class.getResourceAsStream("mappings.json")) {
			Iterator<Map.Entry<String, JsonNode>> iField = JSON.readTree(new InputStreamReader(in)).fields();
			while (iField.hasNext()) {
				Map.Entry<String, JsonNode> field = iField.next();
				mappings.set(db.localizeIndexName(field.getKey()), field.getValue());
			}
		} catch (Exception e) {
			logger.warn("ES.init: couldn't load mappings, defaulting to empty object...");
		}

		allObjectIndices();
	}

	@Override
	public String createObjectIndex(String name) {
		try {
			try {
				db.client(OpenSearchClient.class).indices().get(c -> c.index(name));
			} catch (OpenSearchException e) {
				db.client(OpenSearchClient.class).indices().create(c -> {
					c = c.index(name);
					JsonNode mapping = mappings.get(name);
					if (mapping != null) {
						try {
							String properties = JSON
									.writeTreeAsString(JSON.factory.objectNode().set("properties", mapping));
							c = c.mappings(TypeMapping.of(t -> t.withJson(new StringReader(properties))));
						} catch (IOException e1) {
							throw new IllegalArgumentException(e1);
						}
					} else {
						logger.warn(String.format("no mapping for index %s", name));
					}
					return c;
				});
			}
		} catch (OpenSearchException | IOException e) {
			throw new IllegalStateException(e);
		}
		return name;
	}

}
