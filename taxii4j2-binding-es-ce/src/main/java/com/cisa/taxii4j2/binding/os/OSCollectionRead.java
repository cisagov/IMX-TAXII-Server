/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.binding.os;

import java.io.IOException;

import org.apache.hc.core5.http.HttpStatus;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.FieldValue;
import org.opensearch.client.opensearch._types.OpenSearchException;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.core.search.HitsMetadata;

import com.cisa.taxii4j2.data.Collections.Collection;
import com.cisa.taxii4j2.servlet.store.DbBase;
import com.cisa.taxii4j2.servlet.store.DbRootCollectionRead;

import jakarta.inject.Singleton;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotFoundException;

@Singleton
public class OSCollectionRead implements DbRootCollectionRead.CollectionRead {

	@Override
	public Collection readCollection(String id, DbBase db, String collectionIndex) {
		try {
			SearchResponse<Collection> response = db.client(OpenSearchClient.class).search(
					c -> c.index(collectionIndex)
							.query(q -> q.bool(b -> b
									.should(t0 -> t0.term(i -> i.field(db.keyword(Collection.idKey)).value(FieldValue.of(id))))
									.should(t1 -> t1.term(a -> a.field(db.keyword(Collection.aliasKey)).value(FieldValue.of(id)))))),
					Collection.class);
			HitsMetadata<Collection> hits = response.hits();
			switch ((int) hits.total().value()) {
			case 0:
				throw new NotFoundException(String.format("\"%s\" is an unknown collection id or alias", id));
			case 1:
				return hits.hits().get(0).source();
			default:
				throw new InternalServerErrorException("ESAdmin.readCollection");
			}
		} catch (OpenSearchException e) {
			int status = e.status();
			if (status == HttpStatus.SC_NOT_FOUND) {
				throw new NotFoundException(e);
			}
			throw new ClientErrorException(status, e);
		} catch (IOException e) {
			throw new InternalServerErrorException(e);
		}
	}


}
