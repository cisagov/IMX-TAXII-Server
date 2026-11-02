/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.store;

import java.util.List;

import com.cisa.taxii4j2.auth.data.Fragment;
import com.cisa.taxii4j2.auth.method.RootCollectionRead;
import com.cisa.taxii4j2.data.Collections.Collection;

import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;

public class DbRootCollectionRead implements RootCollectionRead {

	public static interface CollectionRead {
		public Collection readCollection(String id, DbBase db, String collectionIndex);
	}

	protected final String fragmentIndex;
	protected final String collectionIndex;

	protected final DbBase db;
	private final CollectionRead collectionRead;


	@Inject
	public DbRootCollectionRead(DbBase db, CollectionRead collectionRead) {
		super();
		this.db = db;
		this.collectionRead = collectionRead;
		fragmentIndex = db.createIndex(db.localizeIndexName("fragments"));
		collectionIndex = db.createIndex(db.localizeIndexName("collections"));
	}

	@Override
	public Fragment readFragment(String fragment) {
		try {
			return db.get(fragment, fragmentIndex, Fragment.class);
		} catch (NotFoundException e) {
			throw new NotFoundException(String.format("\"%s\" is an unknown api-root path", fragment), e);
		}
	}

	@Override
	public List<Fragment> listFragments() {
		return db.list(fragmentIndex, Fragment.class, DbBase.maxSize);
	}

	@Override
	public List<Collection> listCollections() {
		return db.list(collectionIndex, Collection.class, DbBase.maxSize);
	}

	@Override
	public Collection readCollection(String cId) {
		return collectionRead.readCollection(cId, db, collectionIndex);
	}

}
