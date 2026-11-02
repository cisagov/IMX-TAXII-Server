/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.store;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.cisa.cti4j2.CommonProperty;
import com.cisa.cti4j2.STIXIdentifier;
import com.cisa.cti4j2.Type;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.data.impl.Storable;

import jakarta.inject.Inject;

public abstract class DbTaxiiBase implements DbTaxii {

	protected final DbBase db;

	@Inject
	public DbTaxiiBase(DbBase db) {
		super();

		logger.info("DbTaxiiBase.<init>");

		this.db = db;
	}

	@Override
	public List<STIXObject> read(String id, int from, int size) {
		return db.search(Map.of(db.keyword(CommonProperty.ID.getJsonKey()), id), STIXObject.class, from, size,
				Collections.singletonList(objectIndexName(STIXIdentifier.getStixType(id))));
	}

	@Override
	public STIXObject read(String id, String version) {
		return db.get(Storable.encodeId(id, version), objectIndexName(STIXIdentifier.getStixType(id)),
				STIXObject.class);
	}

	@Override
	public DbBase getDb() {
		return db;
	}

	@Override
	public Set<String> allObjectIndices() {
		Set<String> allObjectIndices = new HashSet<>();
		for (Type type : Type.values()) {
			allObjectIndices.add(createObjectIndex(objectIndexName(type.toSTIXType())));
		}
		db.allIndices().stream().filter(i -> i.split(qualifierCustom).length == 2)
				.forEach(i -> allObjectIndices.add(i));
		return allObjectIndices;
	}

}
