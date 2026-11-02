/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.binding.sqlite;

import com.cisa.taxii4j2.servlet.store.DbBase;
import com.cisa.taxii4j2.servlet.store.DbTaxiiBase;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
public class SqliteTaxii extends DbTaxiiBase {

	@Inject
	public SqliteTaxii(DbBase db) {
		super(db);
		/*
		 * force creation of all object indices...
		 */
		allObjectIndices();
	}

	@Override
	public String createObjectIndex(String name) {
		return db.createIndex(name);
	}

}
