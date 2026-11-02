/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.store;

import java.io.IOException;
import java.util.UUID;

import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.method.impl.Nexts;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.InternalServerErrorException;

@Singleton
public class DbNexts implements Nexts {

	private final String index;

	private final DbBase db;

	@Inject
	public DbNexts(DbBase db) throws IOException {
		super();
		this.db = db;
		index = db.createIndex(db.localizeIndexName("nexts"));
	}

	private Filters getFilters(String id) throws IOException {
		return db.get(id, index, Entry.class).getFilters();
	}

	@Override
	public Envelope create(boolean more, Timestamp last, String cId, Filters filters) {
		try {
			Envelope envelope = null;
			if (more) {
				Filters src = filters;
				String prev = src.getNext();
				if (prev != null) {
					src = getFilters(prev);
				}
				Filters dst = new Filters(src).setAdded_after(last);
				String curr = UUID.randomUUID().toString();
				db.put(new Entry(cId, dst), index, curr);
				envelope = new Envelope(true, curr, null, cId);
			} else {
				envelope = new Envelope(false, null, null, cId);
			}
			return envelope;
		} catch (IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public Entry read(String next) {
		return db.get(next, index, Entry.class);
	}

}
