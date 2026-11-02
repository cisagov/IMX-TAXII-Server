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

import com.cisa.taxii4j2.data.Status;
import com.cisa.taxii4j2.data.Status.Details;
import com.cisa.taxii4j2.data.Status.SFP;
import com.cisa.taxii4j2.method.impl.Statuses;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.InternalServerErrorException;

@Singleton
public class DbStatuses implements Statuses {

	private final String index;

	private final DbBase db;

	@Inject
	public DbStatuses(DbBase db) throws IOException {
		super();
		this.db = db;
		index = db.createIndex(db.localizeIndexName("statuses"));
	}

	@Override
	public Status read(String id) {
		return db.get(id, index, Status.class);
	}

	@Override
	public Status create(int pending) {
		String id = UUID.randomUUID().toString();
		return db.put(new Status(id, pending), index, id);
	}

	@Override
	public Status update(String id, SFP sfp, Details details) {
		Status status = db.get(id, index, Status.class);
		switch (sfp) {
		case success:
			status = status.success(details);
			break;
		case failure:
			status = status.failure(details);
			break;
		default:
			throw new InternalServerErrorException("ESStatusesWrite.update: not success or failure...");
		}
		db.put(status, index, id, false);
		return status;
	}

}
