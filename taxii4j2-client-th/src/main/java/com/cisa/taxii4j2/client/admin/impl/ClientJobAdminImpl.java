/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.admin.impl;

import java.util.List;

import com.cisa.taxii4j2.client.admin.ClientJobAdmin;
import com.cisa.taxii4j2.client.job.taxii.remote.TAXIIRemoteConfiguration;
import com.cisa.taxii4j2.client.job.taxii.remote.TAXIIRemoteSnapshot;
import com.cisa.taxii4j2.servlet.store.DbBase;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.NotFoundException;

@Singleton
public class ClientJobAdminImpl implements ClientJobAdmin {

	private DbBase db;

	private String clientConfigurationIndex;
	private String clientSnapshotIndex;
	private String clientStatusIndex;

	@Inject
	public ClientJobAdminImpl(DbBase db) {
		this.db = db;
		this.clientConfigurationIndex = db.createIndex(db.localizeIndexName("clientConfiguration"));
		this.clientSnapshotIndex = db.createIndex(db.localizeIndexName("clientSnapshot"));
		this.clientStatusIndex = db.createIndex(db.localizeIndexName("clientStatus"));
	}

	@Override
	public TAXIIRemoteConfiguration getConfiguration(String id) {
		return db.get(id, clientConfigurationIndex, TAXIIRemoteConfiguration.class);
	}

	@Override
	public TAXIIRemoteConfiguration updateConfiguration(TAXIIRemoteConfiguration c, String id) {
		return db.put(c, clientConfigurationIndex, id);
	}

	@Override
	public List<TAXIIRemoteConfiguration> listConfigurations() {
		return db.list(clientConfigurationIndex, TAXIIRemoteConfiguration.class, DbBase.maxSize);
	}

	@Override
	public TAXIIRemoteSnapshot getSnapshot(String id) {
		return db.get(id, clientSnapshotIndex, TAXIIRemoteSnapshot.class);
	}

	@Override
	public TAXIIRemoteSnapshot updateSnapshot(TAXIIRemoteSnapshot s) {
		return db.put(s, clientSnapshotIndex, s.getUuid().toString());
	}

	@Override
	public List<TAXIIRemoteSnapshot> listSnapshots() {
		return db.list(clientSnapshotIndex, TAXIIRemoteSnapshot.class, DbBase.maxSize);
	}

	@Override
	public void deleteConfiguration(String id) {
		try {
			db.delete(id, clientSnapshotIndex, TAXIIRemoteSnapshot.class);
		} catch (NotFoundException e) { /* OK if the snapshot didn't exist */ }
		db.delete(id, clientConfigurationIndex, TAXIIRemoteConfiguration.class);
	}

	@Override
	public JobStatus getStatus(String id) {
		return db.get(id, clientStatusIndex, JobStatus.class);
	}

	@Override
	public JobStatus updateStatus(JobStatus s) {
		return db.put(s, clientStatusIndex, s.getUuid().toString());
	}
}
