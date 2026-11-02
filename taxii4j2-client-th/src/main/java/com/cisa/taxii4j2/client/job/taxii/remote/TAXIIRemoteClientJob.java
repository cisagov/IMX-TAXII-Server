/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job.taxii.remote;

import java.net.MalformedURLException;
import java.net.URI;

import com.cisa.taxii4j2.client.job.Configuration;
import com.cisa.taxii4j2.client.job.Snapshot;
import com.cisa.taxii4j2.client.job.remote.RemoteConfiguration;
import com.cisa.taxii4j2.client.job.taxii.TAXIIClientJob;
import com.cisa.taxii4j2.client.job.taxii.TAXIIConfiguration;
import com.cisa.taxii4j2.client.job.taxii.TAXIISnapshot;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Status;

public class TAXIIRemoteClientJob extends TAXIIClientJob {

	private final RemoteConfiguration remote;

	public TAXIIRemoteClientJob(TAXIIRemoteConfiguration config, URI baseUri) throws MalformedURLException {
		super(config);
		this.remote = new RemoteConfiguration(config.getRemote(), baseUri);
	}

	@Override
	public Configuration getConfiguration() {
		return new TAXIIRemoteConfiguration(TAXIIConfiguration.class.cast(super.getConfiguration()), remote);
	}

	@Override
	public Snapshot getSnapshot() {
		return new TAXIIRemoteSnapshot(TAXIISnapshot.class.cast(super.getSnapshot()), remote.getUuid());
	}

	@Override
	public void upsert() {
		remote.upsert(getSnapshot());
	}

	@Override
	public void accept(Envelope envelope) {
		Status status = remote.accept(envelope);
		// Send the status to the upsert endpoint.
		TAXIIRemoteSnapshot snapshot = (TAXIIRemoteSnapshot) getSnapshot();
		snapshot.setStatus(status);
		remote.upsert(snapshot);
	}

}
