/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job.misp.remote;

import java.net.MalformedURLException;
import java.net.URI;

import com.cisa.taxii4j2.client.job.Configuration;
import com.cisa.taxii4j2.client.job.Snapshot;
import com.cisa.taxii4j2.client.job.misp.MISPClientJob;
import com.cisa.taxii4j2.client.job.misp.MISPSnapshot;
import com.cisa.taxii4j2.client.job.remote.RemoteConfiguration;
import com.cisa.taxii4j2.data.Envelope;

public class MISPRemoteClientJob extends MISPClientJob {

	private final RemoteConfiguration remote;

	public MISPRemoteClientJob(MISPRemoteConfiguration config, URI baseUri) throws MalformedURLException {
		super(config);
		this.remote = new RemoteConfiguration(config.getRemote(), baseUri);
	}

	@Override
	public Configuration getConfiguration() {
		return new MISPRemoteConfiguration(Configuration.class.cast(super.getConfiguration()), remote);
	}

	@Override
	public Snapshot getSnapshot() {
		return new MISPRemoteSnapshot(MISPSnapshot.class.cast(super.getSnapshot()), remote.getUuid());
	}

	@Override
	public void upsert() {
		remote.upsert(getSnapshot());
	}

	@Override
	public void accept(Envelope envelope) {
		remote.accept(envelope);
	}

}
