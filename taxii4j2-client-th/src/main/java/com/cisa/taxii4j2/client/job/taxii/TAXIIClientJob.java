/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job.taxii;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.CTIDuration;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.client.RemoteInfo;
import com.cisa.taxii4j2.client.TAXIIClient;
import com.cisa.taxii4j2.client.job.ClientJob;
import com.cisa.taxii4j2.client.job.Configuration;
import com.cisa.taxii4j2.client.job.Snapshot;
import com.cisa.taxii4j2.client.job.WorkerParams;
import com.cisa.taxii4j2.client.job.taxii.remote.TAXIIRemoteSnapshot;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.data.Manifest;
import com.cisa.taxii4j2.method.response.EnvelopeResponse;
import com.cisa.taxii4j2.method.response.ManifestResponse;

/**
 * Provides "at least once" delivery of objects...it is likely that, especially
 * if stopped and restarted, objects will be duplicated. It is up to consumer to
 * cope, sorry...
 */
public class TAXIIClientJob extends ClientJob {

	public class TAXIIWorker extends Worker {

		private final TAXIIWorkerParams params;

		public TAXIIWorker(TAXIIWorkerParams params) {
			super();
			this.params = params;
			setEnvelope(objects());
		}

		@Override
		protected Envelope objects() {
			int retriesLeft = 3;
			long millis = 1000;
			Envelope envelope = null;
			while (--retriesLeft >= 0) {
				ManifestResponse manResponse = client.manifest(fragment, cId, params.getFilters(), null, readTimeout);
				Manifest manifest = manResponse.ok;
				if (manifest != null) {
					// figure out how many objects, if any, to get.
					int count = 0;
					List<Manifest.Record> records = manifest.getObjects();
					if (records != null) {
						for (Manifest.Record rec: records) {
							if (rec.getDate_added().compareTo(params.getEnd()) < 0)
								count++;
						}
					}
					if (count == 0) {
						envelope = new Envelope(null);
						break;
					} else {
						params.getFilters().setLimit(count);
					}
					EnvelopeResponse response = client.objects(fragment, cId, params.getFilters(), null, readTimeout);
					envelope = response.ok;
					if (envelope != null) {
						break;
					}
					Error error = response.error;
					if (error != null) {
						logger.debug(error.toString());
					} else {
						logger.fatal("response error was null!!!");
					}
				} else {
					logger.error("Error from manifest endpoint");
				}
				try {
					Thread.sleep(millis);
				} catch (InterruptedException e) {
//					logger.log(Level.WARNING, "ClientJob.Worker.objects", e);
				}
				millis <<= 1;
			}
			if (envelope == null) {
				logger.fatal(String.format("failed: %s", params.getFilters()));
				envelope = new Envelope(null);
			}
			// Update filters for next iteration
			if (!envelope.isEmpty()) {
				params.getFilters().setAdded_after(envelope.getLast());
				params.getFilters().setLimit(TAXIIWorkerParams.limit);
			}
			return envelope;
		}

		@Override
		protected WorkerParams getParams() {
			return params;
		}

	}

	private final TAXIIClient client;
	private final String fragment;
	private final String cId;
	private final Integer readTimeout;

	public Configuration getConfiguration() {
		return new TAXIIConfiguration(super.getConfiguration(), fragment, cId, readTimeout);
	}

	public TAXIIClientJob(TAXIIConfiguration config) {
		this(config.getInfo(), config.getFragment(), config.getcId(), config.getWorkerCount(),
				config.getWorkerDuration(), config.getNextWorker(), config.getReadTimeout());
	}

	public TAXIIClientJob(RemoteInfo info, String fragment, String cId, int workerCount, CTIDuration workerDuration,
			Timestamp nextWorker, Integer readTimeout) {

		super(info, workerCount, workerDuration, nextWorker);

		this.client = TAXIIClient.factory(info, false);
		this.fragment = fragment;
		this.cId = cId;
		this.readTimeout = readTimeout;

		if (nextWorker == null) {

			ManifestResponse response = client.manifest(fragment, cId,
					new Filters().setVersion(true, Filters.allKey).setLimit(1));
			Manifest manifest = response.ok;

			if (manifest != null) {
				List<Manifest.Record> objects = manifest.getObjects();
				nextWorker = ((objects != null) && !objects.isEmpty())
						? objects.get(0).getDate_added().minus(resolution())
						: Timestamp.epoch;
			} else {
				String error = response.error.toString();
				logger.fatal(error);
				throw new IllegalArgumentException(error);
			}
		}
		setNextWorker(nextWorker);

	}

	public TAXIIClientJob(TAXIIConfiguration configuration, Snapshot snapshot) {
		this(configuration);
		setSnapshot(snapshot);
	}

	@Override
	protected Configuration configurationFactory(RemoteInfo info, int workerCount, CTIDuration workerDuration,
			Timestamp nextWorker) {
		return new TAXIIConfiguration(new Configuration(info, workerCount, workerDuration, nextWorker), fragment, cId,
				readTimeout);
	}

	@Override
	protected Snapshot snapshotFactory(Set<WorkerParams> wps, Timestamp nextWorker) {
		return new TAXIISnapshot(
				(wps != null) ? wps.stream().map(wp -> TAXIIWorkerParams.class.cast(wp)).collect(Collectors.toSet())
						: null,
				nextWorker);
	}

	@Override
	protected Worker workerFactory(Timestamp begin, Timestamp end, WorkerParams wps) {
		TAXIIWorkerParams newWPS;
		if (wps instanceof TAXIIWorkerParams) {
			newWPS = new TAXIIWorkerParams(begin, end, ((TAXIIWorkerParams) wps).getFilters());
		} else {
			newWPS = new TAXIIWorkerParams(begin, end);
		}
		return new TAXIIWorker(newWPS);
	}

	@Override
	protected CTIDuration resolution() {
		return CTIDuration.ONE_NANO;
	}

	@Override
	protected Worker workerFactory(WorkerParams wps) {
		return new TAXIIWorker(TAXIIWorkerParams.class.cast(wps));
	}

	@Override
	public Snapshot remoteSnapshotFactory(JsonNode root) {
		try {
			return JSON.readValue(root, TAXIIRemoteSnapshot.class);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

}
