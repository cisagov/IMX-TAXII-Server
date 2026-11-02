/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job.misp;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.cisa.cti4j2.CTIDuration;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.STIXProperty;
import com.cisa.cti4j2.Timestamp;
import com.cisa.cti4j2.Type;
import com.cisa.taxii4j2.client.RemoteBearerBase;
import com.cisa.taxii4j2.client.RemoteInfo;
import com.cisa.taxii4j2.client.job.ClientJob;
import com.cisa.taxii4j2.client.job.Configuration;
import com.cisa.taxii4j2.client.job.Snapshot;
import com.cisa.taxii4j2.client.job.WorkerParams;
import com.cisa.taxii4j2.client.job.misp.remote.MISPRemoteSnapshot;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.impl.JSONBundle;
import com.cisa.taxii4j2.data.impl.JSONSTIXObject;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.misp.MISPClient;
import com.cisa.taxii4j2.misp.MISPEventSDO;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

public class MISPClientJob extends ClientJob {

	public class MISPWorker extends Worker {

		private final MISPWorkerParams params;

		public MISPWorker(MISPWorkerParams params) {
			super();
			this.params = params;
			setEnvelope(objects());
		}

		@Override
		protected Envelope objects() {
			int retriesLeft = 3;
			long millis = 1000;
			JsonNode root = null;
			while (--retriesLeft >= 0) {
				ObjectNode payload = params.getPayload().put(MISPClient.returnFormatKey, "json");
				logger.debug(String.format("restSearch payload: %s", payload));
				Response response = client.postHelper(payload, null, "events", "restSearch");
				int status = response.getStatus();
				if (status == Status.OK.getStatusCode()) {
					root = response.readEntity(JsonNode.class);
					break;
				} else {
					logger.warn(String.format("MISPWorker.objects: events %d", status));
				}
				try {
					Thread.sleep(millis);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				millis <<= 1;
			}
			Envelope envelope = new Envelope(null);
			if (root != null) {
				List<STIXObject> objects = new ArrayList<>();
				Iterator<JsonNode> iResponse = root.get(MISPClient.responseKey).iterator();
				while (iResponse.hasNext()) {
					JsonNode event = iResponse.next().get(MISPClient.eventKey);
					STIXObject misp = new MISPEventSDO(event);
					int eventid = event.get(MISPClient.idKey).asInt();
					JsonNode bundle = bundle(eventid);
					if (bundle == null) {
						logger.warn(String.format("couldn't get bundle for %d", eventid));
						continue;
					}
					Iterator<JsonNode> iObject = bundle.get(JSONBundle.objectsKey).elements();
					String object_refsKey = STIXProperty.OBJECT_REFS.getJsonKey();
					while (iObject.hasNext()) {
						STIXObject object = new JSONSTIXObject(iObject.next());
						if (!object.isCustom().isEmpty()) {
							continue;
						}
						if (object.getType() == Type.REPORT) {
							Iterator<JsonNode> iRef = object.asObjectNode().get(object_refsKey).elements();
							while (iRef.hasNext()) {
								if (iRef.next().asText().startsWith("x-")) {
									iRef.remove();
								}
							}
							object.asObjectNode().withArray(object_refsKey).add(misp.getId());
						}
						objects.add(object);
					}
					objects.add(misp);
				}
				if (!objects.isEmpty()) {
					Collections.sort(objects, (o0, o1) -> o0.getVersion().compareTo(o1.getVersion()));
					envelope = new Envelope(objects);
					Timestamp last = Timestamp.valueOf(objects.get(objects.size() - 1).getVersion());
					envelope.setFirstLast(Timestamp.valueOf(objects.get(0).getVersion()), last);
					params.setTimestamp(last.plus(resolution()));
				}
			}
			return envelope;
		}

		private JsonNode bundle(int eventid) {
			int retriesLeft = 3;
			long millis = 1000;
			JsonNode root = null;
			while (--retriesLeft >= 0) {
				ObjectNode payload = JSON.factory.objectNode().put(MISPClient.returnFormatKey, "stix2")
						.put(MISPClient.eventidKey, eventid);
				logger.debug(String.format("restSearch payload: %s", payload));
				Response response = client.postHelper(payload, null, "events", "restSearch");
				int status = response.getStatus();
				if (status == Status.OK.getStatusCode()) {
					root = response.readEntity(JsonNode.class);
					break;
				} else {
					logger.warn(String.format("MISPWorker.objects: events %d", status));
				}
				try {
					Thread.sleep(millis);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				millis <<= 1;
			}
			return root;
		}

		@Override
		protected WorkerParams getParams() {
			return params;
		}

	}

	private final RemoteBearerBase client;

	public MISPClientJob(Configuration config) {
		this(config.getInfo(), config.getWorkerCount(), config.getWorkerDuration(), config.getNextWorker());
	}

	public MISPClientJob(RemoteInfo info, int workerCount, CTIDuration workerDuration, Timestamp nextWorker) {
		super(info, workerCount, workerDuration, nextWorker);
		client = new RemoteBearerBase(info, MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);
		if (nextWorker == null) {
			ObjectNode payload = JSON.factory.objectNode().put(MISPClient.returnFormatKey, "json")
					.put(MISPClient.limitKey, 1);
			Response response = client.postHelper(payload, null, "events", "restSearch");
			if (response.getStatus() != Status.OK.getStatusCode()) {
				String message = null;
				try {
					message = JSON.writeValueAsString(new Error("no idea...", response.getStatus()));
				} catch (Exception e) {

				}
				throw new IllegalStateException(message);
			}
			JsonNode root = response.readEntity(JsonNode.class);
			Iterator<JsonNode> iResponse = root.get(MISPClient.responseKey).elements();
			JsonNode event = iResponse.hasNext() ? iResponse.next().get(MISPClient.eventKey) : null;
			setNextWorker(
					(event != null) ? new Timestamp(Instant.ofEpochSecond(event.get(MISPClient.timestampKey).asLong()))
							: Timestamp.epoch);
		}
	}

	public MISPClientJob(Configuration configuration, MISPSnapshot snapshot) {
		this(configuration);
		setSnapshot(snapshot);
	}

	@Override
	public void close() throws IOException {
		super.close();
		try {
			client.close();
		} catch (Exception e) {
			throw new IOException(e);
		}
	}

	@Override
	protected CTIDuration resolution() {
		return CTIDuration.ONE_SECOND;
	}

	@Override
	protected Configuration configurationFactory(RemoteInfo info, int workerCount, CTIDuration workerDuration,
			Timestamp nextWorker) {
		return new Configuration(info, workerCount, workerDuration, nextWorker);
	}

	@Override
	protected Snapshot snapshotFactory(Set<WorkerParams> wps, Timestamp nextWorker) {
		return new MISPSnapshot(
				(wps != null) ? wps.stream().map(wp -> MISPWorkerParams.class.cast(wp)).collect(Collectors.toSet())
						: null,
				nextWorker);
	}

	@Override
	protected Worker workerFactory(Timestamp begin, Timestamp end, WorkerParams wps) {
		return new MISPWorker(new MISPWorkerParams(begin, end));
	}

	@Override
	protected Worker workerFactory(WorkerParams wps) {
		return new MISPWorker(MISPWorkerParams.class.cast(wps));
	}

	@Override
	public void accept(Envelope envelope) {
		System.out.println(envelope);
	}

	@Override
	public Snapshot remoteSnapshotFactory(JsonNode root) {
		try {
			return JSON.readValue(root, MISPRemoteSnapshot.class);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

}
