/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job.remote;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.cisa.cti4j2.CTIMediaType;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.client.admin.ClientJobAdmin;
import com.cisa.taxii4j2.client.job.ClientJob;
import com.cisa.taxii4j2.client.job.Configuration;
import com.cisa.taxii4j2.client.job.Snapshot;
import com.cisa.taxii4j2.client.job.WorkerParams;
import com.cisa.taxii4j2.client.job.taxii.remote.TAXIIRemoteClientJob;
import com.cisa.taxii4j2.client.job.taxii.remote.TAXIIRemoteConfiguration;
import com.cisa.taxii4j2.client.job.taxii.remote.TAXIIRemoteSnapshot;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.method.TAXII;
import com.cisa.taxii4j2.method.impl.Objects;
import com.cisa.taxii4j2.method.response.StatusResponse;
import com.cisa.taxii4j2.servlet.EndpointUtils;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.UriInfo;

@Singleton
@Path("admin/v1.0/clientJob")
public class ClientJobEndpoint {

	@Context
	protected UriInfo uriInfo;

	protected final Map<UUID, ClientJob> jobs = new HashMap<>();

	public static class State {

		public final Configuration configuration;
		public final Snapshot snapshot;

		public State(Configuration configuration, Snapshot snapshot) {
			super();
			this.configuration = configuration;
			this.snapshot = snapshot;
		}

	}

	private ClientJobAdmin clientAdmin;
	private TAXII taxii;

	@Inject
	public ClientJobEndpoint(ClientJobAdmin admin, TAXII taxii) {
		this.clientAdmin = admin;
		this.taxii = taxii;
	}

	@GET
	@Path("list")
	@Produces(MediaType.APPLICATION_JSON)
	synchronized public List<State> list() {
		return jobs.values().stream().map(j -> new State(j.getConfiguration(), j.getSnapshot())).toList();
	}

	@POST
	@Path("taxii")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	synchronized public Response create(TAXIIRemoteConfiguration configuration) {
		UUID uuid = configuration.getRemote().getUuid();
		if (jobs.containsKey(uuid)) {
			logger.fatal(String.format("duplicate uuid: %s", uuid));
			return Response.status(Response.Status.BAD_REQUEST).build();
		}
		try {
			jobs.put(uuid, new TAXIIRemoteClientJob(configuration, uriInfo.getBaseUri()));
			clientAdmin.updateConfiguration(configuration, uuid.toString());
		} catch (Exception e) {
			logger.error("Error creating client job", e);
			int status = Status.INTERNAL_SERVER_ERROR.getStatusCode();
			try {
				status = JSON.readValue(e.getMessage(), Error.class).getStatusCode();
			} catch (Exception e1) {

			}
			return Response.status(status).build();
		}
		return Response.ok(jobs.get(uuid).getConfiguration(), MediaType.APPLICATION_JSON).build();
	}

	@POST
	@Path("snapshot")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	synchronized public Response set(JsonNode snapshot) {
		ClientJob job = jobs.get(UUID.fromString(snapshot.get(RemoteSnapshot.uuidKey).asText()));
		if (job == null) {
			return Response.status(Response.Status.NOT_FOUND).build();
		}
		try {
			job.setSnapshot(job.remoteSnapshotFactory(snapshot));
			clientAdmin.updateSnapshot((TAXIIRemoteSnapshot) job.getSnapshot());
		} catch (IllegalStateException | IllegalArgumentException e) {
			logger.error("Error creating snapshot", e);
			throw new BadRequestException(e);
		}
		return Response.ok(snapshot, MediaType.APPLICATION_JSON).build();
	}

	@GET
	@Path("{uuid}/configuration")
	@Produces(MediaType.APPLICATION_JSON)
	synchronized public Response getConfiguration(@PathParam("uuid") UUID uuid) {
		ClientJob job = jobs.get(uuid);
		if (job == null) {
			return Response.status(Response.Status.NOT_FOUND).build();
		}
		return Response.ok(job.getConfiguration(), MediaType.APPLICATION_JSON).build();
	}

	@GET
	@Path("{uuid}/snapshot")
	@Produces(MediaType.APPLICATION_JSON)
	synchronized public Response getSnapshot(@PathParam("uuid") UUID uuid) {
		ClientJob job = jobs.get(uuid);
		if (job == null) {
			return Response.status(Response.Status.NOT_FOUND).build();
		}
		return Response.ok(job.getSnapshot(), MediaType.APPLICATION_JSON).build();
	}

	@GET
	@Path("{uuid}/start")
	@Produces(MediaType.APPLICATION_JSON)
	synchronized public Response start(@PathParam("uuid") UUID uuid) {
		ClientJob job = jobs.get(uuid);
		if (job == null) {
			return Response.status(Response.Status.NOT_FOUND).build();
		}
		return Response.ok(job.start(), MediaType.APPLICATION_JSON).build();
	}

	@GET
	@Path("{uuid}/stop")
	@Produces(MediaType.APPLICATION_JSON)
	synchronized public Response stop(@PathParam("uuid") UUID uuid) {
		ClientJob job = jobs.get(uuid);
		if (job == null) {
			return Response.status(Response.Status.NOT_FOUND).build();
		}
		return Response.ok(job.stop(), MediaType.APPLICATION_JSON).build();
	}

	@GET
	@Path("{uuid}/isRunning")
	@Produces(MediaType.APPLICATION_JSON)
	synchronized public Response isRunning(@PathParam("uuid") UUID uuid) {
		ClientJob job = jobs.get(uuid);
		if (job == null) {
			return Response.status(Response.Status.NOT_FOUND).build();
		}
		return Response.ok(job.isRunning(), MediaType.APPLICATION_JSON).build();
	}

	@DELETE
	@Path("{uuid}")
	synchronized public Response delete(@PathParam("uuid") UUID uuid) {
		ClientJob job = jobs.remove(uuid);
		if (job == null) {
			return Response.status(Response.Status.NOT_FOUND).build();
		}
		try {
			job.close();
			clientAdmin.deleteConfiguration(uuid.toString());
		} catch (IOException e) {
			throw new InternalServerErrorException(e);
		}
		return Response.ok().build();
	}

	@GET
	@Path("{uuid}/status")
	public Response getStatus(@PathParam("uuid") UUID uuid) {
		return Response.ok(clientAdmin.getStatus(uuid.toString()), MediaType.APPLICATION_JSON).build();
	}

	@GET
	@Path("{uuid}/status/{statusUuid}")
	public Response getDetailedStatus(@PathParam("uuid") UUID uuid,
			@PathParam("statusUuid") UUID statusUuid) {
		TAXIIRemoteConfiguration config = (TAXIIRemoteConfiguration) jobs.get(uuid).getConfiguration();
		return config.getRemote().getStatusDetail(statusUuid);
	}

	protected static final Logger logger = LogManager.getLogger(ClientJobEndpoint.class);

	@POST
	@Path("upsert")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response upsert(String snapshot) {
		logger.debug(snapshot);
		return Response.ok().build();
	}

	@POST
	@Path("accept")
	@Consumes({MediaType.APPLICATION_JSON, CTIMediaType.TAXII2_1})
	public Response accept(String payload) {
		try {
			JsonNode json = JSON.readTree(payload);
			UUID uuid = UUID.fromString(json.get("uuid").textValue());
			String fragment = json.get("fragment").textValue();
			String cId = json.get("cId").textValue();
			ClientJob job = jobs.get(uuid);
			if (job == null) {
				return Response.status(Response.Status.NOT_FOUND).build();
			}
			logger.debug(String.format("ClientJobEndpoint.accept: fragment = %s, collection id = %s", fragment, cId));

			// Use the TAXII interface to create the objects
			Envelope envelope = JSON.readValue(json.get("envelope"), Envelope.class);
			StatusResponse status = taxii.postObjects(fragment, cId, envelope);
			if (status.ok != null) {
				while (status.ok.getStatus().equals("pending")) {
					try {
						Thread.sleep(Duration.ofSeconds(2).toMillis());
					} catch (InterruptedException e) { }
					status = taxii.status(fragment, status.ok.getId());
				}
			}
			return EndpointUtils.builder(status).build();
		} catch (IOException e) {
			logger.log(Level.FATAL, "ClientJobEndpoint.accept", e);
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
		}
	}

	public void load() {
		logger.info("Loading ClientJob configurations");

		// All remote configurations stored in the database should have full accept-info and upsert-info,
		// so we don't need to worry about the base URI in the TAXIIRemoteClientJob constructor.
		for (TAXIIRemoteConfiguration config: clientAdmin.listConfigurations()) {
			try {
				UUID uuid = config.getRemote().getUuid();
				jobs.put(uuid, new TAXIIRemoteClientJob(config, null));
			} catch (Exception e) {
				logger.error("Error loading TAXII client job from database", e);
			}
		}

		for (TAXIIRemoteSnapshot snap: clientAdmin.listSnapshots()) {
			UUID id = snap.getUuid();
			jobs.get(id).setSnapshot(snap);
		}

		// Start up any snapshots with a begin before now and end after now.
		Timestamp now = Timestamp.now();
		for (UUID uuid: jobs.keySet()) {
			if (jobs.get(uuid).getSnapshot().getWorkerParams() != null) {
				for (WorkerParams wp: jobs.get(uuid).getSnapshot().getWorkerParams()) {
					if ((wp.getBegin().compareTo(now) < 0) && (wp.getEnd().compareTo(now) > 0)) {
						jobs.get(uuid).start();
					}

				}
			}
		}

	}
}
