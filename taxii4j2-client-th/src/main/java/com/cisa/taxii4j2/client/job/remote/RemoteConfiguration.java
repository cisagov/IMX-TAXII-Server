/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job.remote;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.cisa.cti4j2.CTIMediaType;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.client.RemoteBearerBase;
import com.cisa.taxii4j2.client.RemoteInfo;
import com.cisa.taxii4j2.client.admin.ClientJobAdmin;
import com.cisa.taxii4j2.client.admin.ClientJobAdmin.JobStatus;
import com.cisa.taxii4j2.client.job.ClientJob;
import com.cisa.taxii4j2.client.job.Snapshot;
import com.cisa.taxii4j2.client.job.taxii.remote.TAXIIRemoteSnapshot;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Status;
import com.cisa.taxii4j2.data.impl.TAXIIConfig;

import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

@JsonInclude(Include.NON_NULL)
public class RemoteConfiguration {

	private static final String uuidKey = "uuid";
	private static final String upsertInfoKey = "upsert-info";
	private static final String acceptInfoKey = "accept-info";
	private static final String envelopeKey = "envelope";
	private static final String fragmentKey = "fragment";
	private static final String cIdKey = "cId";

	@JsonProperty(uuidKey)
	private final UUID uuid;

	@JsonProperty(upsertInfoKey)
	private final RemoteInfo upsertInfo;

	@JsonProperty(acceptInfoKey)
	private final RemoteInfo acceptInfo;

	@JsonProperty(fragmentKey)
	private final String fragment;

	@JsonProperty(cIdKey)
	private final String cId;

	@JsonIgnore
	private final RemoteBearerBase upsert;

	@JsonIgnore
	private final RemoteBearerBase accept;

	@JsonIgnore
	protected ClientJobAdmin admin;

	public RemoteConfiguration(RemoteConfiguration src, URI baseUri) throws MalformedURLException {
		this(src.uuid, (src.upsertInfo != null) ? src.upsertInfo
				: new RemoteInfo.None(UUID.randomUUID(),
						UriBuilder.fromUri(baseUri).path("admin").path("v1.0").path("clientJob").path("upsert").build().toURL(), null, null),
				(src.acceptInfo != null) ? src.acceptInfo
						: new RemoteInfo.None(UUID.randomUUID(),
								UriBuilder.fromUri(baseUri).path("admin").path("v1.0").path("clientJob").path("accept").build().toURL(), null,
								null),
			src.fragment, src.cId);

		try {
			admin = TAXIIConfig.serviceLocator().getService(ClientJobAdmin.class);
		} catch (Exception e) {
			ClientJob.logger.error("Error looking up ClientJobAdmin", e);
		}
	}

	@JsonCreator
	public RemoteConfiguration(@JsonProperty(value = uuidKey, required = true) UUID uuid,
			@JsonProperty(value = upsertInfoKey, required = false) RemoteInfo upsertInfo,
			@JsonProperty(value = acceptInfoKey, required = false) RemoteInfo acceptInfo,
			@JsonProperty(value = fragmentKey, required = true) String fragment,
			@JsonProperty(value = cIdKey, required = true) String cId) {
		super();
		this.uuid = uuid;
		this.upsertInfo = upsertInfo;
		upsert = (upsertInfo != null)
				? new RemoteBearerBase(this.upsertInfo, MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON)
				: null;
		// Should be able to put the media types in the acceptInfo somewhere, but hard coding for now.
		this.acceptInfo = acceptInfo;
		accept = (acceptInfo != null)
				? new RemoteBearerBase(this.acceptInfo, CTIMediaType.TAXII2_1, CTIMediaType.TAXII2_1)
				: null;
		this.fragment = fragment;
		this.cId = cId;
	}

	public UUID getUuid() {
		return uuid;
	}

	public RemoteInfo getUpsertInfo() {
		return upsertInfo;
	}

	public RemoteInfo getAcceptInfo() {
		return acceptInfo;
	}

	public String getFragment() {
		return fragment;
	}

	public String getcId() {
		return cId;
	}

	public void upsert(Snapshot snapshot) {
		if (upsert != null) {
			upsert.postHelper(snapshot, null);
			admin.updateSnapshot((TAXIIRemoteSnapshot) snapshot);
		} else {
			ClientJob.logger.warn(String.format("RemoteConfiguration.upsert: %s has null upserter...", getUuid()));
		}
	}

	public Status accept(Envelope envelope) {
		ClientJob.logger
				.debug(String.format("accept: %s <=> %s %d", envelope.getFirst(), envelope.getLast(), envelope.size()));
		if (accept != null) {
			try {
				ObjectNode payload = JSON.factory.objectNode()
						.put(uuidKey, uuid.toString())
						.put(fragmentKey, fragment)
						.put(cIdKey, cId)
						.set(envelopeKey, JSON.toJsonNode(envelope));
				// Not sure if there is a more concise way to do this than get the HTTP response and then parse the body.
				Response response = accept.postHelper(payload, null);
				ClientJob.logger.debug(String.format("accept response: %d", response.getStatus()));
				Status status = JSON.readValue(response.readEntity(String.class), Status.class);
				try {
					admin.updateStatus(admin.getStatus(uuid.toString()).addStatus(status));
				} catch (NotFoundException e) {
					admin.updateStatus(new JobStatus(uuid).addStatus(status));
				}
				return status;
			} catch (Exception e) {
				ClientJob.logger.error("Exception calling accept endpoint", e);
				return null;
			}
		} else {
			ClientJob.logger.warn(String.format("RemoteConfiguration.accept: %s has null accepter...", getUuid()));
			return null;
		}
	}

	public Response getStatusDetail(UUID statusUuid) {
		try {
			URL baseURL = new URL(acceptInfo.getUrl(), "/");
			WebTarget target = accept.target(baseURL.toString());
			Invocation invocation = accept.paths(target, null, CTIMediaType.TAXII2_1, null,
					"taxii/v2.1-os", fragment, "status", statusUuid.toString(), "/").buildGet();
			return invocation.invoke();
		} catch (Exception e) {
			ClientJob.logger.error(String.format("Error getting status detail %s from remote server", statusUuid.toString()), e);
			return Response.serverError().build();
		}
	}

	@Override
	public String toString() {
		try {
			return JSON.writeValueAsString(this);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

}
