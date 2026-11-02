/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.admin;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.taxii4j2.client.job.taxii.remote.TAXIIRemoteConfiguration;
import com.cisa.taxii4j2.client.job.taxii.remote.TAXIIRemoteSnapshot;
import com.cisa.taxii4j2.data.Status;

public interface ClientJobAdmin {

	public static class JobStatus {

		private static final String uuidKey = "uuid";
		private static final String statusesKey = "statuses";

		@JsonProperty(uuidKey)
		private UUID uuid;

		@JsonProperty(statusesKey)
		private List<Status> statuses;

		public JobStatus(@JsonProperty(value = uuidKey, required = true) UUID uuid,
				@JsonProperty(value = statusesKey, required = true) List<Status> statuses) {
			super();
			this.uuid = uuid;
			this.statuses = statuses;
		}

		public JobStatus(UUID uuid) {
			super();
			this.uuid = uuid;
			this.statuses = new ArrayList<Status>();
		}

		public UUID getUuid() {
			return uuid;
		}

		public List<Status> getStatuses() {
			return statuses;
		}

		@JsonIgnore
		public JobStatus addStatus(Status status) {
			Status newStatus = new Status(status.getId(), status.getStatus(),
					status.getTotal_count(), status.getSuccess_count(), status.getFailure_count(), status.getPending_count(),
					status.getRequest_timestamp(), null, null, null);
			statuses.add(newStatus);
			return this;
		}

	}

	TAXIIRemoteConfiguration getConfiguration(String id);

	TAXIIRemoteConfiguration updateConfiguration(TAXIIRemoteConfiguration c, String id);

	List<TAXIIRemoteConfiguration> listConfigurations();

	TAXIIRemoteSnapshot getSnapshot(String id);

	TAXIIRemoteSnapshot updateSnapshot(TAXIIRemoteSnapshot s);

	List<TAXIIRemoteSnapshot> listSnapshots();

	void deleteConfiguration(String id);

	JobStatus getStatus(String id);

	JobStatus updateStatus(JobStatus s);

}
