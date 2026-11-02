/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.data.impl.CustomFields;

import jakarta.ws.rs.InternalServerErrorException;

@JsonInclude(Include.NON_NULL)
public class Status extends CustomFields {

	public enum SFP {
		success, failure, pending, complete
	}

	protected static final String idKey = "id";
	protected static final String statusKey = "status";
	protected static final String total_countKey = "total_count";
	protected static final String success_countKey = "success_count";
	protected static final String failure_countKey = "failure_count";
	protected static final String pending_countKey = "pending_count";

	protected static final String request_timestampKey = "request_timestamp";
	protected static final String successesKey = "successes";
	protected static final String failuresKey = "failures";
	protected static final String pendingsKey = "pendings";

	@JsonProperty(idKey)
	private final String id;

	@JsonProperty(statusKey)
	private String status;

	@JsonProperty(total_countKey)
	private int total_count;

	@JsonProperty(success_countKey)
	private int success_count;

	@JsonProperty(failure_countKey)
	private int failure_count;

	@JsonProperty(pending_countKey)
	private int pending_count;

	@JsonProperty(request_timestampKey)
	private Timestamp request_timestamp;

	@JsonProperty(successesKey)
	private List<Details> successes;

	@JsonProperty(failuresKey)
	private List<Details> failures;

	@JsonProperty(pendingsKey)
	private List<Details> pendings;

	public Status(String id, int pending) {
		this(id, ((pending > 0) ? SFP.pending : SFP.complete).name(), pending, 0, 0, pending, new Timestamp(), null,
				null, null);
	}

	@JsonCreator
	public Status(@JsonProperty(value = idKey, required = true) String id,
			@JsonProperty(value = statusKey, required = true) String status,
			@JsonProperty(value = total_countKey, required = true) int total_count,
			@JsonProperty(value = success_countKey, required = true) int success_count,
			@JsonProperty(value = failure_countKey, required = true) int failure_count,
			@JsonProperty(value = pending_countKey, required = true) int pending_count,
			@JsonProperty(value = request_timestampKey, required = false) Timestamp request_timestamp,
			@JsonProperty(value = successesKey, required = false) List<Details> successes,
			@JsonProperty(value = failuresKey, required = false) List<Details> failures,
			@JsonProperty(value = pendingsKey, required = false) List<Details> pendings) {
		super(Status.class);
		this.id = id;
		this.status = status;
		this.total_count = total_count;
		this.success_count = success_count;
		this.failure_count = failure_count;
		this.pending_count = pending_count;
		this.request_timestamp = request_timestamp;
		this.successes = successes;
		this.failures = failures;
		this.pendings = pendings;
	}

	@JsonInclude(Include.NON_NULL)
	public static class Details extends CustomFields {

		private static final String idKey = "id";
		private static final String versionKey = "version";
		private static final String messageKey = "message";

		@JsonProperty(idKey)
		public final String id;

		@JsonProperty(versionKey)
		public final String version;

		@JsonProperty(messageKey)
		public String message;

		public Details(@JsonProperty(value = idKey, required = true) String id,
				@JsonProperty(value = versionKey, required = true) String version,
				@JsonProperty(value = messageKey, required = false) String message) {
			super(Details.class);
			this.id = id;
			this.version = version;
			this.message = message;
		}

	}

	public Status success(Details details) {
		++success_count;
		if (details != null) {
			if (successes == null) {
				successes = new ArrayList<>();
			}
			successes.add(details);
		}
		return epilogue();
	}

	public Status failure(Details details) {
		++failure_count;
		if (details != null) {
			if (failures == null) {
				failures = new ArrayList<>();
			}
			failures.add(details);
		}
		return epilogue();
	}

	private Status epilogue() {
		if (--pending_count < 0) {
			throw new InternalServerErrorException();
		}
		if (pending_count == 0) {
			status = SFP.complete.name();
		}
		return this;
	}

	public Status setStatus(String status) {
		this.status = status;
		return this;
	}

	public String getId() {
		return id;
	}

	public String getStatus() {
		return status;
	}

	public int getTotal_count() {
		return total_count;
	}

	public int getSuccess_count() {
		return success_count;
	}

	public int getFailure_count() {
		return failure_count;
	}

	public int getPending_count() {
		return pending_count;
	}

	public Timestamp getRequest_timestamp() {
		return request_timestamp;
	}

	public List<Details> getSuccesses() {
		return (successes != null) ? java.util.Collections.unmodifiableList(successes) : null;
	}

	public List<Details> getFailures() {
		return (failures != null) ? java.util.Collections.unmodifiableList(failures) : null;
	}

	public List<Details> getPendings() {
		return (pendings != null) ? java.util.Collections.unmodifiableList(pendings) : null;
	}

}
