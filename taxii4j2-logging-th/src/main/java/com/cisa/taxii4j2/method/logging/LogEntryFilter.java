/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.logging;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.cisa.cti4j2.Timestamp;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.ws.rs.core.MultivaluedMap;

@JsonInclude(Include.NON_NULL)
public class LogEntryFilter {

	public static final int maxSize = 64;

	private static final String t0Key = "t0";
	private static final String t1Key = "t1";
	private static final String fromKey = "from";
	private static final String sizeKey = "size";
	private static final String pathKey = "path";
	private static final String methodKey = "method";

	@JsonProperty(RequestLogEntry.user_nameKey)
	private String user_name;

	@JsonProperty(t0Key)
	private Timestamp t0;

	@JsonProperty(t1Key)
	private Timestamp t1;

	@JsonProperty(fromKey)
	private Integer from;

	@JsonProperty(sizeKey)
	private Integer size = maxSize;

	@JsonProperty(pathKey)
	private String path;

	@JsonProperty(methodKey)
	private String method;

	public LogEntryFilter(@JsonProperty(value = RequestLogEntry.user_nameKey, required = false) String user_name,
			@JsonProperty(value = t0Key, required = false) Timestamp t0,
			@JsonProperty(value = t1Key, required = false) Timestamp t1,
			@JsonProperty(value = fromKey, required = false) Integer from,
			@JsonProperty(value = sizeKey, required = false) Integer size,
			@JsonProperty(value = pathKey, required = false) String path,
			@JsonProperty(value = methodKey, required = false) String method) {
		super();
		this.user_name = user_name;
		this.t0 = t0;
		this.t1 = t1;
		this.from = from;
		this.size = size;
		this.path = path;
		this.method = method;
	}

	public LogEntryFilter(MultivaluedMap<String, String> qps) {
		super();
		this.user_name = qps.getFirst(RequestLogEntry.user_nameKey);
		String value = qps.getFirst(t0Key);
		this.t0 = (value != null) ? Timestamp.valueOf(value) : null;
		value = qps.getFirst(t1Key);
		this.t1 = (value != null) ? Timestamp.valueOf(value) : null;
		value = qps.getFirst(fromKey);
		this.from = (value != null) ? Integer.valueOf(value) : null;
		/*
		 * #size is treated differently since it has a default value...
		 */
		value = qps.getFirst(sizeKey);
		if (value != null) {
			this.size = Integer.valueOf(value);
		}

		this.path = qps.getFirst(pathKey);
		this.method = qps.getFirst(methodKey);
	}

	public String getPath() {
		return path;
	}

	public void setPath(String path) {
		this.path = path;
	}

	public String getMethod() {
		return method;
	}

	public void setMethod(String method) {
		this.method = method;
	}

	public LogEntryFilter setUser_name(String user_name) {
		this.user_name = user_name;
		return this;
	}

	public LogEntryFilter setT0(Timestamp t) {
		t0 = t;
		return this;
	}

	public LogEntryFilter setT1(Timestamp t) {
		t1 = t;
		return this;
	}

	@JsonIgnore
	public LogEntryFilter setT0T1(Timestamp t0, Timestamp t1) {
		return setT0(t0).setT1(t1);
	}

	public LogEntryFilter setFrom(int from) {
		this.from = from;
		return this;
	}

	public LogEntryFilter setSize(int size) {
		this.size = Math.min(size, maxSize);
		return this;
	}

	public String getUser_name() {
		return user_name;
	}

	public Timestamp getT0() {
		return t0;
	}

	public Timestamp getT1() {
		return t1;
	}

	public Integer getFrom() {
		return from;
	}

	public Integer getSize() {
		return size;
	}
}
