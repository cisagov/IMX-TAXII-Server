/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.cti4j2.Timestamp;

@JsonInclude(Include.NON_NULL)
public class WorkerParams implements Comparable<WorkerParams> {

	protected static final String beginKey = "begin";
	protected static final String endKey = "end";

	@JsonProperty(beginKey)
	private final Timestamp begin;

	@JsonProperty(endKey)
	private final Timestamp end;

	@JsonCreator
	public WorkerParams(@JsonProperty(value = beginKey, required = true) Timestamp begin,
			@JsonProperty(value = endKey, required = true) Timestamp end) {
		super();
		this.begin = begin;
		this.end = end;
	}

	public Timestamp getBegin() {
		return begin;
	}

	public Timestamp getEnd() {
		return end;
	}

	@Override
	public String toString() {
		return String.format("{ %s <=> %s }", begin, end);
	}

	@Override
	public int compareTo(WorkerParams arg0) {
		int c = begin.compareTo(arg0.begin);
		if (c == 0) {
			c = end.compareTo(arg0.end);
		}
		return c;
	}

	public boolean contains(WorkerParams worker) {
		return (begin.compareTo(worker.begin) <= 0) && (end.compareTo(worker.end) >= 0);
	}

}
