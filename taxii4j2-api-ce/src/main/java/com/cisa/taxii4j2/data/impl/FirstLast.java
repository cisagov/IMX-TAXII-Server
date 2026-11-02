/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data.impl;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Manifest;
import com.cisa.taxii4j2.data.Versions;

import jakarta.ws.rs.core.Response;

/**
 * This class encapsulates first and last date added values for
 * {@link Envelope}, {@link Manifest}, and {@link Versions}. It is hidden from
 * JSON representations of those, being used only internally to generate HTTP
 * header values when required.
 */
public class FirstLast extends CustomFields {

	public final static String dateAddedFirst = "X-TAXII-Date-Added-First";
	public final static String dateAddedLast = "X-TAXII-Date-Added-Last";
	public final static String expose = "Access-Control-Expose-Headers";

	@JsonIgnore
	private Timestamp first;
	@JsonIgnore
	private Timestamp last;

	public FirstLast(String className) {
		super(className);
	}

	public FirstLast(Class<?> clazz) {
		super(clazz);
	}

	@JsonIgnore
	public FirstLast clearFirstLast() {
		first = null;
		last = null;
		return this;
	}

	@JsonIgnore
	public static void setFirstLast(FirstLast o, Response response) {
		if (o == null) {
			return;
		}
		o.setFirstLast(response);
	}

	@JsonIgnore
	public FirstLast setFirstLast(Response response) {
		String t = response.getHeaderString(dateAddedFirst);
		if (t != null) {
			first = Timestamp.valueOf(t);
		}
		t = response.getHeaderString(dateAddedLast);
		if (t != null) {
			last = Timestamp.valueOf(t);
		}
		return this;
	}

	@JsonIgnore
	public void setFirstLast(Timestamp value) {
		if (first == null) {
			first = value;
		}
		last = value;
	}

	@JsonIgnore
	public void setFirstLast(Timestamp first, Timestamp last) {
		if (this.first != null) {
			throw new IllegalStateException("FirstLast.setFirstLast");
		}
		this.first = first;
		this.last = last;
	}

	@JsonIgnore
	public Timestamp getFirst() {
//		return (first != null) ? first : Timestamp.epoch;
		return first;
	}

	@JsonIgnore
	public Timestamp getLast() {
//		return (last != null) ? last : Timestamp.epoch;
		return last;
	}

}
