/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.cisa.cti4j2.JSON;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(Include.NON_NULL)
public class Issuer implements Comparable<Issuer> {

	public static final String issKey = "iss";
	public static final String required_roleKey = "required_role";

	@JsonProperty(issKey)
	private final String iss;

	@JsonProperty(required_roleKey)
	private String required_role;

	@JsonCreator
	public Issuer(@JsonProperty(value = issKey, required = true) String iss,
			@JsonProperty(value = required_roleKey, required = false) String required_role) {
		super();
		this.iss = iss;
		this.required_role = required_role;
	}

	public String getRequired_role() {
		return required_role;
	}

	public Issuer setRequired_role(String required_role) {
		this.required_role = required_role;
		return this;
	}

	public String getIss() {
		return iss;
	}

	@Override
	public int compareTo(Issuer arg0) {
		return getIss().compareTo(arg0.getIss());
	}

	@Override
	public String toString() {
		return JSON.toJsonNode(this).toPrettyString();
	}

}
