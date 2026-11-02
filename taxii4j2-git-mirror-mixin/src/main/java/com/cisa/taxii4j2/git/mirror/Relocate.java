/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.mirror;

import java.net.URI;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

@JsonInclude(Include.NON_NULL)
public class Relocate {

	public static final String fromKey = "from";
	public static final String toKey = "to";

	@JsonProperty(fromKey)
	private final String from;

	@JsonProperty(toKey)
	private final String to;

	public Relocate(@JsonProperty(value = fromKey, required = true) String from,
			@JsonProperty(value = toKey, required = true) String to) {
		super();
		this.from = from;
		this.to = to;
	}

	public String getFrom() {
		return from;
	}

	public String getTo() {
		return to;
	}

	public String apply(String in) {
		URI original = URI.create(in);
		URI suffix = URI.create(from).relativize(original);
		URI out = URI.create(to).resolve(suffix);
		return out.toString();
	}

}
