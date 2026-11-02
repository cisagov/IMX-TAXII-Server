/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client;

import java.net.URL;

import com.cisa.taxii4j2.auth.data.TAXIICredentials;

import jakarta.ws.rs.client.Invocation.Builder;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;

public class RemoteBearerBase extends RemoteBase {

	protected final TAXIICredentials token;

	public RemoteBearerBase(RemoteInfo info, String consumes, String produces) {
		super(info, consumes, produces);
		this.token = info.credentials();
	}

	public RemoteBearerBase(TAXIICredentials token, URL url, String consumes, String produces, MultivaluedMap<String, Object> headers) {
		super(url, consumes, produces, headers);
		this.token = token;
	}

	@Override
	public Builder paths(WebTarget target, MultivaluedMap<String, Object> headers, String produces, MultivaluedMap<String, String> queryParams,
			String... paths) {
		Builder builder = super.paths(target, headers, produces, queryParams, paths);
		String headerValue = (token != null) ? token.getHeaderValue() : null;
		return (headerValue != null) ? builder.header(HttpHeaders.AUTHORIZATION, headerValue) : builder;
	}

}
