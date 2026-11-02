/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.a1;

import java.io.IOException;
import java.net.URI;

import com.cisa.taxii4j2.client.RemoteBearerBase;
import com.cisa.taxii4j2.client.RemoteInfo;

import jakarta.ws.rs.core.MediaType;

public class A1ClientBase extends RemoteBearerBase {

	public static final String A1HostKey = "A1_HOST";
	public static final String A1UserKey = "A1_USER";
	public static final String A1PassKey = "A1_PASS";

	public A1ClientBase() throws IOException {
		super(RemoteInfo.factory(null, URI.create(System.getenv(A1HostKey)).resolve("api/1_0/").toURL().toString(),
				null, null, System.getenv(A1UserKey), System.getenv(A1PassKey), null, null, null),
				MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);
	}

}
