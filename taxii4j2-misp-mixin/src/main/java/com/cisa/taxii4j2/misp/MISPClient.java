/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.misp;

import java.net.MalformedURLException;
import java.net.URL;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.taxii4j2.auth.data.TAXIICredentials;
import com.cisa.taxii4j2.client.RemoteBearerBase;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;

public class MISPClient extends RemoteBearerBase {

	public static final String returnFormatKey = "returnFormat";
	public static final String responseKey = "response";
	public static final String eventKey = "Event";
	public static final String idKey = "id";
	public static final String eventidKey = "eventid";
	public static final String limitKey = "limit";
	public static final String timestampKey = "timestamp";


	public MISPClient(String token, URL url) {
		super(new TAXIICredentials() {

			@Override
			public String getHeaderValue() {
				return token;
			}

		}, url, MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON, null);
	}

	public static final String tokenKey = "MISP_TOKEN";
	public static final String urlKey = "MISP_URL";

	public MISPClient() throws MalformedURLException {
		this(System.getenv(tokenKey), new URL(System.getenv(urlKey)));
	}

	public JsonNode get(String... paths) {
		return get(null, paths);
	}

	public JsonNode get(MultivaluedMap<String, String> qps, String... paths) {
        System.out.println("getHelper");
		return super.getHelper(JsonNode.class, qps, paths);
	}

	public JsonNode post(JsonNode body, String... paths) {
		return post(body, null, paths);
	}

	public JsonNode post(JsonNode body, MultivaluedMap<String, String> qps, String... paths) {
        System.out.println("postHelper");
		return super.postHelper(body, JsonNode.class, qps, paths);
	}

}
