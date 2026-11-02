/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.data;

import java.net.URL;
import java.util.Base64;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.Level;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.auth.method.PropsAuthConfig;
import com.cisa.taxii4j2.client.RemoteBase;

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

public class TCOIDC extends TAXIICredentials {

	private static final String method = "bearer";
	private final RemoteBase client;

	private static final String access_tokenKey = "access_token";
	private String access_token;

	private static final String refresh_tokenKey = "refresh_token";
	private String refresh_token;

	private static final String expires_inKey = "expires_in";
	private static final long scale = 900;
	private long refresh_after;

	public TCOIDC(URL provider, String username, String password) {
		super();
		client = new RemoteBase(provider, MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON, null);
		MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
		params.add("grant_type", "password");
		params.add("username", username);
		params.add("password", password);
		params.add("client_id", getResource());
		/*
		 * just going for the side effect here...
		 */
		tokenHelper(params);
	}

	private String getResource() {
		return PropsAuthConfig.instance().getResource();
	}

	private String tokenHelper(MultivaluedMap<String, String> params) {
		long ms = 1000;
		while (true) {
			try {
				String json = client.postHelper(Entity.form(params), String.class, null, "realms", getRealm(),
						"protocol", "openid-connect", "token");
				logger.debug(json);
				JsonNode root = JSON.readTree(json);
				synchronized (this) {
					access_token = root.get(access_tokenKey).asText();
					refresh_token = root.get(refresh_tokenKey).asText();
					refresh_after = System.currentTimeMillis() + root.get(expires_inKey).asLong() * scale;
					return access_token;
				}
			} catch (NullPointerException e) {
				/*
				 * all we know is that we didn't get a token back...
				 */
				return null;
			} catch (Exception e) {
				if (ms > 64000) {
					logger.log(Level.FATAL, "keycloakBearerToken.tokenHelper", e);
					return null;
				}
				logger.warn(String.format("KeycloakBearerToken.tokenHelper: waiting %d ms...", ms));
				try {
					Thread.sleep(ms);
				} catch (InterruptedException e1) {
					return null;
				}
				ms *= 2;
			}
		}
	}

	private String getRealm() {
		return PropsAuthConfig.instance().getRealm();
	}

	private String token() {
		MultivaluedMap<String, String> params = null;
		synchronized (this) {
			if (System.currentTimeMillis() < refresh_after) {
				return access_token;
			}
			params = new MultivaluedHashMap<>();
			params.add("grant_type", "refresh_token");
			params.add("refresh_token", refresh_token);
			params.add("client_id", getResource());
		}
		return tokenHelper(params);
	}

	@Override
	public String getHeaderValue() {
		return getHeaderValue(token());
	}

	private String getHeaderValue(String value) {
		return String.format("%s %s", method, value);
	}

	private static Base64.Decoder decoder = Base64.getUrlDecoder();

	public static JsonNode payload(String headerValue) {
		String[] tokens = headerValue.split("\\s+");
		if ((tokens.length != 2) || !tokens[0].equalsIgnoreCase(method)) {
			throw new IllegalArgumentException();
		}
		try {
			String payload = new String(decoder.decode(tokens[1].split("\\.")[1]));
			return JSON.readTree(payload);
		} catch (Exception e) {
			throw new IllegalArgumentException(e);
		}
	}

	public static String username(JsonNode root) {
		return root.get("preferred_username").asText();
	}

	public static Set<String> roles(JsonNode root) {
		Set<String> roles = new HashSet<>();
		User known = userAdmin().readUserByName(username(root));
		if (known != null) {
			Set<String> knownRoles = known.getRoles();
			if (knownRoles != null) {
				roles.addAll(knownRoles);
			}
		}
		JsonNode realm_access = root.get("realm_access");
		if (realm_access != null) {
			Iterator<JsonNode> iRole = realm_access.withArray("roles").elements();
			while (iRole.hasNext()) {
				roles.add(iRole.next().asText());
			}
		}
		JsonNode resource_access = root.get("resource_access");
		if (resource_access != null) {
			Iterator<Map.Entry<String, JsonNode>> iResource = resource_access.fields();
			while (iResource.hasNext()) {
				Iterator<JsonNode> iRole = iResource.next().getValue().withArray("roles").elements();
				while (iRole.hasNext()) {
					roles.add(iRole.next().asText());
				}
			}
		}
		return roles;
	}

	public static User getUser(String headerValue) {
		JsonNode root = payload(headerValue);
		return new User(username(root), null, roles(root));
	}

	public static Set<String> getGroups(String headerValue) {
		HashSet<String> groups = new HashSet<>();
		try {
			JsonNode groupNode = payload(headerValue).get("groups");
			if (groupNode != null) {
				Iterator<JsonNode> iGroup = groupNode.elements();
				while (iGroup.hasNext()) {
					groups.add(iGroup.next().asText());
				}
			}

		} catch (IllegalArgumentException e) {
			// Error parsing, probably wasn't OIDC header
		} catch (Exception e) {
			logger.error("Error getting groups from OIDC", e);
		}
		return groups;
	}
}
