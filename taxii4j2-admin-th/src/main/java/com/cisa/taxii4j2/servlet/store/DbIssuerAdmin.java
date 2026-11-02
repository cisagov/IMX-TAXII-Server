/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.store;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.auth.data.Issuer;
import com.cisa.taxii4j2.auth.data.TCOIDC;
import com.cisa.taxii4j2.auth.method.IssuerAdmin;
import com.cisa.taxii4j2.client.RemoteBase;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Singleton
public class DbIssuerAdmin implements IssuerAdmin {

	private final DbBase db;
	private final String index;
	private RemoteBase client;
	private final Map<String, WebTarget> userinfoEndpoints = new HashMap<>();

	@Inject
	public DbIssuerAdmin(DbBase db) {
		super();
		this.db = db;
		index = db.createIndex(db.localizeIndexName("issuers"));
		try {
			client = new RemoteBase("https://localhost/", MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON, null);
		} catch (MalformedURLException e1) {
			// can't happen...
		}
		String issuers = System.getenv("VALID_ISSUERS");
		if (issuers != null) {
			try {
				Iterator<JsonNode> iIssuer = JSON.readTree(issuers).elements();
				while (iIssuer.hasNext()) {
					put(JSON.readValue(iIssuer.next(), Issuer.class));
				}
			} catch (IOException e) {
				logger.warn("VALID_ISSUERS must be json list of issuer objects...");
			}
		}
	}

	private String normalize(String iss) {
		return iss.endsWith("/") ? iss : iss + "/";
	}

	@Override
	public Issuer get(String iss) {
		try {
			return db.get(normalize(iss), index, Issuer.class);
		} catch (NotFoundException e) {
			return null;
		}
	}

	@Override
	public Issuer put(Issuer issuer) {
		String normalized = normalize(issuer.getIss());
		return db.put(new Issuer(normalized, issuer.getRequired_role()), index, normalized, false);
	}

	@Override
	public List<Issuer> list() {
		return db.list(index, Issuer.class);
	}

	@Override
	public void delete(String iss) {
		db.delete(normalize(iss), index, Issuer.class);
	}

	@Override
	public boolean isValid(String credentials, JsonNode root) {
		try {
			String iss = root.get("iss").asText();
			logger.debug(String.format("DbIssuerAdmin.isValid: %s", iss));
			Issuer issuer = get(iss);
			logger.debug(String.format("DbIssuerAdmin.isValid: %s", issuer));
			if(issuer == null) {
				logger.info(String.format("Unable to find OIDC issuer %s", iss));
				return false;
			}
			return isIssuerRoleValid(issuer, root) && isTokenValid(issuer.getIss(), credentials);
		} catch (Exception e) {
			return false;
		}
	}

	private boolean isIssuerRoleValid(Issuer issuer, JsonNode root) {
		String required_role = issuer.getRequired_role();
		if (required_role != null) {
			return TCOIDC.roles(root).contains(required_role);
		}
		return true;
	}

	private boolean isTokenValid(String iss, String credentials) {
		WebTarget target = userinfoEndpoints.computeIfAbsent(iss, t -> {
			logger.debug(String.format("DbIssuerAdmin.isTokenValid: %s", t));
			Response configuration = client
					.paths(client.target(t), null, MediaType.APPLICATION_JSON, null, ".well-known", "openid-configuration")
					.get();
			logger.debug(String.format("DbIssuerAdmin.isTokenValid: %s", configuration));
			if (configuration.getStatus() == Response.Status.OK.getStatusCode()) {
				return client.target(configuration.readEntity(JsonNode.class).get("userinfo_endpoint").asText());
			} else {
				return client.target(t).path("protocol/openid-connect/userinfo");
			}
		});
		logger.debug(String.format("DbIssuerAdmin.isTokenValid: %s", target));
		Response userinfo = target.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, credentials)
				.get();
		logger.debug(String.format("DbIssuerAdmin.isTokenValid: %s", userinfo));
		return userinfo.getStatus() == Response.Status.OK.getStatusCode();
	}

}
