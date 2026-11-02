/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.method;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public interface AuthConfig {

	public static Logger logger = LogManager.getLogger(AuthConfig.class);

	default public String getRealm() {
		return "dfta";
	}

	default public String getResource() {
		return "imx";
	}

	default public String getTaxiiAdminUsername() {
		return "imx-admin";
	}

	default public String getRelayRole() {
		return "imx-relay";
	}

	public static final String taxiiPasswordKey = "TAXII_PASSWORD";

	default public String getTaxiiAdminPassword() {
		String env = System.getenv(taxiiPasswordKey);
		if (env == null) {
			logger.fatal(String.format("Environment variable \"%s\" must be set!!!", taxiiPasswordKey));
			System.exit(-1);
		}
		return env;
	}

	default public String getKeycloakAdminUsername() {
		return "keycloak-admin";
	}

	public static final String keycloakPasswordKey = "KEYCLOAK_PASSWORD";

	default public String getKeycloakAdminPassword() {
		String env = System.getenv(keycloakPasswordKey);
		if (env == null) {
			logger.fatal(String.format("Environment variable \"%s\" must be set!!!", keycloakPasswordKey));
			System.exit(-1);
		}
		return env;
	}

	default public List<String> getRoles() {
		return Arrays.asList(getAdminRole(), getUserRole(), getRelayRole());
	}

	default public String getAdminRole() {
		return "imx-admin";
	}

	default public String getUserRole() {
		return "imx-user";
	}

	public static final String keycloakUrlKey = "KEYCLOAK_URL";

	default public URL getKeycloakUrl() {
		String env = System.getenv(keycloakUrlKey);
		if (env == null) {
			logger.fatal(String.format("Environment variable \"%s\" must be set!!!", keycloakUrlKey));
			System.exit(-1);
		}
		try {
			return new URL(env);
		} catch (MalformedURLException e) {
			logger.fatal(String.format("Environment variable \"%s\" not URL (%s)!!!", keycloakUrlKey, env));
			System.exit(-1);
		}
		return null;
	}

}
