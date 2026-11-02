/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.method;

import java.util.Arrays;
import java.util.List;
import java.util.Properties;

public class PropsAuthConfig implements AuthConfig {

	private final Properties properties;

	private static final String realmKey = "realm";
	private static final String resourceKey = "resource";
	private static final String adminUsernameKey = "adminUsername";
	private static final String adminPasswordKey = "adminPassword";
	private static final String rolesKey = "roles";

	private PropsAuthConfig(Properties properties) {
		super();
		this.properties = properties;
	}

	private static AuthConfig instance;

	public static AuthConfig instance() {
		return instance;
	}

	public static void setProperties(Properties _properties) {
		instance = new PropsAuthConfig(_properties);
	}

	@Override
	public String getRealm() {
		return properties.getProperty(realmKey, AuthConfig.super.getRealm());
	}

	@Override
	public String getResource() {
		return properties.getProperty(resourceKey, AuthConfig.super.getResource());
	}

	@Override
	public String getTaxiiAdminUsername() {
		return properties.getProperty(adminUsernameKey, AuthConfig.super.getTaxiiAdminUsername());
	}

	@Override
	public String getTaxiiAdminPassword() {
		return properties.getProperty(adminPasswordKey, AuthConfig.super.getTaxiiAdminPassword());
	}

	@Override
	public List<String> getRoles() {
		String roles = properties.getProperty(rolesKey);
		return (roles != null) ? Arrays.asList(roles.split("\\s*,\\s*")) : AuthConfig.super.getRoles();
	}

}
