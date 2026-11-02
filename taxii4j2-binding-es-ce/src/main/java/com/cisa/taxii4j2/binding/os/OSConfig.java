/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.binding.os;

import java.net.URI;
import java.util.Properties;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;

public class OSConfig {

	private static Properties properties;

	private static final String hostKey = "host";
	private static final String portKey = "port";
	private static final String schemeKey = "scheme";
	private static final String usernameKey = "username";
	private static final String passwordKey = "OPENSEARCH_PASSWORD";

	public static String getHost() {
		return properties.getProperty(hostKey);
	}

	public static Integer getPort() {
		return Integer.valueOf(properties.getProperty(portKey));
	}

	public static String getScheme() {
		return properties.getProperty(schemeKey);
	}

	public static String getUsername() {
		return properties.getProperty(usernameKey, "elastic");
	}

	public static String getPassword() {
		return properties.getProperty(passwordKey);
	}

	public static final String urlKey = "OPENSEARCH_URL";

	private static String get(String key) {
		String env = System.getenv().get(key);
		if (env == null) {
			LogManager.getLogger(OSConfig.class).log(Level.FATAL, String.format("Environment variable \"%s\" wasn't set...", key));
			System.exit(-1);
		}
		return env;
	}

	private static void put(String key) {
		properties.put(key, get(key));
	}

	static {

		properties = new Properties();

		String env = get(urlKey);
		URI uri = URI.create(env);
		properties.put(hostKey, uri.getHost());
		properties.put(portKey, Integer.toString(uri.getPort()));
		properties.put(schemeKey, uri.getScheme());

		put(passwordKey);

	}

}
