/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data.impl;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Properties;

import org.apache.logging.log4j.Level;

public class PropsHosts implements Hosts {

	private final Properties properties;

	private static final String baseUriKey = "TAXII_URL";
	private static final String validatorKey = "VALIDATOR_URL";
	private static final String taxiiKey = "taxii";
	private static final String adminKey = "admin";
	private static final String searchKey = "search";
	private static final String schemaRepoKey = "schemaRepo";
	private static final String generatorKey = "GENERATOR_URL";

	private static URL url(String value) {
		try {
			return new URL(value);
		} catch (MalformedURLException e) {
			throw new IllegalArgumentException(e);
		}
	}

	@Override
	public URI baseUri() {
		String env = System.getenv(baseUriKey);
		if (env == null) {
			logger.log(Level.FATAL,
					String.format("Environment variable \"%s\" must be set!!!", baseUriKey));
			System.exit(-1);
		}
		return URI.create(env);
	}

	@Override
	public URL validator() {
		String env = System.getenv(validatorKey);
		if (env == null) {
			logger.log(Level.FATAL,
					String.format("Environment variable \"%s\" must be set!!!", validatorKey));
			System.exit(-1);
		}
		return url(env);
	}

	@Override
	public URI taxiiPath() {
		return URI.create(properties.getProperty(taxiiKey));
	}

	@Override
	public URI adminPath() {
		return URI.create(properties.getProperty(adminKey));
	}

	@Override
	public URI searchPath() {
		return URI.create(properties.getProperty(searchKey));
	}

	@Override
	public URL generator() {
		String env = System.getenv(generatorKey);
		if (env == null) {
			logger.log(Level.FATAL,
					String.format("Environment variable \"%s\" must be set!!!", generatorKey));
			System.exit(-1);
		}
		return url(env);
	}

	private PropsHosts(Properties properties) {
		super();
		this.properties = properties;
	}

	private static Hosts instance;

	public static Hosts instance() {
		return instance;
	}

	public static void setProperties(Properties _properties) {
		instance = new PropsHosts(_properties);
	}

	@Override
	public URI schemaRepoPath() {
		return URI.create(properties.getProperty(schemaRepoKey));
	}

}
