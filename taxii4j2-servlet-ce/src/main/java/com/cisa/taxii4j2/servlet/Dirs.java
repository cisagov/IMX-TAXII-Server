/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

public class Dirs {

	private static final String schema_dirKey = "SCHEMA_DIR";
	private static final String schema_dirDefault = "/opt/schema";

	public Path schema() {
		return Paths.get(properties.getProperty(schema_dirKey));
	}

	private static final String bootstrap_dirKey = "BOOTSTRAP_DIR";
	private static final String bootstrap_dirDefault = "/opt/bootstrap";

	public Path boostrap() {
		return Paths.get(properties.getProperty(bootstrap_dirKey));
	}

	private static final Dirs instance = new Dirs();

	public static Dirs instance() {
		return instance;
	}

	private static Properties properties = new Properties();

	public static void setProperties(Properties _properties) {
		properties = _properties;
		setProperty(schema_dirKey, schema_dirDefault);
		setProperty(bootstrap_dirKey, bootstrap_dirDefault);
	}

	/**
	 * Priority: environment, config file, default
	 *
	 * @param key
	 * @param def
	 */
	private static void setProperty(String key, String def) {
		String value = System.getenv(key);
		if (value != null) {
			properties.put(key, value);
		} else if (!properties.containsKey(key)) {
			properties.put(key, def);
		}
	}

}
