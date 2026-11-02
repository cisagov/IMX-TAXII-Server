/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.binding.sqlite;

import java.util.Properties;
import java.util.logging.Logger;

public class SqliteConfig {

	private static final Properties properties = new Properties();

	private static final String urlKey = "SQLITE_URL";

	static {
		init(urlKey);
	}

	private static void init(String key) {
		String value = System.getenv(key);
		if(value == null) {
			Logger.getGlobal().severe(String.format("SqliteConfig environment variable \"%s\" must be set!!!", key));
			System.exit(-1);
		}
		properties.put(key, value);
	}

	public static String getUrl() {
//		return "jdbc:sqlite:/opt/taxii4j2/taxii4j2.db";
		return properties.getProperty(urlKey);
	}

}
