/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import com.cisa.taxii4j2.auth.method.PropsAuthConfig;
import com.cisa.taxii4j2.impl.ApiConfiguration;

public class Configuration {

	public static Map<String, Properties> configure(String... paths) {
		return configure(Arrays.asList(paths));
	}

	public static Map<String, Properties> configure(List<String> paths) {

		Map<String, Properties> separated = ApiConfiguration.configure(paths);

		Dirs.setProperties(separated.getOrDefault("dirs", new Properties()));
		PropsBinder.init(separated.getOrDefault("bind", new Properties()),
				separated.getOrDefault("bindSpecs", new Properties()));
		PropsAuthConfig.setProperties(separated.getOrDefault("auth", new Properties()));

		return separated;

	}

}
