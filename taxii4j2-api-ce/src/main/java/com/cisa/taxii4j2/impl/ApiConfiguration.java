/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.impl;

import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;

import com.cisa.taxii4j2.data.impl.PropsHosts;
import com.cisa.taxii4j2.data.impl.TAXIIConfig;

public class ApiConfiguration {

	public static Map<String, Properties> configure(String... paths) {
		return configure(Arrays.asList(paths));
	}

	public static Map<String, Properties> configure(List<String> paths) {

		Properties merged = new Properties();

		for (String path : paths) {

			Properties layer = new Properties();

			try (InputStream in = TAXIIConfig.open(path)) {
				layer.load(in);
				if(layer.isEmpty()) {
					throw new IllegalArgumentException();
				}
			} catch (Exception e) {
				LogManager.getLogger(ApiConfiguration.class)
						.fatal(String.format("Configuration path %s not found or empty!!!", path));
				System.exit(-1);
			}

			merged.putAll(layer);

		}

		if (merged.isEmpty()) {
			LogManager.getLogger(ApiConfiguration.class)
					.fatal(String.format("Configuration from \"%s\" is empty!!!", paths));
			System.exit(-1);
		}

		Map<String, Properties> separated = new HashMap<>();
		for (String key : merged.stringPropertyNames()) {
			int index = key.indexOf('.');
			separated.computeIfAbsent(key.substring(0, index), k -> new Properties())
					.setProperty(key.substring(index + 1), merged.getProperty(key));
		}

		PropsHosts.setProperties(separated.getOrDefault("hosts", new Properties()));
		TAXIIConfig.setProperties(separated.getOrDefault("taxii", new Properties()));

		return separated;

	}

}
