/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Properties;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.glassfish.hk2.api.ServiceLocator;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.data.Discovery;

public class TAXIIConfig {

	public static InputStream open(String path) {
		try {
			return Files.newInputStream(Paths.get(path));
		} catch (Exception e) {
			return ClassLoader.getSystemResourceAsStream(path);
		}
	}

	public static class Args {

		@Parameter(names = "--help", help = true, description = "print this help message")
		private boolean help;

		@Parameter(names = { "--config",
				"-c" }, description = "add a runtime configuration resource (paths, constants, dependency injection, ...)")
		private List<String> configs;

		@Parameter(names = { "--root",
				"-r" }, description = "add a data configuration resource (users, collections, api-roots)")
		private List<String> roots;

		@Parameter(names = { "--mirror", "-m" }, description = "add a Git object mirror")
		private List<String> mirrors;

		@Parameter(names = { "--schema", "-s" }, description = "add a Git schema mirror")
		private List<String> schemas;

		@Override
		public String toString() {
			return "Args [configs=" + configs + ", roots=" + roots + ", mirrors=" + mirrors + ", schema=" + schemas
					+ "]";
		}

		private Args() {

		}

		public static Args factory(String[] argv) {
			try {
				Args args = new Args();
				JCommander jCommander = JCommander.newBuilder().addObject(args).build();
				jCommander.setProgramName("TAXII");
				jCommander.parse(argv);
				return args;
			} catch (ParameterException e) {
				e.getJCommander().usage();
				throw new IllegalArgumentException(e);
			}
		}

	}

	private static ServiceLocator serviceLocator;

	public static void setServiceLocator(ServiceLocator _locator) {
		serviceLocator = _locator;
	}

	public static ServiceLocator serviceLocator() {
		return serviceLocator;
	}

	/*
	 * Setting this to empty list allows clients to use defaults...
	 */
	private static Properties properties = new Properties();

	private static String _taxii4j2UUID;
	private static final String xuuidKey = "TAXII_XUUID";

	public static String taxii4j2UUID() {
		if (_taxii4j2UUID == null) {
			_taxii4j2UUID = System.getenv(xuuidKey);
			if (_taxii4j2UUID == null) {
				logger.fatal(String.format("Server serial number environment var %s must be specified", xuuidKey));
				System.exit(-1);
			}
		}
		return _taxii4j2UUID;
	}

	public static final int customPropertyLength = 250;
	public static String _prefix;

	private static String prefix() {
		if (_prefix == null) {
			_prefix = String.format("x_%s_", safeCustomProperty(taxii4j2UUID()));
		}
		return _prefix;
	}

	public static String x_(String suffix) {
		String x_ = String.format("%s%s", prefix(), safeCustomProperty(suffix));
		return x_.substring(0, Math.min(x_.length(), customPropertyLength));
	}

	public static String unX_(String key) {
		return key.substring(prefix().length());
	}

	private static String safeCustomProperty(String s) {
		return s.toLowerCase().replaceAll("[^a-z0-9_]", "_");
	}

	public static boolean isMyX_(String key) {
		return key.startsWith(prefix());
	}

	public static boolean isX_(String key) {
		return key.startsWith("x_");
	}

	public static final Logger logger = LogManager.getLogger(TAXIIConfig.class);

	private static final int _limitMax = 1024;

	private static final String limitMaxKey = "limitMax";

	public static int limitMax() {
		String limitMax = properties.getProperty(limitMaxKey);
		return (limitMax != null) ? Integer.valueOf(limitMax) : _limitMax;
	}

	private static Discovery discovery;
	private static final String discoveryKey = "discovery";

	public static Discovery discovery() {
		if (discovery == null) {
			try {
				discovery = JSON.readValue(properties.getProperty(discoveryKey), Discovery.class);
			} catch (IOException e) {
				logger.log(Level.FATAL, "TAXIIConfig.discovery", e);
			}
		}
		return discovery;
	}

	public static void setProperties(Properties _properties) {
		properties = _properties;
	}

	private static final String baseURIKey = "baseURI";

	public static URI baseURI() {
		String baseURI = properties.getProperty(baseURIKey);
		return (baseURI != null) ? URI.create(baseURI) : null;
	}

	private static Args args;

	public static void setArgs(String[] argv) {
		args = Args.factory(argv);
		logger.debug(args.toString());
	}

	public static List<String> getConfigs() {
		return args.configs;
	}

	public static List<String> getRoots() {
		return args.roots;
	}

	public static List<String> getMirrors() {
		return args.mirrors;
	}

	public static List<String> getSchemas() {
		return args.schemas;
	}

	@SuppressWarnings("resource")
	public static <T> T readValue(String fileOrResource, Class<T> clazz) throws IOException {
		InputStream in = null;
		try {
			in = Files.newInputStream(Paths.get(fileOrResource));
		} catch (Exception e) {
			in = ClassLoader.getSystemResourceAsStream(fileOrResource);
		}
		if (in == null) {
			throw new IOException(String.format("TAXIIConfig.readValue(%s)", fileOrResource));
		}
		T t = JSON.readValue(new InputStreamReader(in), clazz);
		in.close();
		return t;
	}

}
