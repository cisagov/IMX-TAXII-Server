/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.annotation.Annotation;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.glassfish.hk2.api.Factory;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.hk2.utilities.binding.ServiceBindingBuilder;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.cti4j2.JSON;

public class PropsBinder extends AbstractBinder {

	private static final Logger logger = LogManager.getLogger(PropsBinder.class);

	@JsonInclude(Include.NON_NULL)
	public static class BindSpec {

		private static final String contractKey = "contract";
		private static final String serviceKey = "service";
		private static final String scopeKey = "scope";
		private static final String factoryKey = "factory";

		@JsonProperty(contractKey)
		private final String contract;

		@JsonProperty(serviceKey)
		private final String service;

		@JsonProperty(scopeKey)
		private final String scope;

		@JsonProperty(factoryKey)
		private final String factory;

		@JsonCreator
		public BindSpec(@JsonProperty(value = contractKey, required = true) String contract,
				@JsonProperty(value = serviceKey, required = true) String service,
				@JsonProperty(value = scopeKey, required = false) String scope,
				@JsonProperty(value = factoryKey, required = false) String factory) {
			super();
			this.contract = contract;
			this.service = service;
			this.scope = scope;
			this.factory = factory;
		}

		public String getContract() {
			return contract;
		}

		public String getService() {
			return service;
		}

		public String getScope() {
			return scope;
		}

		public String getFactory() {
			return factory;
		}

		@Override
		public String toString() {
			try {
				return JSON.writeValueAsString(this);
			} catch (IOException e) {
				throw new IllegalArgumentException(e);
			}
		}

	}

	@JsonInclude(Include.NON_NULL)
	public static class BindSpecs {

		private static final String default_packageKey = "default_package";
		private static final String binder_specsKey = "bind_specs";

		@JsonProperty(default_packageKey)
		private final String default_package;

		@JsonProperty(binder_specsKey)
		private final List<BindSpec> bind_specs;

		public BindSpecs(@JsonProperty(value = default_packageKey, required = true) String default_package,
				@JsonProperty(value = binder_specsKey, required = false) List<BindSpec> binder_specs) {
			super();
			this.default_package = default_package;
			this.bind_specs = binder_specs;
		}

		public String getDefault_package() {
			return default_package;
		}

		public List<BindSpec> getBind_specs() {
			return bind_specs;
		}

		@Override
		public String toString() {
			try {
				return JSON.writeValueAsString(this);
			} catch (IOException e) {
				throw new IllegalArgumentException(e);
			}
		}

	}

	private PropsBinder(Properties properties, BindSpecs binderSpecs) {
		super();
		this.properties = properties;
		this.specs = binderSpecs;
	}

	private static final String base = "com.cisa.taxii4j2";

	private final Properties properties;
	private final BindSpecs specs;

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	protected void configure() {
		if (specs != null) {
			try {
				String base = specs.getDefault_package();
				for (BindSpec spec : specs.getBind_specs()) {
					try {
//						Class<?> contract = forName(spec.getContract(), base);
//						Class<?> service = forName(spec.getService(), base); // .asSubclass(contract);
						ServiceBindingBuilder<?> builder = null;
						String name = spec.getFactory();
						if (name != null) {
							Class<? extends Factory> factory = forName(name, base).asSubclass(Factory.class);
							builder = bindFactory(factory.getConstructor().newInstance());
						} else {
							builder = bind(forName(spec.getService(), base));
						}
						builder = builder.to(forName(spec.getContract(), base));
						name = spec.getScope();
						if (name != null) {
							builder.in(forName(name, base).asSubclass(Annotation.class));
						}
					} catch (Exception e) {
						logger.log(Level.FATAL, String.format("PropsBinder.configure: unknown class %s", spec), e);
						System.exit(-1);
					}
				}
			} catch (NullPointerException e) {
				// TODO
			}
		}
		if (properties != null) {
			for (String key : properties.stringPropertyNames()) {
				String[] values = properties.getProperty(key).split("\\s*,\\s*");
				try {
					Class<?> anonymous = forName(key);
					Class<?> specific = forName(values[0]).asSubclass(anonymous);
					ServiceBindingBuilder<?> builder = bind(specific).to(anonymous);
					if (values.length > 1) {
						builder.in(forName(values[1]).asSubclass(Annotation.class));
					}
				} catch (ClassNotFoundException e) {
					logger.fatal(String.format("PropsBinder.configure: unknown class %s -> %s", key,
							Arrays.toString(values)));
					System.exit(-1);
				}
			}
		}
	}

	private static Class<?> forName(String name) throws ClassNotFoundException {
		return forName(name, base);
	}

	private static Class<?> forName(String name, String base) throws ClassNotFoundException {
		name = name.trim();
		String altName = String.format("%s.%s", base, name);
		try {
			return Class.forName(name);
		} catch (ClassNotFoundException e0) {
			return Class.forName(altName);
		}
	}

	private static PropsBinder instance;

	public static void init(Properties properties, Properties _specs) {
		if (instance != null) {
			throw new IllegalStateException();
		}
		BindSpecs specs = null;
		if ((_specs != null) && !_specs.isEmpty()) {
			try (InputStream in = ClassLoader.getSystemResourceAsStream(_specs.getProperty("file"))) {
				specs = JSON.readValue(new InputStreamReader(in), BindSpecs.class);
			} catch (IOException e) {
				logger.log(Level.FATAL, "PropsBinder.setSpecs(String)", e);
				System.exit(-1);
			}

		}
		instance = new PropsBinder(properties, specs);
	}

	public static void init(Properties properties) {
		init(properties, null);
	}

	public static void init(BindSpecs specs) {
		if (instance != null) {
			throw new IllegalStateException();
		}
		instance = new PropsBinder(null, specs);
	}

	public static PropsBinder instance() {
		return instance;
	}

}
