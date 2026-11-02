/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.latency;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Properties;
import java.util.function.Consumer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jvnet.hk2.annotations.Contract;

import com.cisa.taxii4j2.data.impl.TAXIIConfig;

@Contract
public interface LSConsumer extends Consumer<LatencySample> {

	public static Logger logger = LogManager.getLogger(LSConsumer.class);

	public static final String NAME = "NAME";

	default public void configure(Properties properties) {

	}

	public static LSConsumer getService() {
		try {
			return TAXIIConfig.serviceLocator().getService(LSConsumer.class);
		} catch (Exception e) {
			LogManager.getRootLogger().warn("LSConsumer.getService falling back to LoggingLSConsumer...");
			return new LoggingLSConsumer();
		}
	}

	public List<LatencySample> read(Instant end, Duration duration);

}
