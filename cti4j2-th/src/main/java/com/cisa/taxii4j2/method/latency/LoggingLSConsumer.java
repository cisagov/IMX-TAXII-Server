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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.cisa.cti4j2.Timestamp;

public class LoggingLSConsumer implements LSConsumer {

	public static final String LOGGER_LEVEL = "LOGGER_LEVEL";

	private Logger logger = LogManager.getRootLogger();
	private Level level = Level.INFO;

	private final List<LatencySample> samples = new ArrayList<>();

	@Override
	public void configure(Properties properties) {
		String value = properties.getProperty(NAME);
		if(value != null) {
			logger = LogManager.getLogger(value);
		}
		value = properties.getProperty(LOGGER_LEVEL);
		if(value != null) {
			level = Level.valueOf(value);
		}
	}

	@Override
	public void accept(LatencySample t) {
		logger.log(level, t.toString());
	}

	@Override
	public List<LatencySample> read(Instant end, Duration duration) {
		Instant start = end.minus(duration);
		int iStart = Collections.binarySearch(samples, new LatencySample(new Timestamp(start)));
		if(iStart < 0) {
			iStart = -iStart - 1;
		}
		int iEnd = Collections.binarySearch(samples, new LatencySample(new Timestamp(end)));
		if(iEnd >= 0) {
			--iEnd;
		} else {
			iEnd = -iEnd - 1;
		}
		try {
			return samples.subList(iStart, iEnd);
		} catch(Exception e) {
			return Collections.emptyList();
		}
	}

}
