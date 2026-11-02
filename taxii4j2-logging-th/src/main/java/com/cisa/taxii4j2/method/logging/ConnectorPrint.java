/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.logging;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

import com.cisa.cti4j2.JSON;

public class ConnectorPrint implements LogEntryConnector {

	private final AtomicInteger event_id = new AtomicInteger();

	@Override
	public void append(LogEntry logEntry) {
		try {
			System.out.println(JSON.writeValueAsString(logEntry));
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

	@Override
	public int getEvent_id() {
		return event_id.incrementAndGet();
	}

}
