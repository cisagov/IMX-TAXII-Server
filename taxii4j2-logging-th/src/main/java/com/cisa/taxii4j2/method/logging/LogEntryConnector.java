/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.logging;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jvnet.hk2.annotations.Contract;

@Contract
public interface LogEntryConnector {

	public static final Logger logger = LogManager.getLogger(LogEntryConnector.class);

	public int getEvent_id();

	public void append(LogEntry logEntry);

	default public List<RequestLogEntry> readRequestLogEntry(LogEntryFilter filter) {
		throw new UnsupportedOperationException();
	}

	default public List<ResponseLogEntry> readResponseLogEntry(int... event_ids) {
		throw new UnsupportedOperationException();
	}

}
