/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.logging;

import java.io.IOException;

import com.cisa.taxii4j2.servlet.Logged;

import jakarta.inject.Inject;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;

@Logged
@Provider
public class ResponseLoggingFilter extends BaseLoggingFilter implements ContainerResponseFilter {

	@Inject
	public ResponseLoggingFilter(LogEntryConnector connector) {
		super(connector);
	}

	@Override
	public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext)
			throws IOException {
		String method = requestContext.getMethod();
		if (method.equals(HttpMethod.OPTIONS)) {
			return;
		}
		LogEntry logEntry = new ResponseLogEntry(requestContext, responseContext);
		connector.append(logEntry);
	}

}
