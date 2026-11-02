/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.logging;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.eclipse.jetty.server.SecureRequestCustomizer;

import com.cisa.taxii4j2.auth.method.UserAdmin;
import com.cisa.taxii4j2.servlet.Logged;

import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.ext.Provider;

@Logged
@Provider
public class RequestLoggingFilter extends BaseLoggingFilter implements ContainerRequestFilter {

	private final UserAdmin userAdmin;

	@Inject
	public RequestLoggingFilter(LogEntryConnector connector, UserAdmin userAdmin) {
		super(connector);
		this.userAdmin = userAdmin;
	}

	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {

		if (requestContext.getHeaderString(HttpHeaders.AUTHORIZATION) == null) {
			X509Certificate[] certs = (X509Certificate[]) requestContext
					.getProperty("jakarta.servlet.request.X509Certificate");
			if ((certs != null) && (certs.length > 0)) {
				try {
					String credentials = Base64.getEncoder().encodeToString(certs[0].getEncoded());
					requestContext.getHeaders().putSingle(HttpHeaders.AUTHORIZATION,
							String.format("%s %s", HttpServletRequest.CLIENT_CERT_AUTH, credentials));
				} catch (CertificateEncodingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}

		String method = requestContext.getMethod();
		if (method.equals(HttpMethod.OPTIONS)) {
			return;
		}
		LogEntry logEntry = new RequestLogEntry(connector.getEvent_id(), requestContext, userAdmin);
		connector.append(logEntry);
	}

}
