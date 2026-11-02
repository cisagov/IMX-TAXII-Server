/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.security;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.eclipse.jetty.ee9.security.ServerAuthException;
import org.eclipse.jetty.ee9.security.UserAuthentication;
import org.eclipse.jetty.ee9.security.authentication.DeferredAuthentication;
import org.eclipse.jetty.ee9.security.authentication.LoginAuthenticator;
import org.eclipse.jetty.ee9.nested.Authentication;
import org.eclipse.jetty.security.UserIdentity;

import com.cisa.taxii4j2.auth.method.IssuerAdmin;
import com.cisa.taxii4j2.auth.method.UserAdmin;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.core.HttpHeaders;

public class HybridAuthenticator extends LoginAuthenticator {

	private static final String authMethod = "hybrid";

	@Override
	public String getAuthMethod() {
		return authMethod;
	}

	@Override
	public Authentication validateRequest(ServletRequest request, ServletResponse response, boolean mandatory)
			throws ServerAuthException {

		if (!mandatory) {
			return new DeferredAuthentication(this);
		}

		String credentials = HttpServletRequest.class.cast(request).getHeader(HttpHeaders.AUTHORIZATION);

		if (credentials == null) {
			X509Certificate[] certs = (X509Certificate[]) request
					.getAttribute("jakarta.servlet.request.X509Certificate");
			if ((certs != null) && (certs.length > 0)) {
				try {
					credentials = String.format("%s %s", HttpServletRequest.CLIENT_CERT_AUTH,
							Base64.getEncoder().encodeToString(certs[0].getEncoded()));
				} catch (CertificateEncodingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}

		if (!validateIssuer(credentials)) {
			return Authentication.UNAUTHENTICATED;
		}

		UserIdentity user = login(null, credentials, request);
		return (user != null) ? new UserAuthentication(getAuthMethod(), user) : Authentication.UNAUTHENTICATED;

	}

	protected boolean validateIssuer(String credentials) {
		return true;
	}

	@Override
	public boolean secureResponse(ServletRequest request, ServletResponse response, boolean mandatory,
			Authentication.User validatedUser) throws ServerAuthException {
		return true;
	}

	public void setIssuerAdmin(IssuerAdmin issuerAdmin) {

	}

	public void setUserAdmin(UserAdmin userAdmin) {

	}
}
