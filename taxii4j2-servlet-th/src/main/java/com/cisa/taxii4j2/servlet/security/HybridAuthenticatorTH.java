/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.taxii4j2.auth.data.TCOIDC;
import com.cisa.taxii4j2.auth.data.TCPKCS12;
import com.cisa.taxii4j2.auth.data.User;
import com.cisa.taxii4j2.auth.method.IssuerAdmin;
import com.cisa.taxii4j2.auth.method.UserAdmin;

public class HybridAuthenticatorTH extends HybridAuthenticator {

	private IssuerAdmin issuerAdmin;
	private UserAdmin userAdmin;

	public HybridAuthenticatorTH() {
		super();
	}

	@Override
	protected boolean validateIssuer(String credentials) {
		try {
			User user = TCPKCS12.getUser(credentials);
			return (userAdmin.readUserByName(user.getUser()) != null);
		} catch (Exception e) {
			// not a certificate
		}
		try {
			JsonNode root = TCOIDC.payload(credentials);
			return issuerAdmin.isValid(credentials, root);
		} catch (Exception e) {
			// not a bearer token
		}
		return true;
	}

	@Override
	public void setIssuerAdmin(IssuerAdmin issuerAdmin) {
		this.issuerAdmin = issuerAdmin;
	}

	@Override
	public void setUserAdmin(UserAdmin userAdmin) {
		this.userAdmin = userAdmin;
	}
}
