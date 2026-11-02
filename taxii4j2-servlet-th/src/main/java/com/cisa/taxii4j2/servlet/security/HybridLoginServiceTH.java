/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.security;

import java.util.ArrayList;
import org.eclipse.jetty.security.UserPrincipal;
import org.eclipse.jetty.util.security.Credential;

import com.cisa.taxii4j2.auth.data.TCOIDC;

public class HybridLoginServiceTH extends HybridLoginService {

	@Override
	protected UserPrincipal createUserPrincipal(String username, Credential cred, String header) {
		UserGroupPrincipal principal = new UserGroupPrincipal(username, cred);
		principal.addGroups(new ArrayList<>(TCOIDC.getGroups(header)));
		return principal;
	}

}
