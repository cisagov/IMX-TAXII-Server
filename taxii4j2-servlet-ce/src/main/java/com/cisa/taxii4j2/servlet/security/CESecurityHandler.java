/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.security;

import org.eclipse.jetty.ee9.security.RoleInfo;
import org.eclipse.jetty.ee9.nested.Request;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
public class CESecurityHandler extends TAXIISecurityHandler {

	@Inject
	public CESecurityHandler() {
		super(new HybridLoginService(), new HybridAuthenticator());
	}

	@Override
	protected RoleInfo prepareConstraintInfo(String pathInContext, Request request) {
		return anyRoleInfo;
	}

}
