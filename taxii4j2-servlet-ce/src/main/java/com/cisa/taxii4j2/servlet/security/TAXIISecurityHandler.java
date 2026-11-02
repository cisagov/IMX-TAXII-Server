/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.security;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jetty.ee9.security.RoleInfo;
import org.eclipse.jetty.ee9.security.SecurityHandler;
import org.eclipse.jetty.ee9.nested.Request;
import org.eclipse.jetty.ee9.nested.Response;
import org.eclipse.jetty.security.UserIdentity;

import com.cisa.taxii4j2.auth.method.AuthConfig;
import com.cisa.taxii4j2.auth.method.IssuerAdmin;
import com.cisa.taxii4j2.auth.method.PropsAuthConfig;
import com.cisa.taxii4j2.auth.method.RootCollectionRead;
import com.cisa.taxii4j2.auth.method.UserAdmin;

import jakarta.ws.rs.HttpMethod;

public abstract class TAXIISecurityHandler extends SecurityHandler {

	protected final RoleInfo anyRoleInfo = new RoleInfo();
	protected final static Logger logger = LogManager.getLogger(TAXIISecurityHandler.class);

	private final UserAdminLoginService loginService;
	private final HybridAuthenticator authenticator;

	protected TAXIISecurityHandler(UserAdminLoginService loginService,
			HybridAuthenticator authenticator) {

		super();
		this.loginService = loginService;
		this.authenticator = authenticator;

		AuthConfig authConfig = PropsAuthConfig.instance();

		String pass = authConfig.getTaxiiAdminPassword();
		if (pass == null) {
			logger.fatal("TAXII_PASSWORD must be specified!!!");
			System.exit(-1);
		}

		setLoginService(loginService);
		setAuthenticator(authenticator);
		setRealmName(authConfig.getRealm());

		anyRoleInfo.setAnyRole(true);
		anyRoleInfo.setAnyAuth(true);

	}

	@Override
	protected boolean checkUserDataPermissions(String pathInContext, Request request, Response response,
			RoleInfo constraintInfo) throws IOException {
		return true;
	}

	@Override
	protected boolean isAuthMandatory(Request baseRequest, Response baseResponse, Object constraintInfo) {
		if (!baseRequest.hasMetaData()) {
			return true;
		}
		String method = baseRequest.getMetaData().getMethod();
		if (method.equals(HttpMethod.OPTIONS)) {
			/*
			 * all OPTIONS are free...
			 */
			return false;
		}
		return true;
	}

	@Override
	protected boolean checkWebResourcePermissions(String pathInContext, Request request, Response response,
			Object constraintInfo, UserIdentity userIdentity) throws IOException {
		if (constraintInfo == null) {
			return false;
		}
		RoleInfo roleInfo = RoleInfo.class.cast(constraintInfo);
		if (roleInfo.isAnyRole()) {
			return true;
		}
		for (String role : roleInfo.getRoles()) {
			if (userIdentity.isUserInRole(role)) {
				return true;
			}
		}
		return false;
	}

	public void setUserAdmin(UserAdmin userAdmin) {
		loginService.setUserAdmin(userAdmin);
		authenticator.setUserAdmin(userAdmin);
	}

	public void setIssuerAdmin(IssuerAdmin issuerAdmin) {
		authenticator.setIssuerAdmin(issuerAdmin);
	}

	public void setRootCollectionRead(RootCollectionRead rcr) {

	}
}
