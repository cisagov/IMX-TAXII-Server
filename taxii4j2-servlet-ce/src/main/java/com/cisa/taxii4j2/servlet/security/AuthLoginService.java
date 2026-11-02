/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.security;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.eclipse.jetty.security.AbstractLoginService;
import org.eclipse.jetty.security.RolePrincipal;
import org.eclipse.jetty.security.UserPrincipal;
import org.eclipse.jetty.util.security.Credential;

import com.cisa.taxii4j2.auth.data.User;
import com.cisa.taxii4j2.auth.method.UserAdmin;

public class AuthLoginService extends AbstractLoginService {

	protected final UserAdmin auth;

	public AuthLoginService(UserAdmin auth) {
		super();
		this.auth = auth;
	}

	@Override
	protected List<RolePrincipal> loadRoleInfo(UserPrincipal user) {
//		protected String[] loadRoleInfo(UserPrincipal user) {
		try {
			User authUser = auth.readUserByName(user.getName());
			Set<String> roles = authUser.getRoles();
			return (roles != null) ? roles.stream().map(r -> new RolePrincipal(r)).collect(Collectors.toList()) :
				Collections.emptyList();
//			return (roles != null) ? roles.toArray(String[]::new) : new String[0];
		} catch (Exception e) {
			return Collections.emptyList();
//			return new String[0];
		}
	}

	@Override
	protected UserPrincipal loadUserInfo(String username) {
		try {
			User user = auth.readUserByName(username);
			return (user != null) ? new UserPrincipal(user.getUser(), Credential.getCredential(user.getPassword()))
					: null;
		} catch (Exception e) {
			return null;
		}
	}

}
