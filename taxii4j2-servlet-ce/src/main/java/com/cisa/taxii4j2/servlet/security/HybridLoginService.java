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
import java.util.function.Function;

import javax.security.auth.Subject;

import org.eclipse.jetty.security.RolePrincipal;
import org.eclipse.jetty.security.UserPrincipal;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Session;
import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.util.security.Credential;

import com.cisa.taxii4j2.auth.data.TAXIICredentials;
import com.cisa.taxii4j2.auth.data.User;

public class HybridLoginService extends UserAdminLoginService {

	public HybridLoginService() {
		super();
	}

	@Override
	protected List<RolePrincipal> loadRoleInfo(UserPrincipal user) {
//		protected String[] loadRoleInfo(UserPrincipal user) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected UserPrincipal loadUserInfo(String username) {
		// TODO Auto-generated method stub
		return null;
	}

	private static final Credential freePass = new Credential() {

		private static final long serialVersionUID = 1L;

		@Override
		public boolean check(Object credentials) {
			return true;
		}

	};

	@Override
	public UserIdentity login(String username, Object _credentials, Request request, Function<Boolean, Session> getOrCreateSession) {

		/*
		 * get user info for known and unknown...
		 */
		User unknownUser = TAXIICredentials.getUser(String.class.cast(_credentials));
		if (unknownUser == null) {
			return null;
		}
		username = unknownUser.getUser();
		User knownUser = userAdmin.readUserByName(username);

		/*
		 * authenticate here and put get out of jail free card on returned identity...
		 */

//		String knownPassword = (knownUser != null) ? knownUser.getPassword() : null;
//		String unknownPassword = unknownUser.getPassword();
//		if (knownPassword != null) {
//			if ((unknownPassword == null) || !knownPassword.equalsIgnoreCase(unknownPassword)) {
//				return null;
//			}
//		} else if (unknownPassword != null) {
//			return null;
//		}

		String knownPassword = (knownUser != null) ? knownUser.getPassword() : null;
		String unknownPassword = unknownUser.getPassword();
		// Unknown password will be null for OIDC and mTLS authentication
		if(unknownPassword != null) {
			if ((knownPassword != null) && (knownPassword.startsWith(User.PBKDF2_HASH))) {
				String[] splits = knownPassword.split(":");
				unknownPassword = User.hash(unknownPassword, splits[1]);
			} else if ((knownPassword != null) && (knownPassword.startsWith(User.MD5_HASH))) {
				unknownPassword = User.hash(unknownPassword);
			}
			if ((knownPassword == null) || !knownPassword.equalsIgnoreCase(unknownPassword)) {
				return null;
			}
		}

		/*
		 * build out identity...
		 */
		UserPrincipal userPrincipal = createUserPrincipal(username, freePass, String.class.cast(_credentials));
		/*
		 * next line uses unknownUser since it is constructed from both incoming roles
		 * and known roles...
		 */
		Set<String> roles = unknownUser.getRoles();
		Subject subject = new Subject();
		subject.getPrincipals().add(userPrincipal);
		if (roles != null) {
			for (String role : roles) {
				subject.getPrincipals().add(new RolePrincipal(role));
			}
		} else {
			roles = Collections.emptySet();
		}
		subject.setReadOnly();
		return _identityService.newUserIdentity(subject, userPrincipal, roles.toArray(String[]::new));
	}

	protected UserPrincipal createUserPrincipal(String username, Credential cred, String header) {
		return new UserPrincipal(username, cred);
	}

}
