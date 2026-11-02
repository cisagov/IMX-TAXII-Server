/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.security;

import java.util.Collections;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.jetty.ee9.security.RoleInfo;
import org.eclipse.jetty.ee9.nested.Request;

import com.cisa.taxii4j2.auth.data.Fragment;
import com.cisa.taxii4j2.auth.data.RWCollection;
import com.cisa.taxii4j2.auth.method.AuthConfig;
import com.cisa.taxii4j2.auth.method.PropsAuthConfig;
import com.cisa.taxii4j2.auth.method.RootCollectionRead;
import com.cisa.taxii4j2.data.impl.Hosts;
import com.cisa.taxii4j2.data.impl.PropsHosts;

import jakarta.inject.Singleton;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.NotFoundException;

@Singleton
public class RBACSecurityHandler extends TAXIISecurityHandler {

	private final RoleInfo userRoleInfo = new RoleInfo();
	private final RoleInfo adminRoleInfo = new RoleInfo();
	private final RoleInfo noRoleInfo = new RoleInfo();

	private static final String prefixFmt = "/%s";

	private final String pingPrefix = "/ping/";

	private final String adminPrefix;
	private final String schemaRepoPrefix;
	private final String taxiiPrefix;
	private final String searchPrefix;

	private static final String fragmentFmt = "(.+?)/";
	private final Pattern statusPattern = Pattern.compile(fragmentFmt + "status/.+?/$");
	private final Pattern collectionsPattern = Pattern
//			.compile(fragmentFmt + "(collections/((.+?)/((manifest/)|(objects/(.+?/(versions/)?)?))?)?)?$").matcher("");
			.compile(fragmentFmt + "(collections/((.+?)/(.*))?)?");

	private static final String taxii2 = "taxii2";

	private RootCollectionRead rcr;

	private static final Set<String> read = Set.of(HttpMethod.GET);
	private static final Set<String> write = Set.of(HttpMethod.POST, HttpMethod.DELETE);

	public RBACSecurityHandler() {

		super(new HybridLoginServiceTH(), new HybridAuthenticatorTH());

		AuthConfig authConfig = PropsAuthConfig.instance();
		userRoleInfo.addRole(authConfig.getUserRole());
		adminRoleInfo.addRole(authConfig.getAdminRole());

		Hosts hosts = PropsHosts.instance();
		adminPrefix = String.format(prefixFmt, hosts.adminPath());
		schemaRepoPrefix = String.format(prefixFmt, hosts.schemaRepoPath());
		taxiiPrefix = String.format(prefixFmt, hosts.taxiiPath());
		searchPrefix = String.format(prefixFmt, hosts.searchPath());

	}

	@Override
	protected RoleInfo prepareConstraintInfo(String pathInContext, Request request) {

		/*
		 * OPTIONS method -> any role
		 */
		String method = request.getMetaData().getMethod();
		if (method.equals(HttpMethod.OPTIONS)) {
			logger.debug(String.format("OPTIONS -> anyRoleinfo %s", anyRoleInfo));
			return anyRoleInfo;
		}

		if(pathInContext.startsWith(pingPrefix)) {
			return anyRoleInfo;
		}

		/*
		 * admin paths GET -> any role, else -> admin role
		 */
		if (pathInContext.startsWith(adminPrefix)) {
			RoleInfo roleInfo = method.equals(HttpMethod.GET) ? anyRoleInfo : adminRoleInfo;
			logger.debug(String.format("adminPrefix -> %s", roleInfo));
			return roleInfo;
		}

		/*
		 * all schema repo paths -> user role
		 */
		if (pathInContext.startsWith(schemaRepoPrefix)) {
			logger.debug(String.format("schema -> userRoleinfo %s", userRoleInfo));
			return userRoleInfo;
		}

		String suffix = null;
		if (pathInContext.startsWith(taxiiPrefix)) {
			suffix = pathInContext.substring(taxiiPrefix.length());
		}
		if (pathInContext.startsWith(searchPrefix)) {
//			suffix = pathInContext.substring(searchPrefix.length());
			return userRoleInfo;
		}

		/*
		 * bogus prefix (not one of the magic four).
		 */
		if (suffix == null) {
			if (pathInContext.startsWith("/taxii")) {
				logger.debug(String.format("/taxii -> adminRoleinfo %s", adminRoleInfo));
				return adminRoleInfo;
			}
			if (pathInContext.startsWith("/A1")) {
				logger.debug(String.format("/A1 -> userRoleinfo %s", anyRoleInfo));
				return anyRoleInfo;
			}
			if (pathInContext.startsWith("/misp")) {
				logger.debug(String.format("/misp -> userRoleinfo %s", anyRoleInfo));
				return anyRoleInfo;
			}
			return null;
		}

		/*
		 * status path -> user role
		 */
		Matcher statusMatcher = statusPattern.matcher(suffix);
		if (statusMatcher.matches()) {
			return userRoleInfo;
		}

		/*
		 * begin collections paths parsing
		 */
		Matcher collectionsMatcher = collectionsPattern.matcher(suffix);
		if (!collectionsMatcher.matches()) {
			/*
			 * not a collections path
			 */
			return null;
		}

		String fragment = collectionsMatcher.group(1);
		String cId = collectionsMatcher.group(4);
		String tail = collectionsMatcher.group(5);

		/*
		 * taxii2 handling
		 */
		if (fragment.equals(taxii2)) {
			return (cId == null) ? anyRoleInfo : null;
		}

		/*
		 * if not a fragment, some other path?
		 */
		try {
			rcr.readFragment(fragment);
		} catch (NotFoundException e) {
			return anyRoleInfo;
		}

		/*
		 * check for ^{api-root}/collections/$
		 */
		if (cId == null) {
			return anyRoleInfo;
		}

		/*
		 * resolve collection to id
		 */
		try {
			cId = rcr.readCollection(cId).getId();
		} catch(NotFoundException e) {
			// If the collection doesn't exist, let it through so we can return a 404 from the method.
			return anyRoleInfo;
		}

		/*
		 * check sandbox
		 */
		if (rcr.sandboxMap().getOrDefault(fragment, Collections.emptySet()).contains(cId)) {
			return anyRoleInfo;
		}

		/*
		 * check for ^{api-root}/collections/{id}/$
		 */
		if ((tail == null) || tail.isEmpty()) {
			return anyRoleInfo;
		}

		/*
		 * build from api-root / collection mappings
		 */
		RoleInfo roleInfo = new RoleInfo();
		try {
			Fragment f = rcr.readFragment(fragment);
			RWCollection rw = f.getRw(cId);
			if (rw == null) {
				return roleInfo;
			}
			Set<String> roles = read.contains(method) ? rw.getReaders()
					: (write.contains(method) ? rw.getWriters() : null);
			if (roles == null) {
				return roleInfo;
			}
			roles.forEach(role -> roleInfo.addRole(role));
			return roleInfo;
		} catch (Exception e) {
			return roleInfo;
		}

	}

	@Override
	public void setRootCollectionRead(RootCollectionRead rcr) {
		this.rcr = rcr;
	}

}
