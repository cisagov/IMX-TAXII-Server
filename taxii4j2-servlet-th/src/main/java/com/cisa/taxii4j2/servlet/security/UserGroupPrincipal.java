/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.security;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.security.UserPrincipal;
import org.eclipse.jetty.util.security.Credential;

public class UserGroupPrincipal extends UserPrincipal {

	private static final long serialVersionUID = -7158235383244844806L;

	private List<String> groups;

	public UserGroupPrincipal(String username, Credential credential) {
		super(username, credential);
		groups = new ArrayList<>();
	}

	public void addGroups(List<String> newGroups) {
		groups.addAll(newGroups);
	}

	public List<String> groups() {
		return groups;
	}
}
