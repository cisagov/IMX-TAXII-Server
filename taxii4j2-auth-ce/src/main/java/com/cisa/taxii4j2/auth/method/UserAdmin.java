/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.method;

import java.util.List;

import com.cisa.taxii4j2.auth.data.User;

/**
 * The philosophy here is that members of object can be read but writing them
 * requires a method (in case it requires side effects)...
 */
public interface UserAdmin {

	public User upsertUser(User user, boolean create);

	public User readUserByName(String user);

	public List<User> listUsers();

	public User deleteUser(String user);

	public User setPassword(String user, String hash);

	public User addRole(String user, String role);

	public User removeRole(String user, String role);

	public void refreshUsers();

}
