/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.store;

import java.util.List;

import com.cisa.taxii4j2.auth.data.User;
import com.cisa.taxii4j2.auth.method.UserAdmin;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response.Status;

@Singleton
public class DbUserAdmin implements UserAdmin {

	private final String userIndex;

	private final DbBase db;

	// Password complexity requirements
    // Regex requires:
    // At least 12 characters (?=.{12,})
    // At least one digit (?=.*[0-9])
    // At least one lowercase letter (?=.*[a-z])
    // At least one uppercase letter (?=.*[A-Z])
    // At least one special character (?=.*[!@#$%^&*()\\-+=])
    // No whitespace (\\S+$)
    private static final String PASSWORD_REGEX =
        "^(?=.{12,})(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()\\-+=])(?=\\S+$).{12,20}$";

    public boolean isValid(String password) {
        return password.matches(PASSWORD_REGEX);
    }


	@Inject
	public DbUserAdmin(DbBase db) {
		super();
		this.db = db;
		userIndex = db.createIndex(db.localizeIndexName("users"));
	}

	@Override
	public User upsertUser(User user, boolean create) {
		String username = user.getUser();
		try {
			User found = readUserByName(username);
			if ((found != null) && create) {
				throw new BadRequestException(
						String.format("ESUserAdmin.upsertUser: create was requested but user \"%s\" exists", username));

			}
		} catch (NotFoundException e) {
			// ok - fall through
		}
		if (user.getPassword() != null) {
			user.setPassword(user.getPassword());
		}
		return db.put(user, userIndex, user.getUser(), create);
	}

	@Override
	public User readUserByName(String user) {
		try {
			return db.get(user, userIndex, User.class);
		} catch (NotFoundException e) {
			return null;
//			throw new NotFoundException(String.format("\"%s\" is an unknown user", user), e);
		}
	}

	@Override
	public List<User> listUsers() {
		return db.list(userIndex, User.class, DbBase.maxSize);
	}

	@Override
	public User deleteUser(String user) {
		readUserByName(user);
		return db.delete(user, userIndex, User.class);
	}

	@Override
	public User setPassword(String user, String hash) {
		if (!isValid(hash)) {
			throw new ClientErrorException("Password must be at least 12 characters, and contain at least one uppper case letter, one lower case letter, one number and one special character", Status.BAD_REQUEST);
		}
		return db.put(readUserByName(user).setPassword(hash), userIndex, user, false);
	}

	@Override
	public User addRole(String user, String role) {
		return db.put(readUserByName(user).addRole(role), userIndex, user, false);
	}

	@Override
	public User removeRole(String user, String role) {
		return db.put(readUserByName(user).removeRole(role), userIndex, user, false);
	}

	@Override
	public void refreshUsers() {
		db.refresh(userIndex);
	}

}
