/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.method.impl;

import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;

import com.cisa.taxii4j2.auth.data.Fragment;
import com.cisa.taxii4j2.auth.data.RWCollection;
import com.cisa.taxii4j2.auth.data.User;
import com.cisa.taxii4j2.auth.method.PropsAuthConfig;
import com.cisa.taxii4j2.auth.method.RoleAdmin;
import com.cisa.taxii4j2.auth.method.RootCollectionAdmin;
import com.cisa.taxii4j2.auth.method.UserAdmin;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;

@Singleton
public class RoleAdminImpl implements RoleAdmin {

	private final RootCollectionAdmin rcAdmin;
	private final UserAdmin userAdmin;
	private final Set<String> untouchables;

	@Inject
	public RoleAdminImpl(RootCollectionAdmin rcAdmin, UserAdmin userAdmin) {
		super();
		this.rcAdmin = rcAdmin;
		this.userAdmin = userAdmin;
		untouchables = new TreeSet<>(PropsAuthConfig.instance().getRoles());
	}

	@Override
	synchronized public Set<String> list() {
		Set<String> roles = new TreeSet<>();
		for (Fragment fragment : rcAdmin.listFragments()) {
			try {
				for (RWCollection rw : fragment.getRws()) {
					Set<String> readers = rw.getReaders();
					if (readers != null) {
						roles.addAll(rw.getReaders());
					}
					Set<String> writers = rw.getWriters();
					if (writers != null) {
						roles.addAll(rw.getWriters());
					}
				}
			} catch (NullPointerException e) {

			}
		}
		for (User user : userAdmin.listUsers()) {
			Set<String> userRoles = user.getRoles();
			if (userRoles != null) {
				roles.addAll(userRoles);
			}
		}
		return roles;
	}

	@Override
	synchronized public RoleUse read(String role) {
		RoleUse roleUse = new RoleUse();
		for (Fragment fragment : rcAdmin.listFragments()) {
			String api_root = fragment.getFragment();
			try {
				for (RWCollection rw : fragment.getRws()) {
					String collection_id = rw.getId();
					boolean can_read = rw.isCan_read(role);
					boolean can_write = rw.isCan_write(role);
					if (can_read || can_write) {
						roleUse.add(new Privilege(api_root, collection_id, can_read, can_write));
					}
				}
			} catch (NullPointerException e) {

			}
		}
		for (User user : userAdmin.listUsers()) {
			if (user.isRole(role)) {
				roleUse.add(user.getUser());
			}
		}
		if (roleUse.isEmpty()) {
			throw new NotFoundException();
		}
		return roleUse;
	}

	@Override
	synchronized public RoleUse upsert(String role, RoleUse roleUse) {
		Set<Privilege> privileges = roleUse.getPrivileges();
		if (privileges != null) {
			for (Privilege rw : privileges) {
				String fragment = rw.getFragment();
				String cId = rw.getcId();
				if (rw.isCan_read()) {
					notFoundOk(() -> rcAdmin.addCan_read(fragment, cId, role));
				} else {
					notFoundOk(() -> rcAdmin.removeCan_read(fragment, cId, role));
				}
				if (rw.isCan_write()) {
					notFoundOk(() -> rcAdmin.addCan_write(fragment, cId, role));
				} else {
					notFoundOk(() -> rcAdmin.removeCan_write(fragment, cId, role));
				}
			}
		}
		Set<String> user_names = roleUse.getUser_names();
		if (user_names != null) {
			for (String user_name : user_names) {
				userAdmin.addRole(user_name, role);
			}
		}
		return read(role);
	}

	@Override
	synchronized public void delete(String role) {
		if (untouchables.contains(role)) {
			throw new BadRequestException(String.format("Reserved role \"%s\" can't be deleted", role));
		}
		RoleUse roleUse = read(role);
		Set<Privilege> privileges = roleUse.getPrivileges();
		if (privileges != null) {
			for (Privilege rw : privileges) {
				String fragment = rw.getFragment();
				String cId = rw.getcId();
				if (rw.isCan_read()) {
					notFoundOk(() -> rcAdmin.removeCan_read(fragment, cId, role));
				}
				if (rw.isCan_write()) {
					notFoundOk(() -> rcAdmin.removeCan_write(fragment, cId, role));
				}
			}
		}
		Set<String> user_names = roleUse.getUser_names();
		if (user_names != null) {
			for (String user_name : user_names) {
				notFoundOk(() -> userAdmin.removeRole(user_name, role));
			}
		}
	}

	private <T> T notFoundOk(Supplier<T> f) {
		try {
			return f.get();
		} catch (NotFoundException e) {
			return null;
		} catch (Exception e) {
			throw new BadRequestException(e);
		}
	}

}
