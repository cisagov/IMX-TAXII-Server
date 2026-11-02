/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.store;

import java.util.List;

import com.cisa.taxii4j2.auth.data.Fragment;
import com.cisa.taxii4j2.auth.data.User;
import com.cisa.taxii4j2.auth.method.BulkAdmin;
import com.cisa.taxii4j2.auth.method.RootCollectionAdmin;
import com.cisa.taxii4j2.auth.method.UserAdmin;
import com.cisa.taxii4j2.data.Collections.Collection;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
public class DbBulkAdmin implements BulkAdmin {

	private final UserAdmin userAuth;
	private final RootCollectionAdmin rcAdmin;

	@Inject
	public DbBulkAdmin(UserAdmin userAuth, RootCollectionAdmin rcAdmin) {
		super();
		this.userAuth = userAuth;
		this.rcAdmin = rcAdmin;
	}

	@Override
	public Configuration configure(Configuration configuration) throws Exception {

		List<Collection> collections = configuration.getCollections();
		if (collections != null) {
			collections.forEach(c -> {
				try {
					rcAdmin.upsertCollection(c, false);
				} catch (Exception e) {
					// OK
				}
			});
			rcAdmin.refreshCollections();
		}

		List<Fragment> fragments = configuration.getFragments();
		if (fragments != null) {
			fragments.forEach(f -> {
				try {
					rcAdmin.upsertFragment(f, false);
				} catch (Exception e) {
					// OK
				}
			});
			rcAdmin.refreshFragments();
		}

		List<User> users = configuration.getUsers();
		if (users != null) {
			users.forEach(u -> {
				userAuth.upsertUser(u, false);
			});
			userAuth.refreshUsers();
		}

		return new Configuration(rcAdmin.listCollections(), rcAdmin.listFragments(), userAuth.listUsers());
	}

}
