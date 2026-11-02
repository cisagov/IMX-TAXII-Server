/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.method;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.jvnet.hk2.annotations.Contract;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.taxii4j2.auth.data.Fragment;
import com.cisa.taxii4j2.auth.data.User;
import com.cisa.taxii4j2.data.Collections.Collection;

@Contract
public interface BulkAdmin extends Closeable {

	@JsonInclude(Include.NON_NULL)
	public static class Configuration {

		private static final String collectionsKey = "collections";
		private static final String fragmentsKey = "fragments";
		private static final String usersKey = "users";

		@JsonProperty(collectionsKey)
		private List<Collection> collections;

		@JsonProperty(fragmentsKey)
		private List<Fragment> fragments;

		@JsonProperty(usersKey)
		private List<User> users;

		@JsonCreator
		public Configuration(@JsonProperty(value = collectionsKey, required = false) List<Collection> collections,
				@JsonProperty(value = fragmentsKey, required = false) List<Fragment> fragments,
				@JsonProperty(value = usersKey, required = false) List<User> users) {
			super();
			setCollections(collections);
			setFragments(fragments);
			setUsers(users);
		}

		public List<Collection> getCollections() {
			return collections;
		}

		public void setCollections(List<Collection> collections) {
			this.collections = ((collections != null) && !collections.isEmpty()) ? collections : null;
		}

		public List<Fragment> getFragments() {
			return fragments;
		}

		public void setFragments(List<Fragment> fragments) {
			this.fragments = ((fragments != null) && !fragments.isEmpty()) ? fragments : null;;
		}

		public List<User> getUsers() {
			return users;
		}

		public void setUsers(List<User> users) {
			this.users = ((users != null) && !users.isEmpty()) ? users : null;
		}

		public Configuration addCollections(List<Collection> collection) {
			if (collections == null) {
				collections = new ArrayList<>();
			}
			collections.addAll(collection);
			return this;
		}

		public Configuration addFragments(List<Fragment> fragment) {
			if (fragments == null) {
				fragments = new ArrayList<>();
			}
			fragments.addAll(fragment);
			return this;
		}

		public Configuration addUsers(List<User> user) {
			if (users == null) {
				users = new ArrayList<>();
			}
			users.addAll(user);
			return this;
		}
	}

	public Configuration configure(Configuration configuration) throws Exception;

	@Override
	default void close() throws IOException {

	}

}
