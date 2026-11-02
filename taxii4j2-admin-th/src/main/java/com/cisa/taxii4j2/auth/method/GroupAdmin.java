/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.method;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

public interface GroupAdmin {

	@JsonInclude(Include.NON_NULL)
	public static class Group {

		private static final String nameKey = "name";
		private static final String markingsKey = "markings";
		private static final String usersKey = "users";

		@JsonProperty(nameKey)
		private String name;

		@JsonProperty(markingsKey)
		private Set<String> markings;

		@JsonProperty(usersKey)
		private Set<String> users;

		@JsonCreator
		public Group(@JsonProperty(value = nameKey, required = true) String name,
				@JsonProperty( value = markingsKey, required = true) Set<String> markings,
				@JsonProperty( value = usersKey, required = false ) Set<String> users) {
			super();
			this.name = name;
			setMarkings(markings);
			setUsers(users);
		}

		public String getName() {
			return name;
		}

		public void setMarkings(Set<String> markings) {
			this.markings = (markings == null) ? new HashSet<>() : markings;
		}

		public Set<String> getMarkings() {
			return markings;
		}

		public void setUsers(Set<String> users) {
			this.users = (users == null) ? new HashSet<>() : users;
		}

		public Set<String> getUsers() {
			return users;
		}
	}

	public Collection<Group> list();

	public Group read(String groupName);

	public Set<String> getAllMarkings(List<String> groups);

	public Set<String> getMarkingsForUser(String username);

	public Group upsert(Group group);

	public Group addUsers(String groupName, Set<String> users, boolean remove);

	public Group addMarkings(String groupName, Set<String> markings, boolean remove);

	public void delete(String groupName);

}
