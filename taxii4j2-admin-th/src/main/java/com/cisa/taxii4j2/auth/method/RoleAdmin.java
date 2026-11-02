/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.method;

import java.util.Set;
import java.util.TreeSet;

import org.jvnet.hk2.annotations.Contract;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

@Contract
public interface RoleAdmin {

	@JsonInclude(Include.NON_NULL)
	public static class Privilege implements Comparable<Privilege> {

		private static final String fragmentKey = "api_root";
		private static final String cIdKey = "collection_id";
		private static final String can_readKey = "can_read";
		private static final String can_writeKey = "can_write";

		@JsonProperty(fragmentKey)
		private final String fragment;

		@JsonProperty(cIdKey)
		private final String cId;

		@JsonProperty(can_readKey)
		private boolean can_read;

		@JsonProperty(can_writeKey)
		private boolean can_write;

		@JsonCreator
		public Privilege(@JsonProperty(value = fragmentKey, required = true) String fragment,
				@JsonProperty(value = cIdKey, required = true) String cId,
				@JsonProperty(value = can_readKey, required = true) boolean can_read,
				@JsonProperty(value = can_writeKey, required = true) boolean can_write) {
			super();
			this.fragment = fragment;
			this.cId = cId;
			this.can_read = can_read;
			this.can_write = can_write;
		}

		public boolean isCan_read() {
			return can_read;
		}

		public boolean isCan_write() {
			return can_write;
		}

		public String getFragment() {
			return fragment;
		}

		public String getcId() {
			return cId;
		}

		@Override
		public int compareTo(Privilege other) {
			int c = fragment.compareTo(other.fragment);
			if (c == 0) {
				c = cId.compareTo(other.cId);
			}
			return c;
		}

	}

	@JsonInclude(Include.NON_NULL)
	public static class RoleUse {

		private static final String privilegesKey = "privileges";
		private static final String user_namesKey = "user_names";

		@JsonProperty(privilegesKey)
		private Set<Privilege> privileges;

		@JsonProperty(user_namesKey)
		private Set<String> user_names;

		@JsonCreator
		public RoleUse(@JsonProperty(value = privilegesKey, required = false) Set<Privilege> privileges,
				@JsonProperty(value = user_namesKey, required = false) Set<String> user_names) {
			super();
			setPrivileges(privileges);
			setUser_names(user_names);
		}

		public RoleUse() {
			super();
		}

		public Set<Privilege> getPrivileges() {
			return privileges;
		}

		public void setPrivileges(Set<Privilege> privileges) {
			this.privileges = null;
			if ((privileges != null) && !privileges.isEmpty()) {
				this.privileges = new TreeSet<>(privileges);
			}
		}

		@JsonIgnore
		public void add(Privilege privilege) {
			if (privileges == null) {
				privileges = new TreeSet<>();
			}
			privileges.add(privilege);
		}

		public Set<String> getUser_names() {
			return user_names;
		}

		public void setUser_names(Set<String> user_names) {
			this.user_names = null;
			if ((user_names != null) && !user_names.isEmpty()) {
				this.user_names = new TreeSet<>(user_names);
			}
		}

		@JsonIgnore
		public void add(String user_name) {
			if (user_names == null) {
				user_names = new TreeSet<>();
			}
			user_names.add(user_name);
		}

		@JsonIgnore
		public boolean isEmpty() {
			return (privileges == null) && (user_names == null);
		}

	}

	public Set<String> list();

	public RoleUse read(String role);

	public RoleUse upsert(String role, RoleUse roleUse);

	public void delete(String role);

}
