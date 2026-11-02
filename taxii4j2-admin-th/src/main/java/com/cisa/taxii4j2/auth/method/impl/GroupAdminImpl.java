/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.method.impl;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.cisa.taxii4j2.auth.method.GroupAdmin;
import com.cisa.taxii4j2.servlet.store.DbBase;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
public class GroupAdminImpl implements GroupAdmin {

	private final String groupIndex;
	private final DbBase db;

	private Map<String, Group> groupMap = new ConcurrentHashMap<>();

	@Inject
	public GroupAdminImpl(DbBase db) {
		super();
		this.db = db;
		this.groupIndex = db.createIndex(db.localizeIndexName("groups"));

		for (Group group: db.list(groupIndex, Group.class)) {
			groupMap.put(group.getName(), group);
		}
	}

	@Override
	public Collection<Group> list() {
		return groupMap.values();
	}

	@Override
	public Group read(String groupName) {
		return groupMap.get(groupName);
	}

	@Override
	public Set<String> getAllMarkings(List<String> groups) {
		Set<String> markings = new HashSet<>();
		for (String groupName: groups) {
			Group group = read(groupName);
			if ((group != null) && (group.getMarkings() != null))
				markings.addAll(group.getMarkings());
		}
		return markings;
	}

	@Override
	public Set<String> getMarkingsForUser(String username) {
		Set<String> markings = new HashSet<>();
		for (Group group: list()) {
			if (group.getUsers().contains(username)) {
				markings.addAll(group.getMarkings());
			}
		}
		return markings;
	}

	@Override
	public Group upsert(Group group) {
		String name = group.getName();
		groupMap.put(name, db.put(group, groupIndex, name));
		return read(name);
	}

	@Override
	public Group addUsers(String groupName, Set<String> users, boolean remove) {
		Group group = read(groupName);
		synchronized (group) {
			Set<String> allUsers = group.getUsers();
			if (remove) {
				allUsers.removeAll(users);
			} else {
				allUsers.addAll(users);
			}
			group.setUsers(allUsers);
			db.put(group, groupIndex, groupName);
		}
		return group;
	}

	@Override
	public Group addMarkings(String groupName, Set<String> markings, boolean remove) {
		Group group = read(groupName);
		synchronized (group) {
			Set<String> allMarkings = group.getMarkings();
			if (remove) {
				allMarkings.removeAll(markings);
			} else {
				allMarkings.addAll(markings);
			}
			group.setMarkings(allMarkings);
			db.put(group, groupIndex, groupName);
		}
		return group;
	}

	@Override
	public void delete(String groupName) {
		groupMap.remove(groupName);
		db.delete(groupName, groupIndex, Group.class);
	}

}
