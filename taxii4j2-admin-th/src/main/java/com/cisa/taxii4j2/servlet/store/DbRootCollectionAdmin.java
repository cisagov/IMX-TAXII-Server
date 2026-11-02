/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.store;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;

import com.cisa.taxii4j2.auth.data.Fragment;
import com.cisa.taxii4j2.auth.data.Lenient;
import com.cisa.taxii4j2.auth.data.RWCollection;
import com.cisa.taxii4j2.auth.method.RootCollectionAdmin;
import com.cisa.taxii4j2.data.ApiRoot;
import com.cisa.taxii4j2.data.Collections.Collection;

import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;

public class DbRootCollectionAdmin extends DbRootCollectionRead implements RootCollectionAdmin {

	private void pHelper(RWCollection rw, Set<String> roles, Set<Collection> inner) {
		String cId = rw.getId();
		Collection c = readCollection(cId);
		boolean can_read = c.isCan_read();
		if (can_read) {
			Set<String> readers = rw.getReaders();
			if (readers != null) {
				Set<String> conjunct = new TreeSet<>(readers);
				conjunct.retainAll(roles);
				can_read = !conjunct.isEmpty();
			} else {
				can_read = false;
			}
		}
		boolean can_write = c.isCan_write();
		if (can_write) {
			Set<String> writers = rw.getWriters();
			if (writers != null) {
				Set<String> conjunct = new TreeSet<>(writers);
				conjunct.retainAll(roles);
				can_write = !conjunct.isEmpty();
			} else {
				can_write = false;
			}
		}
		if (can_read || can_write) {
			c.setCan_read(can_read);
			c.setCan_write(can_write);
			inner.add(c);
		}
	}

	private void pHelper(String cId, Set<Collection> inner) {
		Collection c = readCollection(cId);
		if (c.isCan_read() || c.isCan_write()) {
			inner.remove(c);
			inner.add(c);
		}
	}

	@Override
	public List<RootPermissions> permissions(Set<String> roles) {
		Map<String, Set<String>> sandbox = sandboxMap();
		List<RootPermissions> outer = new ArrayList<>();
		for (Fragment f : listFragments()) {
			String fragment = f.getFragment();
			Set<Collection> inner = new TreeSet<>();
			try {
				for (RWCollection rw : f.getRws()) {
					pHelper(rw, roles, inner);
				}
			} catch (NullPointerException e) {

			}
			for (String cId : sandbox.getOrDefault(fragment, Collections.emptySet())) {
				pHelper(cId, inner);
			}
			if (!inner.isEmpty()) {
				outer.add(new RootPermissions(fragment, inner));
			}
		}
		return outer;
	}

	private final String sandboxIndex;

	@Inject
	public DbRootCollectionAdmin(DbBase db, CollectionRead collectionRead) {
		super(db, collectionRead);
		sandboxIndex = db.localizeIndexName("sandbox");
	}

	public Fragment upsertFragment(Fragment fragment, boolean create) {
		String name = fragment.getFragment();
		try {
			readFragment(name);
			if (create) {
				throw new BadRequestException(
						String.format("ESAdmin.upsertFragment: create was requested but %s exists", name));
			}
		} catch (NotFoundException e) {
			// ok - fall through
		}
		return db.put(fragment, fragmentIndex, name, create);
	}

	@Override
	public Collection upsertCollection(Collection collection, boolean create) {
		String cId = collection.getId();
		try {
			UUID.fromString(cId);
			readCollection(cId);
			if (create) {
				throw new BadRequestException(
						String.format("ESAdmin.upsertCollection: create was requested but %s exists", cId));
			}
		} catch (IllegalArgumentException e) {
			throw new BadRequestException(String.format("ESAdmin.upsertCollection: %s must be UUID", cId), e);
		} catch (NotFoundException e) {
			// ok - fall through
		}
		return db.put(collection, collectionIndex, cId, create);
	}

	@Override
	public Fragment deleteFragment(String name) {
		Fragment fragment = readFragment(name);
		List<RWCollection> rws = fragment.getRws();
		if ((rws != null) && !rws.isEmpty()) {
			StringBuilder ais = new StringBuilder();
			StringBuilder tis = new StringBuilder();
			for (RWCollection rw : rws) {

				Collection c = readCollection(rw.getId());

				if (ais.length() != 0) {
					ais.append(", ");
				}
				String ai = c.getAlias();
				ais.append((ai != null) ? String.format("\"%s\"", ai) : c.getId());

				if (tis.length() != 0) {
					tis.append("; ");
				}
				tis.append(String.format("title: \"%s\", id: %s", c.getTitle(), c.getId()));

			}
			throw new BadRequestException(String.format(
					"api-root path \"%s\" is still using %s; delete collection references first (%s respectively)",
					name, ais, tis));
		}
		return db.delete(name, fragmentIndex, Fragment.class);
	}

	@Override
	public Collection deleteCollection(String cId) {
		Collection c = readCollection(cId);
		String resolved = resolve(cId);
		RWCollection key = new RWCollection(resolved);
		Set<String> in = new HashSet<>();
		for (Fragment fragment : listFragments()) {
			List<RWCollection> rws = fragment.getRws();
			if ((rws != null) && (java.util.Collections.binarySearch(rws, key) >= 0)) {
				in.add(fragment.getFragment());
			}
		}
		if (!in.isEmpty()) {
			String alias = c.getAlias();
			StringBuilder ai = new StringBuilder();
			if (alias != null) {
				ai.append(String.format("alias: \"%s\", ", alias));
			}
			ai.append(String.format("id: %s", c.getId()));
			throw new BadRequestException(String.format(
					"collection titled \"%s\" is still being used by api-root(s) on path(s) %s; delete api-root dependencies first (%s)",
					c.getTitle(), in, ai));
		}
		return db.delete(resolved, collectionIndex, Collection.class); // (c.setCan_read(false).setCan_write(false));
	}

	@Override
	public Fragment addCan_write(String name, String cId, String writer) {
		return db.put(readFragment(name).addCan_write(resolve(cId), writer), fragmentIndex, name, false);
	}

	@Override
	public Fragment addCan_read(String name, String cId, String reader) {
		return db.put(readFragment(name).addCan_read(resolve(cId), reader), fragmentIndex, name, false);
	}

	@Override
	public Fragment removeCan_write(String name, String cId, String writer) {
		return db.put(readFragment(name).removeCan_write(resolve(cId), writer), fragmentIndex, name, false);
	}

	@Override
	public Fragment removeCan_read(String name, String cId, String reader) {
		return db.put(readFragment(name).removeCan_read(resolve(cId), reader), fragmentIndex, name, false);
	}

	@Override
	public Fragment removeRW(String name, String cId) {
		return db.put(readFragment(name).removeRW(resolve(cId)), fragmentIndex, name, false);
	}

	@Override
	public Fragment addRW(String name, RWCollection rw) {
		return db.put(readFragment(name).addRW(rw), fragmentIndex, name, false);
	}

	@Override
	public Fragment setApiRoot(String name, ApiRoot apiRoot) {
		return db.put(readFragment(name).setApiRoot(apiRoot), fragmentIndex, name, false);
	}

	@Override
	public Collection setDescription(String cId, String description) {
		return updateCollection(readCollection(cId).setDescription(description));
	}

	@Override
	public Collection setAlias(String cId, String alias) {
		return updateCollection(readCollection(cId).setAlias(alias));
	}

	@Override
	public Collection add(String cId, String media_type) {
		return updateCollection(readCollection(cId).add(media_type));
	}

	@Override
	public Collection remove(String cId, String media_type) {
		return updateCollection(readCollection(cId).remove(media_type));
	}

	@Override
	public Collection setCan_read(String cId, boolean can_read) {
		return updateCollection(readCollection(cId).setCan_read(can_read));
	}

	@Override
	public Collection setCan_write(String cId, boolean can_write) {
		return updateCollection(readCollection(cId).setCan_write(can_write));
	}

	@Override
	public Collection setTitle(String cId, String title) {
		return updateCollection(readCollection(cId).setTitle(title));
	}

	private Collection updateCollection(Collection c) {
		return db.put(c, collectionIndex, c.getId(), false);
	}

	private String resolve(String cId) {
		try {
			return UUID.fromString(cId).toString();
		} catch (IllegalArgumentException e) {
			return readCollection(cId).getId();
		}
	}

	@Override
	public void sandboxAdd(List<RootCollection> rcs) {
		for (RootCollection rc : rcs) {
			readFragment(rc.getApi_root());
			String id = sandboxEncode(rc);
			try {
				db.get(id, sandboxIndex, RootCollection.class);
			} catch (Exception e) {
				db.put(rc, sandboxIndex, id);
			}
		}
	}

	/**
	 * Resolves collection alias to id in place as side-effect...
	 *
	 * @param rc
	 * @return
	 */
	private String sandboxEncode(RootCollection rc) {
		return String.format("%s %s", rc.getApi_root(), rc.setCollection(resolve(rc.getCollection())));
	}

	@Override
	public void sandboxRemove(List<RootCollection> rcs) {
		for (RootCollection rc : rcs) {
			db.delete(sandboxEncode(rc), sandboxIndex, RootCollection.class);
		}
	}

	@Override
	public Set<RootCollection> sandboxSet() {
		return db.set(sandboxIndex, RootCollection.class, DbBase.maxSize);
	}

	@Override
	public Map<String, Set<String>> sandboxMap() {
		Map<String, Set<String>> sandbox = new TreeMap<>();
		for (RootCollection rc : sandboxSet()) {
			sandbox.computeIfAbsent(rc.getApi_root(), k -> new TreeSet<>()).add(rc.getCollection());
		}
		return sandbox;
	}

	@Override
	public Collection addMedia_type(String cId, String media_type) {
		return updateCollection(readCollection(cId).add(media_type));
	}

	@Override
	public Collection removeMedia_type(String cId, String media_type) {
		return updateCollection(readCollection(cId).remove(media_type));
	}

	@Override
	public Fragment setLenients(String name, Set<Lenient> values) {
		return db.put(readFragment(name).setLenients(values), fragmentIndex, name, false);
	}

	@Override
	public Fragment addLenients(String name, Set<Lenient> values) {
		return db.put(readFragment(name).addLenients(values), fragmentIndex, name, false);
	}

	@Override
	public Fragment removeLenients(String name, Set<Lenient> values) {
		return db.put(readFragment(name).removeLenients(values), fragmentIndex, name, false);
	}

	@Override
	public Fragment setLenients(String fragment, String cId, Set<Lenient> values) {
		return db.put(readFragment(fragment).setLenients(cId, values), fragmentIndex, fragment, false);
	}

	@Override
	public Fragment addLenients(String fragment, String cId, Set<Lenient> values) {
		return db.put(readFragment(fragment).addLenients(cId, values), fragmentIndex, fragment, false);
	}

	@Override
	public Fragment removeLenients(String fragment, String cId, Set<Lenient> values) {
		return db.put(readFragment(fragment).removeLenients(cId, values), fragmentIndex, fragment, false);
	}

	@Override
	public Set<Lenient> getLenients(String name) {
		Set<Lenient> lenients = readFragment(name).getLenients();
		return (lenients != null) ? lenients : Collections.emptySet();
	}

	@Override
	public Set<Lenient> getLenients(String fragment, String cId) {
		Set<Lenient> lenients = readFragment(fragment).getLenients(cId);
		return (lenients != null) ? lenients : Collections.emptySet();
	}

	@Override
	public void refreshFragments() {
		db.refresh(fragmentIndex);
	}

	@Override
	public void refreshCollections() {
		db.refresh(collectionIndex);
	}

}
