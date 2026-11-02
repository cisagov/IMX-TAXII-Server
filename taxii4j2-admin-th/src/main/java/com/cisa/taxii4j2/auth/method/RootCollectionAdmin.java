/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.method;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import org.jvnet.hk2.annotations.Contract;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.taxii4j2.auth.data.Fragment;
import com.cisa.taxii4j2.auth.data.Lenient;
import com.cisa.taxii4j2.auth.data.RWCollection;
import com.cisa.taxii4j2.data.ApiRoot;
import com.cisa.taxii4j2.data.Collections.Collection;

/**
 * The philosophy here is that members of object can be read but writing them
 * requires a method (in case it requires side effects)...
 */
@Contract
public interface RootCollectionAdmin extends RootCollectionRead {

	public Fragment upsertFragment(Fragment fragment, boolean create);

	public Fragment deleteFragment(String fragment);

	public Fragment addCan_write(String name, String cId, String writer);

	public Fragment addCan_read(String name, String cId, String reader);

	public Fragment removeCan_write(String name, String cId, String writer);

	public Fragment removeCan_read(String name, String cId, String reader);

	public Fragment removeRW(String name, String cId);

	public Fragment addRW(String name, RWCollection rw);

	public Fragment setApiRoot(String name, ApiRoot apiRoot);

	public Fragment setLenients(String name, Set<Lenient> values);

	public Set<Lenient> getLenients(String name);

	public Fragment addLenients(String name, Set<Lenient> values);

	public Fragment removeLenients(String name, Set<Lenient> values);

	public Set<Lenient> getLenients(String fragment, String cId);

	public Fragment setLenients(String fragment, String cId, Set<Lenient> values);

	public Fragment addLenients(String fragment, String cId, Set<Lenient> values);

	public Fragment removeLenients(String fragment, String cId, Set<Lenient> values);

	public void refreshFragments();

	public Collection upsertCollection(Collection collection, boolean create);

	public Collection deleteCollection(String cId);

	public Collection setDescription(String cId, String description);

	public Collection setAlias(String cId, String alias);

	public Collection add(String cId, String media_type);

	public Collection remove(String cId, String media_type);

	public Collection setCan_read(String cId, boolean can_read);

	public Collection setCan_write(String cId, boolean can_write);

	public Collection setTitle(String cId, String title);

	public void refreshCollections();

	@Override
	default void close() throws IOException {

	}

	@JsonInclude(Include.NON_NULL)
	public static class RootPermissions {

		private static final String api_rootKey = "api-root";
		private static final String collectionsKey = "collections";

		@JsonProperty(api_rootKey)
		public final String api_root;

		@JsonProperty(collectionsKey)
		public final Set<Collection> collections;

		public RootPermissions(@JsonProperty(value = api_rootKey, required = true) String api_root,
				@JsonProperty(value = collectionsKey, required = false) Set<Collection> collections) {
			super();
			this.api_root = api_root;
			this.collections = collections;
		}

		public String getApi_root() {
			return api_root;
		}

		public Set<Collection> getCollections() {
			return collections;
		}

	}

	public List<RootPermissions> permissions(Set<String> roles);

	@JsonInclude(Include.NON_NULL)
	public static class RootCollection implements Comparable<RootCollection> {

		private static final String api_rootKey = "api-root";
		private static final String collectionKey = "collection";

		@JsonProperty(api_rootKey)
		private final String api_root;

		@JsonProperty(collectionKey)
		private String collection;

		public RootCollection(@JsonProperty(value = api_rootKey, required = true) String api_root,
				@JsonProperty(value = collectionKey, required = true) String collection) {
			super();
			this.api_root = api_root;
			this.collection = collection;
		}

		public String getApi_root() {
			return api_root;
		}

		public String getCollection() {
			return collection;
		}

		public String setCollection(String collection) {
			this.collection = collection;
			return collection;
		}

		@Override
		public int compareTo(RootCollection o) {
			int c = api_root.compareTo(o.api_root);
			return (c != 0) ? c : collection.compareTo(o.collection);
		}

	}

	public void sandboxAdd(List<RootCollection> rcs);

	public void sandboxRemove(List<RootCollection> rcs);

	public Set<RootCollection> sandboxSet();

	public Collection addMedia_type(String cId, String media_type);

	public Collection removeMedia_type(String cId, String media_type);

	default public Set<String> listLenients() {
		return Lenient.list();
	}

}
