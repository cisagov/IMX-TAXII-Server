/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.store;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import jakarta.inject.Singleton;

@Singleton
public interface DbBase extends AutoCloseable {

	public static final Logger logger = LogManager.getLogger(DbBase.class);

	public static final Integer maxSize = 1 << 12; // 4096

	public String deleteIndex(String index);

	public String legalizeIndexName(String in);

	public String localizeIndexName(String index);

	public String createIndex(String name);

	public Set<String> allIndices();

	public <T> T get(String id, String index, Class<T> clazz);

	public <T> T put(T info, String index, String id, boolean create);

	public <T> T delete(String id, String index, Class<T> clazz);

	public <T> Map<String, T> map(String index, Class<T> clazz, Integer size);

	public <T, C extends java.util.Collection<T>> C collect(String index, Class<T> clazz, Supplier<C> ts, Integer size);

	default public <T> T client(Class<T> clazz) {
		return null;
	}

	default public <T> Map<String, T> map(String index, Class<T> clazz) {
		return map(index, clazz, null);
	}

	default public <T> List<T> list(String index, Class<T> clazz, Integer size) {
		return collect(index, clazz, ArrayList::new, size);
	}

	default public <T extends Comparable<T>> Set<T> set(String index, Class<T> clazz, Integer size) {
		return collect(index, clazz, TreeSet::new, size);
	}

	default public <T> List<T> list(String index, Class<T> clazz) {
		return list(index, clazz, null);
	}

	default public <T extends Comparable<T>> Set<T> set(String index, Class<T> clazz) {
		return set(index, clazz, null);
	}

	default public <T> T put(T info, String index, String id) {
		return put(info, index, id, true);
	}

	default public String keyword(String property) {
		return property;
	}

	default public <T> List<T> search(Map<String, String> kvs, Class<T> clazz, String index) {
		return search(kvs, clazz, 0, maxSize, Collections.singletonList(index));
	}

	public <T> List<T> search(Map<String, String> kvs, Class<T> clazz, int from, int size, Collection<String> indices);

	public <T> List<T> searchWithRange(Map<String, String> kvs, Map<String, Pair<Integer, Integer>> ranges, Class<T> clazz,
			int _size, Collection<String> indices);

	public void refresh(String... index);

	/*
	 * snapshots
	 */

	default public String listSnapshots() {
		throw new UnsupportedOperationException();
	}

	default public String createSnapshot(String name) {
		throw new UnsupportedOperationException();
	}

	default public String getSnapshotStatus(String name) {
		throw new UnsupportedOperationException();
	}

	default public String deleteSnapshot(String name) {
		throw new UnsupportedOperationException();
	}

	default public String restoreSnapshot(String name) {
		throw new UnsupportedOperationException();
	}

}
