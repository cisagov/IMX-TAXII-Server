/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.api;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Spliterator;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.databind.JsonNode;

public class Tree extends GitHub.Wrapper {

	public Tree(JsonNode object) {
		super(object);
		if (object.get("truncated").asBoolean()) {
			throw new IllegalStateException("tree was truncated...");
		}
	}

	private class IHelper implements Iterator<Entry> {

		private final Predicate<Entry> p;
		private final Iterator<Entry> i;
		private Entry node;

		private IHelper(Predicate<Entry> p) {
			super();
			this.p = p;
			i = getEntries().iterator();
			_next();
		}

		private void _next() {
			while (i.hasNext()) {
				node = i.next();
				if (p.test(node)) {
					return;
				}
			}
			node = null;
		}

		@Override
		public boolean hasNext() {
			return node != null;
		}

		@Override
		public Entry next() {
			Entry result = node;
			_next();
			return result;
		}

	}

	public Iterator<Entry> trees() {
		return new IHelper(e -> e.isTree());
	}

	public Iterator<Entry> blobs() {
		return new IHelper(e -> e.isBlob());
	}

	private static interface EntryBase extends Comparable<EntryBase> {

		public String getPath();

		@Override
		default public int compareTo(EntryBase other) {
			return getPath().compareTo(other.getPath());
		}

	}

	public static class EntryKey implements EntryBase {

		private final String path;

		public EntryKey(String path) {
			super();
			this.path = path;
		}

		@Override
		public String getPath() {
			return path;
		}
	}

	public static class Entry extends GitHub.Wrapper implements EntryBase {

		public Entry(JsonNode object) {
			super(object);
		}

		@Override
		public String getPath() {
			return getObject().get("path").asText();
		}

		public String getType() {
			return getObject().get("type").asText();
		}

		public boolean isBlob() {
			return getType().equalsIgnoreCase("blob");
		}

		public boolean isTree() {
			return getType().equalsIgnoreCase("tree");
		}

		public Blob getBlob(GitHub gh) {
			return isBlob() ? gh.get(url(), Blob.class) : null;
		}

		public Tree getTree(GitHub gh) {
			return isTree() ? gh.get(url(), Tree.class) : null;
		}

	}

	private List<Entry> entries;

	public List<Entry> getEntries() {
		if (entries == null) {
			Spliterator<JsonNode> spliterator = getObject().get("tree").spliterator();
			entries = StreamSupport.stream(spliterator, false).map(node -> new Entry(node))
					.collect(Collectors.toList());
			Collections.sort(entries);
		}
		return entries;
	}

	public Entry getEntry(String path) {
		int index = Collections.binarySearch(getEntries(), new EntryKey(path));
		return (index >= 0) ? entries.get(index) : null;
	}

}
