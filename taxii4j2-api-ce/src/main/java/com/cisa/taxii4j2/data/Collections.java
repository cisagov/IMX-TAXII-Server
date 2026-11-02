/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.taxii4j2.data.impl.CustomFields;

@JsonInclude(Include.NON_NULL)
public class Collections extends CustomFields implements Iterable<Collections.Collection> {

	private static final String collectionsKey = "collections";

	public Collections() {
		super(Collections.class);
	}

	@JsonProperty(collectionsKey)
	public List<Collection> collections;

	@JsonInclude(Include.NON_NULL)
	public static class Collection extends CustomFields implements Comparable<Collection> {

		public static final String idKey = "id";
		protected static final String titleKey = "title";
		protected static final String descriptionKey = "description";
		public static final String aliasKey = "alias";
		protected static final String media_typesKey = "media_types";
		protected static final String can_readKey = "can_read";
		protected static final String can_writeKey = "can_write";

		@JsonProperty(idKey)
		protected final String id;

		@JsonProperty(titleKey)
		protected String title;

		@JsonProperty(descriptionKey)
		protected String description;

		@JsonProperty(aliasKey)
		protected String alias;

		@JsonProperty(media_typesKey)
		protected List<String> media_types;

		@JsonProperty(can_readKey)
		private boolean can_read;

		@JsonProperty(can_writeKey)
		private boolean can_write;

		public Collection(String id, String title, boolean can_read, boolean can_write) {
			this(id, title, can_read, can_write, null, null, null);
		}

		public Collection(Collection src, boolean can_read, boolean can_write) {
			this(src.id, src.title, can_read, can_write, src.description, src.alias, src.media_types);
		}

		public Collection(Collection src) {
			this(src, src.can_read, src.can_write);
		}

		@JsonCreator
		public Collection(@JsonProperty(value = idKey, required = true) String id,
				@JsonProperty(value = titleKey, required = true) String title,
				@JsonProperty(value = can_readKey, required = true) boolean can_read,
				@JsonProperty(value = can_writeKey, required = true) boolean can_write,
				@JsonProperty(value = descriptionKey, required = false) String description,
				@JsonProperty(value = aliasKey, required = false) String alias,
				@JsonProperty(value = media_typesKey, required = false) List<String> media_types) {
			super(Collection.class);
			this.id = id;
			this.title = title;
			this.can_read = can_read;
			this.can_write = can_write;
			this.description = description;
			this.alias = alias;
			if ((media_types != null) && !media_types.isEmpty()) {
				this.media_types = new ArrayList<>(media_types);
				java.util.Collections.sort(this.media_types);
			}
		}

		public boolean isCan_read() {
			return can_read;
		}

		public boolean isCan_write() {
			return can_write;
		}

		@Override
		public int compareTo(Collection arg0) {
			return id.compareTo(arg0.id);
		}

		public String getId() {
			return id;
		}

		public String getTitle() {
			return title;
		}

		public String getDescription() {
			return description;
		}

		public String getAlias() {
			return alias;
		}

		public List<String> getMedia_types() {
			return (media_types != null) ? java.util.Collections.unmodifiableList(media_types) : null;
		}

		public synchronized Collection setDescription(String description) {
			this.description = description;
			return this;
		}

		public synchronized Collection setAlias(String alias) {
			this.alias = alias;
			return this;
		}

		synchronized public Collection add(String media_type) {
			if (media_types == null) {
				media_types = new ArrayList<>();
			}
			int index = java.util.Collections.binarySearch(media_types, media_type);
			if (index < 0) {
				media_types.add(-index - 1, media_type);
			}
			return this;
		}

		synchronized public Collection remove(String media_type) {
			int index = (media_types != null) ? java.util.Collections.binarySearch(media_types, media_type) : -1;
			if (index >= 0) {
				media_types.remove(index);
				if (media_types.isEmpty()) {
					media_types = null;
				}
			}
			return this;
		}

		public synchronized Collection setCan_read(boolean can_read) {
			this.can_read = can_read;
			return this;
		}

		public synchronized Collection setCan_write(boolean can_write) {
			this.can_write = can_write;
			return this;
		}

		public synchronized Collection setTitle(String title) {
			this.title = title;
			return this;
		}

//		public Collection constrain(RWCollection rw) {
//			List<String> readers = rw.getReaders();
//			List<String> writers = rw.getWriters();
//			return new Collection(this, can_read && (readers != null) && !readers.isEmpty(),
//					can_write && (writers != null) && !writers.isEmpty());
//		}

	}

	public Collections add(Collection c) {
		if (collections == null) {
			collections = new ArrayList<>();
		}
		int index = java.util.Collections.binarySearch(collections, c);
		if (index < 0) {
			collections.add(-index - 1, c);
		}
		return this;
	}

	@Override
	public Iterator<Collection> iterator() {
		return new Iterator<Collection>() {

			private Iterator<Collection> i = (collections != null) ? collections.iterator() : null;

			@Override
			public boolean hasNext() {
				return i != null;
			}

			@Override
			public Collection next() {
				Collection c = i.next();
				if (!i.hasNext()) {
					i = null;
				}
				return c;
			}
		};
	}

}
