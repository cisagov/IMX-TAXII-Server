/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.data;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.taxii4j2.data.Collections.Collection;
import com.cisa.taxii4j2.data.impl.DataUtils;

@JsonInclude(Include.NON_NULL)
public class MappedCollections {

	@JsonInclude(Include.NON_NULL)
	public static class MappedCollection extends Collection {

		private static final String readersKey = "readers";
		private static final String writersKey = "writers";

		@JsonProperty(readersKey)
		private final List<String> readers;

		@JsonProperty(writersKey)
		private final List<String> writers;

		@JsonCreator
		public MappedCollection(@JsonProperty(value = idKey, required = true) String id,
				@JsonProperty(value = titleKey, required = true) String title,
				@JsonProperty(value = can_readKey, required = true) boolean can_read,
				@JsonProperty(value = can_writeKey, required = true) boolean can_write,
				@JsonProperty(value = descriptionKey, required = false) String description,
				@JsonProperty(value = aliasKey, required = false) String alias,
				@JsonProperty(value = media_typesKey, required = false) List<String> media_types,
				@JsonProperty(value = readersKey, required = false) List<String> readers,
				@JsonProperty(value = writersKey, required = false) List<String> writers) {
			super(id, title, can_read, can_write, description, alias, media_types);
			this.readers = DataUtils.finalTidy(readers);
			this.writers = DataUtils.finalTidy(writers);
		}

		public MappedCollection(Collection src, RWCollection rw) {
			super(src);
			this.readers = DataUtils.finalTidy(rw.getReaders());
			this.writers = DataUtils.finalTidy(rw.getWriters());
		}

		public List<String> getReaders() {
			return readers;
		}

		public List<String> getWriters() {
			return writers;
		}

	}

	private static final String collectionsKey = "collections";

	@JsonProperty(collectionsKey)
	private final List<MappedCollection> collections;

	@JsonCreator
	public MappedCollections(
			@JsonProperty(value = collectionsKey, required = false) List<MappedCollection> collections) {
		super();
		this.collections = DataUtils.finalTidy(collections, (t0, t1) -> t0.compareTo(t1));
	}

	public List<MappedCollection> getCollections() {
		return (collections != null) ? java.util.Collections.unmodifiableList(collections) : null;
	}

}
