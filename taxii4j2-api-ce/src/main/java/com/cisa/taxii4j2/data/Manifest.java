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
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.data.impl.CustomFields;
import com.cisa.taxii4j2.data.impl.FirstLast;

@JsonInclude(Include.NON_NULL)
public class Manifest extends FirstLast implements Iterable<Manifest.Record> {

	private static final String moreKey = "more";
	private static final String objectsKey = "objects";

	@JsonProperty(moreKey)
	private Boolean more;

	@JsonProperty(objectsKey)
	private List<Record> objects;

	@JsonCreator
	public Manifest(@JsonProperty(value = moreKey, required = false) Boolean more,
			@JsonProperty(value = objectsKey, required = false) List<Record> objects) {
		super(Manifest.class);
		setMore(more);
		setObjects(objects);
	}

	public Boolean getMore() {
		return more;
	}

	public boolean isMore() {
		return (more != null) ? more : false;
	}

	@JsonInclude(Include.NON_NULL)
	public static class Record extends CustomFields implements Comparable<Record> {

		public static final String idKey = "id";
		public static final String date_addedKey = "date_added";
		public static final String versionKey = "version";
		public static final String media_typeKey = "media_type";

		@JsonProperty(idKey)
		protected final String id;

		@JsonProperty(date_addedKey)
		private final Timestamp date_added;

		@JsonProperty(versionKey)
		protected final String version;

		@JsonProperty(media_typeKey)
		protected String media_type;

		@JsonCreator
		public Record(@JsonProperty(value = idKey, required = true) String id,
				@JsonProperty(value = date_addedKey, required = true) Timestamp date_added,
				@JsonProperty(value = versionKey, required = true) String version,
				@JsonProperty(value = media_typeKey, required = false) String media_type) {
			super(Record.class);
			this.id = id;
			this.date_added = date_added;
			this.version = version;
			this.media_type = media_type;
		}

		@Override
		public int compareTo(Record arg0) {
			int c = date_added.compareTo(arg0.date_added);
			if (c == 0) {
				c = id.compareTo(arg0.id);
				if (c == 0) {
					c = version.compareTo(arg0.version);
				}
			}
			return c;
		}

		@Override
		public boolean equals(Object obj) {
			return (obj != null) && (obj instanceof Record) && (obj.hashCode() == hashCode());
		}

		@Override
		public int hashCode() {
			return toString().hashCode();
		}

		public String getId() {
			return id;
		}

		public Timestamp getDate_added() {
			return date_added;
		}

		public String getVersion() {
			return version;
		}

		public String getMedia_type() {
			return media_type;
		}

	}

	public Manifest add(Record record) {
		if (objects == null) {
			objects = new ArrayList<>();
		}
		int index = java.util.Collections.binarySearch(objects, record);
		if (index < 0) {
			index = -index - 1;
		}
		objects.add(index, record);
		return this;
	}

	public List<Record> getObjects() {
		return (objects != null) ? java.util.Collections.unmodifiableList(objects) : null;
	}

	@Override
	public Iterator<Record> iterator() {
		return new Iterator<Record>() {

			private Iterator<Record> i = (objects != null) ? objects.iterator() : null;

			@Override
			public boolean hasNext() {
				return i != null;
			}

			@Override
			public Record next() {
				Record r = i.next();
				if (!i.hasNext()) {
					i = null;
				}
				return r;
			}
		};
	}

	public Manifest setMore(Boolean more) {
		this.more = ((more != null) && more) ? true : null;
		return this;
	}

	public Manifest setObjects(List<Record> objects) {
		if ((objects == null) || objects.isEmpty()) {
			clearFirstLast();
			this.objects = null;
			return this;
		}
		java.util.Collections.sort(objects);
		Timestamp first = objects.get(0).getDate_added();
		Timestamp last = objects.get(objects.size() - 1).getDate_added();
		setFirstLast(first, last);
		this.objects = objects;
		return this;
	}

}
