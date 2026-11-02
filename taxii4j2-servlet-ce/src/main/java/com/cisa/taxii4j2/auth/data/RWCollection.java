/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.data;

import java.util.Set;
import java.util.TreeSet;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(Include.NON_NULL)
public class RWCollection implements Comparable<RWCollection> {

	private static final String idKey = "cId";
	private static final String readersKey = "readers";
	private static final String writersKey = "writers";
	private static final String lenientsKey = "lenients";

	@JsonProperty(idKey)
	private final String id;

	@JsonProperty(readersKey)
	private Set<String> readers;

	@JsonProperty(writersKey)
	private Set<String> writers;

	@JsonProperty(lenientsKey)
	private Set<Lenient> lenients;

	public RWCollection(String id) {
		this(id, null, null, null);
	}

	public RWCollection(RWCollection src, Set<String> readers, Set<String> writers) {
		this(src.id, readers, writers, null);
	}

	@JsonCreator
	public RWCollection(@JsonProperty(value = idKey, required = false) String id,
			@JsonProperty(value = readersKey, required = false) Set<String> readers,
			@JsonProperty(value = writersKey, required = false) Set<String> writers,
			@JsonProperty(value = lenientsKey, required = false) Set<Lenient> lenients) {
		super();
		this.id = id;
		this.readers = (readers != null) ? new TreeSet<>(readers) : null;
		this.writers = (writers != null) ? new TreeSet<>(writers) : null;
		this.lenients = lenients;
	}

	public Set<Lenient> getLenients() {
		return lenients;
	}

	public String getId() {
		return id;
	}

	public boolean isCan_read(String reader) {
		return (readers != null) && (readers.contains(reader));
	}

	public boolean isCan_write(String writer) {
		return (writers != null) && (writers.contains(writer));
	}

	@Override
	public int compareTo(RWCollection arg0) {
		return id.compareTo(arg0.id);
	}

	@Override
	public String toString() {
		return "RWCollection [id=" + id + ", can_read=" + readers + ", can_write=" + writers + "]";
	}

	public RWCollection addCan_read(String reader) {
		readers = add(readers, reader);
		return this;
	}

	private Set<String> add(Set<String> rws, String rw) {
		if (rws == null) {
			rws = new TreeSet<>();
		}
		rws.add(rw);
		return rws;
	}

	public RWCollection addCan_write(String writer) {
		writers = add(writers, writer);
		return this;
	}

	public RWCollection removeCan_read(String reader) {
		readers = remove(readers, reader);
		return this;
	}

	private Set<String> remove(Set<String> rws, String rw) {
		if (rws == null) {
			return rws;
		}
		rws.remove(rw);
		return rws.isEmpty() ? null : rws;
	}

	public RWCollection removeCan_write(String writer) {
		writers = remove(writers, writer);
		return this;
	}

	public Set<String> getReaders() {
		return readers;
	}

	public Set<String> getWriters() {
		return writers;
	}

	public RWCollection clear() {
		readers = null;
		writers = null;
		return this;
	}

	@JsonIgnore
	public RWCollection setLenients(Set<Lenient> values) {
		lenients = !values.isEmpty() ? values : null;
		return this;
	}

	@JsonIgnore
	public RWCollection addLenients(Set<Lenient> add) {
		if (add.isEmpty()) {
			return this;
		}
		if (lenients != null) {
			lenients.addAll(add);
		} else {
			lenients = add;
		}
		return this;
	}

	@JsonIgnore
	public RWCollection removeLenients(Set<Lenient> values) {
		if (values.isEmpty()) {
			return this;
		}
		if (lenients != null) {
			lenients.removeAll(values);
			if (lenients.isEmpty()) {
				lenients = null;
			}
		}
		return this;
	}

}
