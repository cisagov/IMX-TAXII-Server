/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data.impl;

public abstract class Storable implements Comparable<Storable> {

	public abstract String getId();

	public abstract String getVersion();

	public static String encodeId(Storable object) {
		return encodeId(object.getId(), object.getVersion());
	}

	public static String encodeId(String id, String version) {
		return String.format("%s %s", id, version);
	}

	public static String[] decodeId(String id) {
		return id.trim().split("\\s+");
	}

	@Override
	public int compareTo(Storable arg0) {
		int c = 0;
		c = getId().compareTo(arg0.getId());
		if (c == 0) {
			c = getVersion().compareTo(arg0.getVersion());
		}
		return c;
	}

	public abstract String getMedia_type();

	@Override
	public boolean equals(Object obj) {
//		return (obj instanceof Storable) && encodeId(this).equals(encodeId(Storable.class.cast(obj)));
		return hashCode() == obj.hashCode();
	}

	@Override
	public int hashCode() {
		return encodeId(this).hashCode();
	}

}
