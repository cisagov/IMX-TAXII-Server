/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.impl;

import java.util.LinkedHashMap;

public class LRUCache<K extends Comparable<K>, V> extends LinkedHashMap<K, V> {

	private static final long serialVersionUID = 1L;
	private static final int defaultSize = 128;
	private final int size;

	public LRUCache() {
		this(defaultSize);
	}

	public LRUCache(int size) {
		super(size, 0.75f, true);
		this.size = size;
	}

	@Override
	protected boolean removeEldestEntry(java.util.Map.Entry<K, V> eldest) {
		return size() > size;
	}


}
