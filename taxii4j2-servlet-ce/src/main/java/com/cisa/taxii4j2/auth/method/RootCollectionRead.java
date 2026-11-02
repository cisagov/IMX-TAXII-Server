/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.method;

import java.io.Closeable;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.cisa.taxii4j2.auth.data.Fragment;
import com.cisa.taxii4j2.data.Collections.Collection;

/**
 * The philosophy here is that members of object can be read but writing them
 * requires a method (in case it requires side effects)...
 */
public interface RootCollectionRead extends Closeable {

	public Fragment readFragment(String fragment);

	public List<Fragment> listFragments();

	public Collection readCollection(String cId);

	public List<Collection> listCollections();

	default public Map<String, Set<String>> sandboxMap() {
		return Collections.emptyMap();
	}

	@Override
	default void close() throws IOException {

	}

}
