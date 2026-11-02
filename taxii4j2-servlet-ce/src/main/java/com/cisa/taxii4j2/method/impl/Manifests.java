/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.impl;

import java.io.Closeable;
import java.io.IOException;

import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.data.Manifest;
import com.cisa.taxii4j2.data.Versions;

public interface Manifests extends Closeable {

	public Manifest read(String cId, Filters filters, long max_content_length);

	public Versions versions(String cId, String oId, Filters filters, long max_content_length);

	@Override
	default void close() throws IOException {

	}

}
