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
import java.util.Arrays;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.data.impl.Storable;

public interface Objects extends Closeable {

	public static final Logger logger = LogManager.getLogger(Objects.class);

	public Envelope read(String cId, Filters filters, long max_content_length);

	/**
	 * Abstract virtual method for reading list of {@link Storable}, that is, all
	 * versions of a given object, given containing collection and object
	 * identifier.
	 *
	 * @param cId the collection id
	 * @param oId the object id
	 * @return always non-null, may be empty
	 */
	public List<STIXObject> read(String cId, String oId);

	public boolean create(STIXObject storable, String cId, boolean replace);

	public void delete(String cId, String oId, Filters filters);

	public Envelope envelope(String cId, Filters filters, long max_content_length);

	@Override
	default void close() throws IOException {

	}

	public void refresh(String... refresh);

	default public void delete(String cId, STIXObject... objects) {
		delete(cId, Arrays.asList(objects));
	}

	public void delete(String cId, List<STIXObject> objects);

	public List<STIXObject> read(String oId);

	public void put(STIXObject object);

}
