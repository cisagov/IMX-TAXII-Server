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

import com.cisa.taxii4j2.data.Status;
import com.cisa.taxii4j2.data.Status.Details;
import com.cisa.taxii4j2.data.Status.SFP;

public interface Statuses extends Closeable {

	public Status read(String id);

	public Status create(int i);

	public Status update(String statusId, SFP failure, Details details);

	@Override
	default void close() throws IOException {

	}

}
