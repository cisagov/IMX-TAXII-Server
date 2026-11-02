/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.data;

public class TCNone extends TAXIICredentials {

	@Override
	public String getHeaderValue() {
		return null;
	}

	public static User getUser(String credentials) {
		throw new IllegalArgumentException();
	}

}
