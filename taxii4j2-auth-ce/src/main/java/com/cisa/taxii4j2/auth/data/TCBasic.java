/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.data;

import java.util.Base64;

public class TCBasic extends TAXIICredentials {

	private static final String method = "basic";

	private final String headerValue;

	public TCBasic(String username, String password) {
		super();
		headerValue = String.format("%s %s", method,
				Base64.getEncoder().encodeToString(String.format("%s:%s", username, password).getBytes()));
	}

	public static User getUser(String headerValue) {
		String[] parts = headerValue.split("\\s+");
		if ((parts.length != 2) || !parts[0].equalsIgnoreCase(method)) {
			throw new IllegalArgumentException();
		}
		parts = new String(Base64.getDecoder().decode(parts[1])).split(":");
		if (parts.length != 2) {
			throw new IllegalArgumentException();
		}
		User known = userAdmin().readUserByName(parts[0]);
		return new User(parts[0], parts[1], (known != null) ? known.getRoles() : null);
	}

	@Override
	public String getHeaderValue() {
		return headerValue;
	}

}
