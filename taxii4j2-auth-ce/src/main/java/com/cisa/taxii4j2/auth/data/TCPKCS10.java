/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.data;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class TCPKCS10 extends TAXIICredentials {

	private final String headerValue;

	public TCPKCS10(String pkcs10) {
		super();
		headerValue = pkcs10;
	}

	public static User getUser(String headerValue) {
		String[] parts = headerValue.split("\\s+");
		if(parts.length != 1) {
			throw new IllegalArgumentException();
		}
		try {
			PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.getDecoder().decode(parts[0]));
			String[] kvs = Arrays.stream(csr.getSubject().getRDNs()).map(rdn -> rdn.getFirst())
					.map(kv -> String.format("%s=%s", kv.getType(), kv.getValue())).toArray(String[]::new);
			String userName = Arrays.toString(kvs);
			User known = userAdmin().readUserByName(userName);
			String rawPassword = Base64.getEncoder().encodeToString(csr.getSignature());
			return new User(userName, rawPassword, (known != null) ? known.getRoles() : null);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

	@Override
	public String getHeaderValue() {
		return headerValue;
	}

}
