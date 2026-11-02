/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.data;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class TCPKCS12 extends TAXIICredentials {

	public static final String method = "CLIENT_CERT";

	@Override
	public String getHeaderValue() {
		return null;
	}

	public static User getUser(String credentials) {
		String[] parts = credentials.split("\\s+");
		if((parts.length != 2) || !method.equalsIgnoreCase(parts[0])) {
			throw new IllegalArgumentException();
		}
		try (InputStream in = new ByteArrayInputStream(Base64.getDecoder().decode(parts[1]))) {
			Certificate _cert = CertificateFactory.getInstance("X.509").generateCertificate(in);
			return getUser(_cert);
		} catch (IOException | CertificateException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public static User getUser(Certificate _cert) {
		X509Certificate cert = X509Certificate.class.cast(_cert);
		Principal principal = cert.getSubjectDN();
		if (principal == null) {
			principal = cert.getIssuerDN();
		}
		String username = principal.getName();
		//logger.debug(String.format("PKCS12 username: %s", username));
		User known = userAdmin().readUserByName(username);
		return new User(username, null, (known != null) ? known.getRoles() : null);
	}
}
