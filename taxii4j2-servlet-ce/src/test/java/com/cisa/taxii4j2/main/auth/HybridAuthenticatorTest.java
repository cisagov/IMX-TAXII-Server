/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.main.auth;

import static org.junit.Assert.fail;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Arrays;
import java.util.Enumeration;

import org.junit.Test;

public class HybridAuthenticatorTest {

	@Test
	public void localhost() {
		final String dn = "localhost";
		try {
			InetAddress[] resolved = InetAddress.getAllByName(dn);
			System.out.println(Arrays.toString(resolved));
			InetAddress localHost = InetAddress.getLocalHost();
			System.out.println(localHost);
			Enumeration<NetworkInterface> iNi = NetworkInterface.getNetworkInterfaces();
			while(iNi.hasMoreElements()) {
				NetworkInterface ni = iNi.nextElement();
				System.out.println(ni.getInterfaceAddresses());
			}
		} catch(Exception e) {
			fail(e.getMessage());
		}
	}

}
