/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.cti4j2;

import org.junit.Test;

public class HashAlgorithmOVTest {

	@Test
	public void test() {
		for(HashAlgorithmOV a : HashAlgorithmOV.values()) {
			System.out.println(a);
		}
	}

}
