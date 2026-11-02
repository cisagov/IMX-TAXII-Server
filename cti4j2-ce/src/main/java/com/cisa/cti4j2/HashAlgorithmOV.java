/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.cti4j2;

public enum HashAlgorithmOV {
	MD5, SHA_1, SHA_256, SHA_512, SHA3_256, SHA3_512, SSDEEP, TLSH;

	@Override
	public String toString() {
		return name().replaceAll("_", "-");
	}

}
