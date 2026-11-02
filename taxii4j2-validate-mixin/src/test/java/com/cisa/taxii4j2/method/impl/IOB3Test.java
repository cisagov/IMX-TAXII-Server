/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.impl;

import static org.junit.Assert.fail;

import java.net.URI;

import org.junit.Test;

public class IOB3Test {

	private static final String original = "https://raw.githubusercontent.com/opencybersecurityalliance/oca-iob/main/apl_reference_implementation_bundle/revision_2/schemas/observables/extended-network-traffic.json";
	private static final String relative = "https://raw.githubusercontent.com/opencybersecurityalliance/oca-iob/main/apl_reference_implementation_bundle/revision_2/schemas/";
	private static final String relocated = "https://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/master/schemas/";

	@Test
	public void test() {
		try {
			URI from = URI.create(original);
			System.out.println(from);
			URI suffix = URI.create(relative).relativize(from);
			System.out.println(suffix);
			URI to = URI.create(relocated).resolve(suffix);
			System.out.println(to);
		} catch(Exception e) {
			fail(e.getMessage());
		}
	}
}
