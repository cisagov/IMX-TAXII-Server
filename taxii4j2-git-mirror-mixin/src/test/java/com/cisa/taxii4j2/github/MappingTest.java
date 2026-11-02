/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.github;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.Test;

public class MappingTest {

	@Test
	public void test() {
		Path t0 = Paths.get("objects/location/location--548a4f7c-610c-48eb-a18c-af8c3fa30b87.json");
		Path t1 = Paths.get("objects/location--548a4f7c-610c-48eb-a18c-af8c3fa30b87.json");
		test(Paths.get("objects/location"), t0, t1);
		test(Paths.get("objects/location/"), t0, t1);
	}

	private void test(Path start, Path t0, Path t1) {
		System.out.println(start);
		System.out.println(String.format("%s starts with %s = %s", t0, start, t0.startsWith(start)));
		System.out.println(String.format("%s starts with %s = %s", t1, start, t1.startsWith(start)));
	}

}
