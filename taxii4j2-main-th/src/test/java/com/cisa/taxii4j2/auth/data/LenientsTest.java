/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.data;

import static org.junit.Assert.fail;

import java.util.Iterator;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Test;

import com.cisa.cti4j2.JSON;

public class LenientsTest {

	@Test
	public void test() {
		Set<String> lenientTypes = Set.of("DONT_CHECK_CUSTOM_OBJECTS", "DONT_FAIL_CUSTOM_OBJECTS",
				"DONT_CHECK_CUSTOM_PROPERTIES", "DONT_FAIL_CUSTOM_PROPERTIES", "DONT_REMOVE_EMPTY_ARRAYS",
				"FAIL_EMPTY_ARRAYS", "DONT_TRIM_URLS", "FAIL_TRIMMED_URLS", "DONT_CHECK_NA_COMMONS",
				"DONT_FAIL_NA_COMMONS");
		Set<Lenient> lenients = lenientTypes.stream().map(t -> Lenient.factory(t)).collect(Collectors.toSet());

		try {
			System.out.println(lenients);
			String json = JSON.writeValueAsString(lenients.iterator().next());
			System.out.println(json);
			Lenient lenient = JSON.readValue(json, Lenient.class);
			System.out.println(lenient);
		} catch (Exception e) {
			fail(e.getMessage());
		}

		Iterator<Lenient> iLenient = lenients.iterator();
		while (iLenient.hasNext()) {
			Lenient lenient = iLenient.next();
			System.out.print(String.format("%s\t%s\t", lenient, lenient.test(lenients)));
			iLenient.remove();
			System.out.println(lenient.test(lenients));
		}
		System.out.println();
//		for(Lenient lenient : Lenients.values()) {
//			System.out.println(String.format("%s\t%s", lenient, lenient.test(lenients)));
//		}
	}

}
