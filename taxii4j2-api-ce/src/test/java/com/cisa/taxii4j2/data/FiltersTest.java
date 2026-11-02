/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data;

import org.junit.Test;

public class FiltersTest {

	@Test
	public void test() {
		Filters filters = Filters.create("match[type]=attack-pattern,file" + "&added_after=2023-10-26T00:00:00Z"
				+ "&match[id]=attack-pattern--69fc9038-b74f-4c0d-b73c-ac637ee8a242" + "&broken");
		System.out.println(filters.getType());
		System.out.println(filters.getAdded_after());
		System.out.println(filters.getId());
		System.out.println(filters.isFirst());
		System.out.println(filters.getSpec_version());
	}

}
