/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.cti4j2;

import java.util.EnumSet;
import java.util.List;

import org.junit.Test;

public class TypeTest {

	@Test
	public void test() {
		for(Type type : EnumSet.complementOf(EnumSet.of(Type.BUNDLE))) {
			List<String> properties = type.getProperties();
			System.out.println(String.format("%s\t%s", type, properties));
			for(String property : properties) {
				System.out.println(String.format("\t%s\t%s", property, Type.getTypes(property)));
			}
		}
	}

}
