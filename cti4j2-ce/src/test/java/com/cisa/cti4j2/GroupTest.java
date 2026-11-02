/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.cti4j2;

import static org.junit.Assert.fail;

import java.util.EnumSet;

import org.junit.Test;

public class GroupTest {

	@Test
	public void test() {
		for (Group group : Group.values()) {

			EnumSet<CommonProperty> extra = EnumSet.noneOf(CommonProperty.class);
			group.required.forEach(p -> {
				if (!extra.add(p)) {
					fail(String.format("%s has %s more than once...", group, p));
				}
			});
			group.optional.forEach(p -> {
				if (!extra.add(p)) {
					fail(String.format("%s has %s more than once...", group, p));
				}
			});
			group.na.forEach(p -> {
				if (!extra.add(p)) {
					fail(String.format("%s has %s more than once...", group, p));
				}
			});

			EnumSet<CommonProperty> missed = EnumSet.allOf(CommonProperty.class);
			missed.removeAll(group.required);
			missed.removeAll(group.optional);
			missed.removeAll(group.na);
			if (!missed.isEmpty()) {
				fail(String.format("%s is missing %s...", group, missed));
			}

		}
	}

}
