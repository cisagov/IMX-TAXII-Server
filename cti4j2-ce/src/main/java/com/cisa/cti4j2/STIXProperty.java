/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.cti4j2;

import java.util.Arrays;
import java.util.Optional;

public enum STIXProperty {

	OBJECT_REFS;

	public String getJsonKey() {
		return name().toLowerCase();
	}

	public static STIXProperty create(String jsonKey) {
		Optional<STIXProperty> value = Arrays.stream(values()).filter(cp -> jsonKey.equals(cp.getJsonKey()))
				.findAny();
		if (value.isPresent()) {
			return value.get();
		}
		throw new IllegalArgumentException();
	}

}
