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

public enum CommonProperty {

	TYPE, SPEC_VERSION, ID, CREATED_BY_REF, CREATED, MODIFIED, REVOKED, LABELS, CONFIDENCE, LANG, EXTERNAL_REFERENCES,
	OBJECT_MARKING_REFS, GRANULAR_MARKINGS, DEFANGED, EXTENSIONS;

	public String getJsonKey() {
		return name().toLowerCase();
	}

	public static CommonProperty create(String jsonKey) {
		Optional<CommonProperty> value = Arrays.stream(values()).filter(cp -> jsonKey.equals(cp.getJsonKey()))
				.findAny();
		if (value.isPresent()) {
			return value.get();
		}
		throw new IllegalArgumentException();
	}

}
