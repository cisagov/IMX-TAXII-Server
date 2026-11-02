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

public enum TLP2 {

	RED("marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1", TLP1.RED),
	GREEN("marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb", TLP1.GREEN),
	CLEAR("marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487", TLP1.WHITE),
	AMBER_STRICT("marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003", TLP1.RED),
	AMBER("marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421", TLP1.AMBER);

	private final String id;
	private final TLP1 tlp1;

	private TLP2(String id, TLP1 tlp1) {
		this.id = id;
		this.tlp1 = tlp1;
	}

	public String getId() {
		return id;
	}

	public TLP1 getTlp1() {
		return tlp1;
	}

	public static TLP2 get(String id) {
		Optional<TLP2> value = Arrays.stream(values()).filter(tlp -> id.equals(tlp.id)).findAny();
		return value.orElse(null);
	}

}
