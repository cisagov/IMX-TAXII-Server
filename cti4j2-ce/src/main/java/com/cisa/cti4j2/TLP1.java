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

public enum TLP1 {

	WHITE("marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9", TLP2.CLEAR),
	RED("marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed", TLP2.RED),
	GREEN("marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da", TLP2.GREEN),
	AMBER("marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", TLP2.AMBER);

	private final String id;
	private final TLP2 tlp2;

	private TLP1(String id, TLP2 tlp2) {
		this.id = id;
		this.tlp2 = tlp2;
	}

	public String getId() {
		return id;
	}

	public TLP2 getTlp2() {
		return tlp2;
	}

	public static TLP1 get(String id) {
		Optional<TLP1> value = Arrays.stream(values()).filter(tlp -> id.equals(tlp.id)).findAny();
		return value.orElse(null);
	}

}
