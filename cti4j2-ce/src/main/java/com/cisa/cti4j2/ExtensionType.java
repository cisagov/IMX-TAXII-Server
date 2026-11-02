/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.cti4j2;

public enum ExtensionType {

	NEW_SDO("new-sdo"), NEW_SCO("new-sco"), NEW_SRO("new-sro"),
	PROPERTY_EXTENSION("property-extension"), TOPLEVEL_PROPERTY_EXTENSION("toplevel-property-extension");

	private String vocab;

	private ExtensionType(String vocab) {
		this.vocab = vocab;
	}

	@Override
	public String toString() {
		return vocab;
	}

	public static ExtensionType create(String vocab) {
		for(ExtensionType type : values()) {
			if(vocab.equals(type.vocab)) {
				return type;
			}
		}
		throw new IllegalArgumentException();
	}

}
