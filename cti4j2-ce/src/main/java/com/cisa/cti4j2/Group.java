/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.cti4j2;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;

public enum Group {

	SDO(EnumSet.of(CommonProperty.TYPE, CommonProperty.SPEC_VERSION, CommonProperty.ID, CommonProperty.CREATED,
			CommonProperty.MODIFIED),
			EnumSet.of(CommonProperty.CREATED_BY_REF, CommonProperty.REVOKED, CommonProperty.LABELS,
					CommonProperty.CONFIDENCE, CommonProperty.LANG, CommonProperty.EXTERNAL_REFERENCES,
					CommonProperty.OBJECT_MARKING_REFS, CommonProperty.GRANULAR_MARKINGS, CommonProperty.EXTENSIONS),
			EnumSet.of(CommonProperty.DEFANGED)),
	SRO(EnumSet.of(CommonProperty.TYPE, CommonProperty.SPEC_VERSION, CommonProperty.ID, CommonProperty.CREATED,
			CommonProperty.MODIFIED),
			EnumSet.of(CommonProperty.CREATED_BY_REF, CommonProperty.REVOKED, CommonProperty.LABELS,
					CommonProperty.CONFIDENCE, CommonProperty.LANG, CommonProperty.EXTERNAL_REFERENCES,
					CommonProperty.OBJECT_MARKING_REFS, CommonProperty.GRANULAR_MARKINGS, CommonProperty.EXTENSIONS),
			EnumSet.of(CommonProperty.DEFANGED)),
	SCO(EnumSet.of(CommonProperty.TYPE, CommonProperty.ID),
			EnumSet.of(CommonProperty.SPEC_VERSION, CommonProperty.OBJECT_MARKING_REFS,
					CommonProperty.GRANULAR_MARKINGS, CommonProperty.DEFANGED, CommonProperty.EXTENSIONS),
			EnumSet.of(CommonProperty.CREATED_BY_REF, CommonProperty.CREATED, CommonProperty.MODIFIED,
					CommonProperty.REVOKED, CommonProperty.LABELS, CommonProperty.CONFIDENCE, CommonProperty.LANG,
					CommonProperty.EXTERNAL_REFERENCES)),
	EXTENSION(
			EnumSet.of(CommonProperty.TYPE, CommonProperty.SPEC_VERSION, CommonProperty.ID,
					CommonProperty.CREATED_BY_REF, CommonProperty.CREATED, CommonProperty.MODIFIED),
			EnumSet.of(CommonProperty.REVOKED, CommonProperty.LABELS, CommonProperty.EXTERNAL_REFERENCES,
					CommonProperty.OBJECT_MARKING_REFS, CommonProperty.GRANULAR_MARKINGS),
			EnumSet.of(CommonProperty.CONFIDENCE, CommonProperty.LANG, CommonProperty.DEFANGED,
					CommonProperty.EXTENSIONS)),
	LANGUAGE(
			EnumSet.of(CommonProperty.TYPE, CommonProperty.SPEC_VERSION, CommonProperty.ID, CommonProperty.CREATED,
					CommonProperty.MODIFIED),
			EnumSet.of(CommonProperty.CREATED_BY_REF, CommonProperty.REVOKED, CommonProperty.LABELS,
					CommonProperty.CONFIDENCE, CommonProperty.EXTERNAL_REFERENCES, CommonProperty.OBJECT_MARKING_REFS,
					CommonProperty.GRANULAR_MARKINGS, CommonProperty.EXTENSIONS),
			EnumSet.of(CommonProperty.DEFANGED, CommonProperty.LANG)),
	MARKINGS(EnumSet.of(CommonProperty.TYPE, CommonProperty.SPEC_VERSION, CommonProperty.ID, CommonProperty.CREATED),
			EnumSet.of(CommonProperty.CREATED_BY_REF, CommonProperty.EXTERNAL_REFERENCES,
					CommonProperty.OBJECT_MARKING_REFS, CommonProperty.GRANULAR_MARKINGS, CommonProperty.EXTENSIONS),
			EnumSet.of(CommonProperty.MODIFIED, CommonProperty.REVOKED, CommonProperty.LABELS,
					CommonProperty.CONFIDENCE, CommonProperty.LANG, CommonProperty.DEFANGED)),
	BUNDLE(EnumSet.of(CommonProperty.TYPE, CommonProperty.ID), EnumSet.noneOf(CommonProperty.class),
			EnumSet.of(CommonProperty.SPEC_VERSION, CommonProperty.CREATED_BY_REF, CommonProperty.CREATED,
					CommonProperty.MODIFIED, CommonProperty.REVOKED, CommonProperty.LABELS, CommonProperty.CONFIDENCE,
					CommonProperty.LANG, CommonProperty.EXTERNAL_REFERENCES, CommonProperty.OBJECT_MARKING_REFS,
					CommonProperty.GRANULAR_MARKINGS, CommonProperty.DEFANGED, CommonProperty.EXTENSIONS));

	final EnumSet<CommonProperty> required;
	final EnumSet<CommonProperty> optional;
	final EnumSet<CommonProperty> na;

	private Group(EnumSet<CommonProperty> required, EnumSet<CommonProperty> optional, EnumSet<CommonProperty> na) {
		this.required = required;
		this.optional = optional;
		this.na = na;
	}

	public boolean isRequired(CommonProperty property) {
		return required.contains(property);
	}

	public boolean isOptional(CommonProperty property) {
		return optional.contains(property);
	}

	public boolean isNa(CommonProperty property) {
		return na.contains(property);
	}

	public List<String> checkMissing(JsonNode root) {
		EnumSet<CommonProperty> remaining = EnumSet.copyOf(required);
		Iterator<String> iJsonKey = root.fieldNames();
		while(iJsonKey.hasNext()) {
			try {
				CommonProperty property = CommonProperty.create(iJsonKey.next());
				remaining.remove(property);
			} catch(IllegalArgumentException e) {

			}
		}
		List<String> message = new ArrayList<>();
		for(CommonProperty property : remaining) {
			message.add(String.format("required property %s missing", property.getJsonKey()));
		}
		return message;
	}

	public List<String> checkHasNa(JsonNode root) {
		List<String> message = new ArrayList<>();
		Iterator<String> iJsonKey = root.fieldNames();
		while(iJsonKey.hasNext()) {
			try {
				CommonProperty property = CommonProperty.create(iJsonKey.next());
				if(isNa(property)) {
					message.add(String.format("has not applicable property %s", property.getJsonKey()));
				}
			} catch(IllegalArgumentException e) {

			}
		}
		return message;
	}

}
