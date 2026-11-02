/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.store;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.cisa.cti4j2.STIXIdentifier;
import com.cisa.cti4j2.Type;
import com.cisa.taxii4j2.data.impl.STIXObject;

public interface DbTaxii {

	public static Logger logger = LogManager.getLogger(DbTaxii.class);
	public static final String qualifierCustom = "custom";

	public DbBase getDb();

	public String createObjectIndex(String name);

	/**
	 * Find objects regardless of collection membership (all versions)
	 *
	 * @param id
	 * @return
	 */
	public List<STIXObject> read(String id, int from, int size);

	/**
	 * Read single object regardless of collection membership
	 *
	 * @param id
	 * @param version
	 * @return
	 */
	public STIXObject read(String id, String version);

	public Set<String> allObjectIndices();

	default public String objectIndexName(String qualifier, String stixType) {
		return getDb().localizeIndexName(String.format("%s-%s", qualifier, stixType));
	}

	default public Set<String> objectIndices(Set<String> stixTypes) {
		return stixTypes.stream().map(t -> objectIndexName(t)).collect(Collectors.toSet());
	}

	default public String createObjectIndex(STIXObject object) {
		return createObjectIndex(objectIndexName(object));
	}

	default public String objectIndexName(STIXObject object) {
		return objectIndexName(STIXIdentifier.getStixType(object.getId()));
	}

	default public String objectIndexName(String stixType) {
		try {
			Type type = Type.fromSTIXType(stixType);
			return objectIndexName(type.indexQualifier(), stixType);
		} catch (IllegalArgumentException e) {
			// TODO - for now permitting dynamic index creation / use for custom objects...
			return createObjectIndex(objectIndexName(qualifierCustom, stixType));
		}
	}

	default public List<STIXObject> read(String id) {
		return read(id, 0, DbBase.maxSize);
	}

}
