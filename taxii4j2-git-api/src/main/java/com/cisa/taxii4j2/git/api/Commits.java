/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

public class Commits extends GitHub.Wrapper {

	public Commits(JsonNode object) {
		super(object);
	}

	public Commit commit() {
		return commit(0);
	}

	public Commit commit(int i) {
		try {
			return new Commit(ArrayNode.class.cast(getObject()).get(i));
		} catch (ClassCastException e) {
			throw new RuntimeException("Error from github: " + getObject().get("message").asText());
		}
	}

}
