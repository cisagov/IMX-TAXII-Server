/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.api;

import com.fasterxml.jackson.databind.JsonNode;

public class Commit extends GitHub.Wrapper {

	public Commit(JsonNode object) {
		super(object);
	}

	private JsonNode tree() {
		return getObject().get("commit").get("tree");
	}

	public String treeSha() {
		return tree().get(shaKey).asText();
	}

	public String treeUrl() {
		return tree().get(urlKey).asText();
	}

}
