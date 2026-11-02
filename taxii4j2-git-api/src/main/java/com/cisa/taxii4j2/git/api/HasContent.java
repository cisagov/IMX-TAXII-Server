/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.api;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.fasterxml.jackson.databind.JsonNode;

public class HasContent extends GitHub.Wrapper {

	private static final Base64.Decoder decoder = Base64.getDecoder();
	private final String base64Encoding = "base64";
	private final String utf8Encoding = "utf-8";

	protected HasContent(JsonNode object) {
		super(object);
	}

	public String content() {
		String content = getObject().get("content").asText();
		String encoding = getObject().get("encoding").asText().toLowerCase();
		if (encoding.equals(base64Encoding)) {
			content = new String(decoder.decode(content.replaceAll("\n", "")), StandardCharsets.UTF_8);
		} else if (!encoding.equals(utf8Encoding)) {
			throw new IllegalArgumentException(String.format("HasContent.content: unknown encoding \"%s\"", encoding));
		}
		return content;
	}

	public int size() {
		return size(getObject());
	}

	public static int size(JsonNode node) {
		return node.get("size").asInt();
	}

}
