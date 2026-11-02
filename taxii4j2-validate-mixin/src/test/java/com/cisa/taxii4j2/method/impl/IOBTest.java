/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.impl;

import static org.junit.Assert.fail;

import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;

public class IOBTest {

	@Test
	public void test() {
		try {
			JsonNode root = null;
			try (InputStream in = ClassLoader.getSystemResourceAsStream("iobExtensionDefinitions.json")) {
				root = JSON.readTree(new InputStreamReader(in));
			}
			Iterator<JsonNode> iDefinition = root.get("objects").elements();
			while (iDefinition.hasNext()) {
				JsonNode definition = iDefinition.next();
				URL url = new URL(definition.get("schema").asText());
				try (InputStream in = (InputStream) url.getContent(new Class<?>[] { InputStream.class })) {
					String content = new String(in.readAllBytes());
					System.out.println(content);
				}
			}
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

}
