/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.impl;

import static org.junit.Assert.fail;

import java.io.InputStream;
import java.io.InputStreamReader;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;

public class CleanerTest {

	@Test
	public void test() {
		try (InputStream in = ClassLoader.getSystemResourceAsStream("cleanMe.json")) {
			JsonNode root = JSON.readTree(new InputStreamReader(in));
			JsonNode clean = new Cleaner().apply(root);
			System.out.println(clean.toPrettyString());
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

}
