/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.cti4j2;

import static org.junit.Assert.fail;

import java.io.InputStream;
import java.io.InputStreamReader;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

public class JSONTest {

	private static final long limit = 9007199254740991L;

	@Test
	public void test() {
		System.out.println(String.format("%d <= %d (%d)", JSON.Integer.MIN_VALUE, JSON.Integer.MAX_VALUE, limit));
		assert(Math.abs(JSON.Integer.MIN_VALUE) == limit);
		assert(Math.abs(JSON.Integer.MAX_VALUE) == limit);
	}

	@Test
	public void single() {
		try(InputStream in = ClassLoader.getSystemResourceAsStream("singlequotes.json")) {
			JsonNode root = JSON.readTree(new InputStreamReader(in));
			String s = root.toPrettyString();
			System.out.println(s);
		} catch(Exception e) {
			fail(e.getMessage());
		}
	}
}
