/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data;

import static org.junit.Assert.fail;

import java.io.InputStreamReader;
import java.io.Reader;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.impl.ApiConfiguration;

public class EnvelopeTest {

	private static final String suffix = "Envelope";

	@Test
	public void test() {
		ApiConfiguration.configure("configuration-minimum.properties");
		test("valid");
		test("invalid");
	}

	private void test(String prefix) {
		int i = 0;
		while (true) {
			try (Reader in = new InputStreamReader(
					ClassLoader.getSystemResourceAsStream(String.format("%s%s%d.json", prefix, suffix, i)))) {
				try {
					JsonNode root = JSON.readTree(in);
					System.out.println("-> " + root);
					try {
						Envelope envelope = Envelope.create(root);
						System.out.println("<- " + JSON.writeValueAsString(envelope));
					} catch(Exception e) {
						e.printStackTrace();
					}
				} catch(Exception e) {
					e.printStackTrace();
					fail(e.getMessage());
				}
			} catch(Exception e) {
				break;
			}
			++i;
		}
	}
}
