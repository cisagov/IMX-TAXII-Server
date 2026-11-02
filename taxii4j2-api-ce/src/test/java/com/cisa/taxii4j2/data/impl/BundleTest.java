/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data.impl;

import static org.junit.Assert.fail;

import java.io.InputStream;
import java.io.InputStreamReader;

import org.junit.Test;

import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.data.Envelope;

public class BundleTest {

	@Test
	public void test() {
		try {
			STIXObject bundle = new JSONBundle();
			System.out.println(bundle);
			String json = JSON.writeValueAsString(bundle);
			System.out.println(json);
			bundle = JSON.readValue(json, STIXObject.class);
			System.out.println(bundle);
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void envelope() {
		try (InputStream in = ClassLoader.getSystemResourceAsStream("identity.json")) {
			Envelope envelope = JSON.readValue(new InputStreamReader(in), Envelope.class);
			System.out.println(envelope);
			STIXObject bundle = new JSONBundle(envelope);
			System.out.println(bundle);
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}
}
