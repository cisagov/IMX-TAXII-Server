/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job.taxii.remote;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.junit.Test;

import com.cisa.cti4j2.JSON;

public class TAXIIRemoteConfigurationTest {

	@Test
	public void test() {
		try {
			test("configuration-remote.json");
			test("configuration-remote-pkcs12.json");
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	private void test(String name) throws IOException {
		try (InputStream in = ClassLoader.getSystemResourceAsStream(name)) {
			TAXIIRemoteConfiguration config = JSON.readValue(new InputStreamReader(in), TAXIIRemoteConfiguration.class);
			System.out.println(config);
			String json = JSON.writeValueAsString(config);
			System.out.println(json);
			config = JSON.readValue(json, TAXIIRemoteConfiguration.class);
			System.out.println(config);
		}
	}
}
