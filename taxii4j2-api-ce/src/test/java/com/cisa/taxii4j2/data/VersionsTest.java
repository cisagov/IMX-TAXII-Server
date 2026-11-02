/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;

import org.junit.Test;

import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.Timestamp;

public class VersionsTest {

	@Test
	public void test() {
		try {
			Versions versions = new Versions(false,
					Arrays.asList(new Timestamp().toString(), new Timestamp().toString()));
			System.out.println(versions);
			String json = JSON.writeValueAsString(versions);
			System.out.println(json);
			versions = JSON.readValue(json, Versions.class);
			System.out.println(versions);
			try (InputStream in = ClassLoader.getSystemResourceAsStream("versions.json")) {
				versions = JSON.readValue(new InputStreamReader(in), Versions.class);
				System.out.println(versions);
			}
		} catch (IOException e) {
			fail(e.getMessage());
		}
	}

}
