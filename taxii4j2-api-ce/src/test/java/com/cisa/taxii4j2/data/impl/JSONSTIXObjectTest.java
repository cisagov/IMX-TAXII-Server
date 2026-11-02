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

public class JSONSTIXObjectTest {

	@Test
	public void test() {
		try {
			STIXObject object = null;
			try (InputStream in = ClassLoader.getSystemResourceAsStream("JSONSTIXObject.json")) {
				object = JSON.readValue(new InputStreamReader(in), STIXObject.class);
				System.out.println(object);
				String json = JSON.writeValueAsString(object);
				System.out.println(json);
				object = JSON.readValue(json, STIXObject.class);
				System.out.println(object);
			}
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

}
