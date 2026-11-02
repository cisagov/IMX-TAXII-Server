/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data.impl;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.UUID;

import org.junit.Test;

import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.STIXIdentifier;
import com.cisa.taxii4j2.data.Envelope;

public class SCOIdTest {

	@Test
	public void test() {
		Envelope envelope = null;
		try (InputStream in = ClassLoader.getSystemResourceAsStream("sco-examples-bundle.json")) {
			envelope = JSON.readValue(new InputStreamReader(in), Envelope.class);
		} catch (IOException e) {
			fail(e.getMessage());
		}
		for (STIXObject object : envelope.getObjects()) {
			UUID computed = object.getType().getUuid(object.asObjectNode());
			System.out.println(String.format("id %s should be %s", object.getId(),
					STIXIdentifier.encode(object.getStixType(), computed)));
		}
	}

}
