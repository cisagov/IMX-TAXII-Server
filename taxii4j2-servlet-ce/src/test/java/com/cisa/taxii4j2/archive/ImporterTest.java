/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.archive;

import static org.junit.Assert.fail;

import java.io.InputStream;

import org.junit.Test;

public class ImporterTest {

	@Test
	public void test() {
		try (InputStream in = ClassLoader.getSystemResourceAsStream("schema-test-export.tgz")) {
			Importer.factory(in);
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

}
