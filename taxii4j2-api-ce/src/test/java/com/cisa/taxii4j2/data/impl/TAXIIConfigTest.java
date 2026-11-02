/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data.impl;

import static org.junit.Assert.fail;

import org.junit.Test;

import com.cisa.taxii4j2.data.impl.TAXIIConfig.Args;

public class TAXIIConfigTest {


	@Test
	public void test() {
		try {
			test(new String[] {});
			test(new String[] { "--help"});
			test(new String[] {"--mirror"});
			test(new String[] {"--mirror", "m0", "--mirror", "m1"});
			test(new String[] {"--unknown"});
		} catch(Exception e) {
			fail(e.getMessage());
		}
	}

	private void test(String[] argv) {
		try {
			System.out.println(Args.factory(argv));
		} catch(Exception e) {
			System.err.println(e.getMessage());
		}
	}


}
