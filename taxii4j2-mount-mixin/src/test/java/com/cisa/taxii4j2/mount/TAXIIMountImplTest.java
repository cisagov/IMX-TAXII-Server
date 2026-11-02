/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.mount;

import static org.junit.Assert.fail;

import java.io.InputStream;
import java.io.InputStreamReader;

import org.junit.Test;

import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.mount.TAXIIMount.MountInfo;

public class TAXIIMountImplTest {

	@Test
	public void test() {
		try(InputStream in = ClassLoader.getSystemResourceAsStream("mount.json")) {
			MountInfo info = JSON.readValue(new InputStreamReader(in), MountInfo.class);
			System.out.println(info);
			System.out.println(info.getMp());
			String json = JSON.writeValueAsString(info);
			System.out.println(json);
			info = JSON.readValue(json, MountInfo.class);
			System.out.println(info);
		} catch(Exception e) {
			fail(e.getMessage());
		}
	}

}
