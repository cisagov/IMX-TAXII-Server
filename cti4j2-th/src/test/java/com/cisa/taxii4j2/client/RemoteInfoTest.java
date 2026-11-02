/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;

import jakarta.ws.rs.core.MultivaluedMap;

public class RemoteInfoTest {

	public static final String url = "https://localhost/";
	public static final String username = "username";
	public static final String password = "password";
	public static final String uuid = UUID.randomUUID().toString();

	@Test
	public void basic() {
		try {
			RemoteInfo basic = RemoteInfo.factory(uuid, url, null, null, username, password, null, null, null);
			System.out.println(basic.getClass());
			String json = JSON.writeValueAsString(basic);
			System.out.println(json);
			RemoteInfo info = JSON.readValue(json, RemoteInfo.class);
			System.out.println(info);
			assertEquals(basic.compareTo(info), 0);
			assertEquals(info.compareTo(basic), 0);
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void proxy() {
		try {
			RemoteInfo basic = RemoteInfo.factory(uuid, url, null, "http://proxy", username, password, null, null, null);
			System.out.println(basic.getClass());
			String json = JSON.writeValueAsString(basic);
			System.out.println(json);
			RemoteInfo info = JSON.readValue(json, RemoteInfo.class);
			System.out.println(info);
			assertEquals(basic.compareTo(info), 0);
			assertEquals(info.compareTo(basic), 0);
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void pkcs10() {
		try {
			RemoteInfo pkcs10 = RemoteInfo.factory(uuid, url, null, null, null, null, "pkcs10", null, null);
			System.out.println(pkcs10.getClass());
			String json = JSON.writeValueAsString(pkcs10);
			System.out.println(json);
			RemoteInfo info = JSON.readValue(json, RemoteInfo.class);
			System.out.println(info);
			assertEquals(pkcs10.compareTo(info), 0);
			assertEquals(info.compareTo(pkcs10), 0);
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void oidc() {
		try {
			RemoteInfo oidc = RemoteInfo.factory(uuid, url, null, null, username, password, null, "https://provider/", null);
			System.out.println(oidc.getClass());
			String json = JSON.writeValueAsString(oidc);
			System.out.println(json);
			RemoteInfo info = JSON.readValue(json, RemoteInfo.class);
			System.out.println(info);
			assertEquals(oidc.compareTo(info), 0);
			assertEquals(info.compareTo(oidc), 0);
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void pkcs12() {
		try {
			RemoteInfo pkcs12 = RemoteInfo.factory(uuid, url, null, null, null, password, null, null, "pkcs12");
			System.out.println(pkcs12.getClass());
			String json = JSON.writeValueAsString(pkcs12);
			System.out.println(json);
			RemoteInfo info = JSON.readValue(json, RemoteInfo.class);
			System.out.println(info);
			assertEquals(pkcs12.compareTo(info), 0);
			assertEquals(info.compareTo(pkcs12), 0);
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void goodHeaders() {
		try {
			headers("headers-good.json");
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void badHeaders() {
		try {
			headers("headers-bad.json");
			fail("badHeaders should have failed");
		} catch (Exception e) {

		}
	}

	private void headers(String path) throws IOException {
		try (InputStream in = ClassLoader.getSystemResourceAsStream(path)) {
			MultivaluedMap<String, Object> headers = RemoteInfo.headers(JSON.readTree(new InputStreamReader(in)));
			System.out.println(headers);
		}
	}

	@Test
	public void sort() {
		try (InputStream in = ClassLoader.getSystemResourceAsStream("infos.json")) {
			JsonNode root = JSON.readTree(new InputStreamReader(in));
			List<RemoteInfo> infos = new ArrayList<>();
			Iterator<JsonNode> iInfo = root.elements();
			while (iInfo.hasNext()) {
				infos.add(JSON.readValue(iInfo.next(), RemoteInfo.class));
			}
			Collections.sort(infos);
			System.out.println(infos);
			for (int i = 0; i < 1024*1024; ++i) {
				Collections.shuffle(infos);
				Collections.sort(infos);
				for (int j = 0; j < infos.size(); ++j) {
					RemoteInfo key = infos.get(j);
					int index = Collections.binarySearch(infos, key);
					if(index != j) {
						System.out.println(String.format("\n%2d %2d %s", j, index, key));
						System.out.println(infos);
						System.out.println();
						fail("broken comparison");
					}
				}
			}
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}
}
