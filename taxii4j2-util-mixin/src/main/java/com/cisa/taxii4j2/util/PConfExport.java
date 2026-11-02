/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.util;

import java.io.Reader;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import com.cisa.cti4j2.CTIMediaType;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.auth.data.Fragment;
import com.cisa.taxii4j2.auth.data.User;
import com.cisa.taxii4j2.auth.method.BulkAdmin.Configuration;
import com.cisa.taxii4j2.client.RemoteBearerBase;
import com.cisa.taxii4j2.client.RemoteInfo;
import com.cisa.taxii4j2.data.Collections.Collection;

public class PConfExport {

	public static void main(String[] args) {
		try (Reader in = Files.newBufferedReader(Paths.get(args[0]))) {
			Configuration configuration = run(JSON.readValue(in, RemoteInfo.class));
			try (Writer out = Files.newBufferedWriter(Paths.get(args[1]))) {
				out.write(JSON.writeValueAsString(configuration));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static Configuration run(RemoteInfo info) throws Exception {
		try (RemoteBearerBase client = new RemoteBearerBase(info, CTIMediaType.TAXII2_1, CTIMediaType.TAXII2_1)) {
			@SuppressWarnings("unchecked")
			List<Fragment> fragments = client.getHelper(List.class, null, "api-roots");
			@SuppressWarnings("unchecked")
			List<Collection> collections = client.getHelper(List.class, null, "collections");
			@SuppressWarnings("unchecked")
			List<User> users = client.getHelper(List.class, null, "users");
			return new Configuration(collections, fragments, users);
		}
	}

}
