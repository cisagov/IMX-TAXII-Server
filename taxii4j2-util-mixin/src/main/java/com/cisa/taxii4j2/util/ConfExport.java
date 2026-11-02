/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.util;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.auth.data.Fragment;
import com.cisa.taxii4j2.auth.data.RWCollection;
import com.cisa.taxii4j2.auth.method.BulkAdmin.Configuration;
import com.cisa.taxii4j2.client.RemoteInfo;
import com.cisa.taxii4j2.client.TAXIIClient;
import com.cisa.taxii4j2.data.Collections.Collection;
import com.cisa.taxii4j2.method.response.ApiRootResponse;
import com.cisa.taxii4j2.method.response.CollectionsResponse;
import com.cisa.taxii4j2.method.response.DiscoveryResponse;

import jakarta.ws.rs.BadRequestException;

public class ConfExport {

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

	public static Configuration run(RemoteInfo info) throws IOException, URISyntaxException {
		Set<Collection> collections = new HashSet<>();
		List<Fragment> fragments = new ArrayList<>();
		Set<String> roles = Set.of("imx-admin");
		try (TAXIIClient client = TAXIIClient.factory(info)) {
			DiscoveryResponse dr = client.discover(null);
			if (dr.error != null) {
				throw new BadRequestException(dr.error.toString());
			}
			List<String> api_roots = dr.ok.getApi_roots();
			if (api_roots != null) {
				URI remote = info.getUrl().toURI();
				for (String api_root : api_roots) {
					String f = remote.relativize(URI.create(api_root)).toString();
					if (f.endsWith("/")) {
						f = f.substring(0, f.length() - 1);
					}
					ApiRootResponse arr = client.apiRoot(f);
					if (arr.ok != null) {
						Fragment fragment = new Fragment(f, arr.ok, null, null);
						CollectionsResponse cr = client.collections(f);
						List<Collection> cs = (cr.ok != null) ? cr.ok.collections : null;
						if (cs != null) {
							for (Collection c : cs) {
								collections.add(c);
								fragment.addRW(new RWCollection(c.getId(), roles, roles, null));
							}
						}
						fragments.add(fragment);
					}
				}
			}
			return new Configuration(new ArrayList<>(collections), fragments, null);
		}
	}

}
