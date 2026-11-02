/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.client.RemoteInfo;
import com.cisa.taxii4j2.client.TAXIIClient;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.method.response.EnvelopeResponse;

public class Exporter {

	private static final int limit = 256;

	public static void main(String[] args) {
		try (Reader in = Files.newBufferedReader(Paths.get(args[0]))) {
			run(JSON.readValue(in, RemoteInfo.class), args[1], args[2], Paths.get(args[3]));
		} catch (Exception e) {
			error(e);
		}
	}

	public static void run(RemoteInfo info, String fragment, String cId, Path path) throws IOException {
		try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(path))) {
			try (TAXIIClient client = TAXIIClient.factory(info)) {
				for (int i = 0; i < 16; ++i) {
					out.putNextEntry(new ZipEntry(String.format("%X/", i)));
					out.closeEntry();
				}
				int i = 0;
				Filters filters = new Filters().setLimit(limit).setVersion(true, Filters.allKey);
				while (true) {
					EnvelopeResponse er = client.objects(fragment, cId, filters);
					if (er.error != null) {
						System.err.println(er.error.toString());
						break;
					}
					Envelope ok = er.ok;
					String name = String.format("%X/%04X.json", i & 0xf, i >> 4);
					out.putNextEntry(new ZipEntry(name));
					out.write(ok.toString().getBytes());
					out.closeEntry();
					System.err.println(name);
					String next = ok.getNext();
					if(next == null) {
						break;
					}
					filters.set(true, Filters.nextKey, next);
					++i;
				}
			}
			out.finish();
		}

	}

	private static void error(Exception e) {
		System.err.println(e.getMessage());
		try(InputStream in = ClassLoader.getSystemResourceAsStream("exportUsage.txt")) {
			System.err.println(new String(in.readAllBytes()));
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		System.exit(-1);
	}

}
