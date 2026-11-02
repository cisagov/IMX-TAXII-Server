/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;

public class BulkLoader extends Poster {

	private final BufferedReader in;

	public BulkLoader(String[] args) throws IOException {
		super(args);
		in = Files.newBufferedReader(Paths.get(args[4]));
	}

	@Override
	public void close() throws Exception {
		super.close();
		in.close();
	}

	public void run() throws IOException {
		JsonNode src = JSON.readTree(in);
		Iterator<JsonNode> iObject = iObject(src);
		while (iObject.hasNext()) {
			accept(iObject.next());
		}
		post();
	}

	public static void main(String[] args) {
		try (BulkLoader loader = new BulkLoader(args)) {
			loader.run();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
