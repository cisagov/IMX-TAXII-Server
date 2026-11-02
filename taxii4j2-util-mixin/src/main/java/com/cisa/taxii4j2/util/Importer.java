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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;

public class Importer extends Poster {

	private final ZipInputStream inObjects;

	public Importer(String[] args) throws IOException {
		super(args);
		inObjects = new ZipInputStream(Files.newInputStream(Paths.get(args[4])));
	}

	public void run() throws IOException {
		while (true) {
			ZipEntry entry = inObjects.getNextEntry();
			if (entry == null) {
				post();
				return;
			}
			if (!entry.isDirectory()) {
				run(entry);
			}
		}
	}

	private void run(ZipEntry entry) throws IOException {
		System.out.println(entry.getName());
		JsonNode root = JSON.readTree(new String(inObjects.readAllBytes()));
		inObjects.closeEntry();
		Iterator<JsonNode> iObject = iObject(root);
		while (iObject.hasNext()) {
			accept(iObject.next());
		}
		post();
	}

	public static void main(String[] args) {
		try (Importer importer = new Importer(args)) {
			importer.run();
		} catch (Exception e) {
			error(e);
		}
	}

	private static void error(Exception e) {
		System.err.println(e.getMessage());
		try (InputStream in = ClassLoader.getSystemResourceAsStream("importUsage.txt")) {
			System.err.println(new String(in.readAllBytes()));
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		System.exit(-1);
	}

	@Override
	public void close() throws Exception {
		super.close();
		inObjects.close();
	}

}
