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
import java.nio.charset.Charset;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Iterator;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;

public class DirPoster extends Poster {

	private final Path path;

	public DirPoster(String[] args) throws IOException {
		super(args);
		path = Paths.get(args[4]);
	}

	public void run() throws IOException {
		Files.walkFileTree(path, new SimpleFileVisitor<Path>() {

			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
				try {
					JsonNode root = JSON.readTree(Files.readString(file, Charset.defaultCharset()));
					Iterator<JsonNode> iObject = iObject(root);
					while (iObject.hasNext()) {
						accept(iObject.next());
					}
				} catch (IOException e) {
					logger.warn(String.format("%s: %s", file, e.getMessage()));
				}
				return FileVisitResult.CONTINUE;
			}

		});
		post();
	}

	public static void main(String[] args) {
		try (DirPoster importer = new DirPoster(args)) {
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

}
