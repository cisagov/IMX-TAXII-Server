/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package org.webpki.jcs;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;

import org.junit.Test;

public class JsonCanonicalizerTest {

	@Test
	public void test() {
		try {
			Path testdata = Paths.get(ClassLoader.getSystemResource("canonicalization-testdata").toURI());
			Path input = testdata.resolve("input");
			final Path output = testdata.resolve("output");
			Files.walkFileTree(input, new SimpleFileVisitor<Path>() {

				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
					JsonCanonicalizer jc = new JsonCanonicalizer(new String(Files.readAllBytes(file)));
					Path fileName = file.getFileName();
					String reference = new String(Files.readAllBytes(output.resolve(fileName))).strip();
					if (!reference.equals(jc.getEncodedString())) {
						fail(fileName.toString());
					}
					return FileVisitResult.CONTINUE;
				}

			});
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

}
