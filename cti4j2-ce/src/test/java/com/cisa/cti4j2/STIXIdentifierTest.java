/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.cti4j2;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Iterator;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

public class STIXIdentifierTest {

	@Test
	public void test() {
		try {
			Path dir = Paths.get(ClassLoader.getSystemResource("SCOs").toURI());
			Files.walkFileTree(dir, new SimpleFileVisitor<Path>() {

				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
					try (Reader in = Files.newBufferedReader(file)) {
						JsonNode roots = JSON.readTree(in);
						Iterator<JsonNode> iRoot = roots.elements();
						while (iRoot.hasNext()) {
							JsonNode root = iRoot.next();
							String id = STIXIdentifier.encode(root);
							System.out.println(
									String.format("%s\n\t%s", root.get(CommonProperty.ID.getJsonKey()).asText(), id));
						}
					}
					return FileVisitResult.CONTINUE;
				}

			});
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

}
