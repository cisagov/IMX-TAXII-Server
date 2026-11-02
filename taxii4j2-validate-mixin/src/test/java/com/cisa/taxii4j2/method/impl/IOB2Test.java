/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.impl;

import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.JsonMetaSchema;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.SpecVersionDetector;
import com.networknt.schema.ValidationMessage;
import com.cisa.cti4j2.JSON;

public class IOB2Test {

	private static final Logger logger = LogManager.getLogger(IOB2Test.class);
	private static Path iob;

	@Test
	public void test() {
		try {
			final URI uri = ClassLoader.getSystemResource("iob").toURI();
			if (!uri.getScheme().equals("file")) {
				try {
					FileSystems.newFileSystem(uri, Map.of("create", "true"));
				} catch (FileSystemAlreadyExistsException e) {
					logger.warn(String.format("%s: already exists", uri));
				}
			}
			iob = Paths.get(uri);
			Files.walkFileTree(iob.resolve("schemas"), new SimpleFileVisitor<Path>() {

				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
					test(file);
					return FileVisitResult.CONTINUE;
				}

			});
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	private void test(Path file) throws IOException {
		System.out.println(file);
		JsonNode root = null;
		try(BufferedReader in = Files.newBufferedReader(file)) {
			root = JSON.readTree(in);
		} catch(Exception e) {
			System.out.println(e.getMessage());
			return;
		}
		SpecVersion.VersionFlag version = SpecVersionDetector.detect(root);
		JsonSchemaFactory.Builder builder = JsonSchemaFactory
				.builder(JsonSchemaFactory.getInstance(version));
		if (version != SpecVersion.VersionFlag.V202012) {
			builder.addMetaSchema(JsonMetaSchema.getV202012());
		}
		JsonSchema schema = builder.build().getSchema(root);
		System.out.println(schema);
		JsonNode object = null;
		try(BufferedReader in = Files.newBufferedReader(iob.resolve("objects").resolve(file.getFileName()))) {
			object = JSON.readTree(in);
		} catch(Exception e) {
			System.out.println(e.getMessage());
			return;
		}
		Set<ValidationMessage> vms = schema.validate(object);
		System.out.println(vms);
	}

}
