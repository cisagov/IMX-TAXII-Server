/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.ext.method;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.SpecVersionDetector;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.servlet.Dirs;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
public class FSSchemaRepo implements SchemaRepo {

	private final Path dir;
	private static FSSchemaRepo instance;

	public static Path getDir() {
		return instance.dir;
	}

	@Inject
	public FSSchemaRepo() {
		super();
		dir = Dirs.instance().schema();
		instance = this;
	}

	private Path path(String id) {
		return dir.resolve(id);
	}

	private String id(Path path) {
		return dir.relativize(path).toString();
	}

	@Override
	public boolean putSchema(String id, JsonNode schema, boolean create) {
		Path path = path(id);
		if (create && Files.exists(path)) {
			return false;
		}
		try {
			Files.writeString(path, schema.toPrettyString());
			return true;
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

	@Override
	public URL url(String id) {
		try {
			return path(id).toUri().toURL();
		} catch (MalformedURLException e) {
			throw new IllegalArgumentException(e);
		}
	}

	@Override
	public JsonNode getSchema(String id) {
		try {
			JsonNode schema = JSON.readTree(Files.readString(path(id)));
			SpecVersionDetector.detect(schema);
			return schema;
		} catch (Exception e) {
			throw new IllegalArgumentException(e);
		}
	}

	@Override
	public Map<String, JsonNode> listSchema() {
		Map<String, JsonNode> schema = new HashMap<>();
		try {
			Files.walkFileTree(dir, new SimpleFileVisitor<Path>() {

//				private int depth = 0;

				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
					String id = id(file);
					try {
						schema.put(id, getSchema(id));
					} catch (IllegalArgumentException e) {
						logger.warn(String.format("%s not a schema...", file));
					}
					return FileVisitResult.CONTINUE;
				}

//				@Override
//				public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
//					--depth;
//					return FileVisitResult.CONTINUE;
//				}
//
//				@Override
//				public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
//					if (depth > 0) {
//						return FileVisitResult.SKIP_SUBTREE;
//					}
//					++depth;
//					return FileVisitResult.CONTINUE;
//				}

			});
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
		return schema;
	}

	@Override
	public boolean deleteSchema(String id) {
		Path path = path(id);
		if (!Files.exists(path)) {
			return false;
		}
		try {
			Files.delete(path);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
		return true;
	}

}
