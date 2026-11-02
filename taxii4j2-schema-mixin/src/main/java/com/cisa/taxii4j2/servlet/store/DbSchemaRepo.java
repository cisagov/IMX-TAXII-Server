/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.store;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.data.impl.PropsHosts;
import com.cisa.taxii4j2.ext.method.SchemaRepo;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.core.UriBuilder;

@Singleton
public class DbSchemaRepo implements SchemaRepo {

	private static final String schemaDirName = "/predefined-extension-schema";
	private final String schemaIndex;
	private Set<String> untouchables = new HashSet<>();
	private static final String schemaKey = "schema";

	private final DbBase db;
	private final URI uri;

	@Override
	public URL url(String id) {
		try {
			return UriBuilder.fromUri(uri).path(id).build().toURL();
		} catch (MalformedURLException e) {
			throw new BadRequestException(e);
		}
	}

	@Inject
	public DbSchemaRepo(DbBase db) throws IOException, URISyntaxException {
		super();
		this.db = db;
		uri = PropsHosts.instance().schemaRepo().toURI();
		schemaIndex = db.createIndex(db.localizeIndexName("extension-schema"));

		final URI uri = getClass().getResource(schemaDirName).toURI();
		if (!uri.getScheme().equals("file")) {
			try {
				FileSystems.newFileSystem(uri, Map.of("create", "true"));
			} catch (FileSystemAlreadyExistsException e) {
				logger.warn(String.format("%s: already exists", uri));
			}
		}
		Path schemaDir = Paths.get(uri);

		Files.walkFileTree(schemaDir, new SimpleFileVisitor<Path>() {

			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
				try (BufferedReader in = Files.newBufferedReader(file)) {
					JsonNode schema = JSON.readTree(in);
					String id = file.getFileName().toString();
					id = id.substring(0, id.lastIndexOf('.'));
					putSchema(id, schema, false);
//					ES.put(schema, schemaIndex, id, false);
					untouchables.add(id);
				}
				return FileVisitResult.CONTINUE;
			}

		});
	}

	private JsonNode wrap(JsonNode schema) {
		return JSON.factory.objectNode().put(schemaKey, schema.toPrettyString());
	}

	private JsonNode unwrap(JsonNode wrapped) {
		try {
			return JSON.readTree(wrapped.get(schemaKey).asText());
		} catch (Exception e) {
			return null;
		}
	}

	@Override
	public boolean putSchema(String id, JsonNode schema, boolean create) {
		if (untouchables.contains(id)) {
			throw new ForbiddenException(String.format("\"%s\" is a predefined extension", id));
		}
		db.put(wrap(schema), schemaIndex, id, create);
		return true;
	}

	@Override
	public Map<String, JsonNode> listSchema() {
		Map<String, JsonNode> wrapped = db.map(schemaIndex, JsonNode.class, DbBase.maxSize);
		Map<String, JsonNode> unwrapped = new HashMap<>();
		wrapped.forEach((k, v) -> unwrapped.put(k, unwrap(v)));
		return unwrapped;
	}

	@Override
	public boolean deleteSchema(String id) {
		if (untouchables.contains(id)) {
			throw new ForbiddenException(String.format("\"%s\" is a predefined extension", id));
		}
		if (getSchema(id) == null) {
			return false;
		}
		db.delete(id, schemaIndex, JsonNode.class);
		return true;
	}

	@Override
	public JsonNode getSchema(String id) {
		return unwrap(db.get(id, schemaIndex, JsonNode.class));
	}

}
