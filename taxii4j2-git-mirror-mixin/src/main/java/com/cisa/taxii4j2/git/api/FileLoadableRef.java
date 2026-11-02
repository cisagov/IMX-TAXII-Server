/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.api;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.client.RemoteBase;
import com.cisa.taxii4j2.git.mirror.FilterType;
import com.cisa.taxii4j2.git.mirror.LoadableRef;

public class FileLoadableRef extends LoadableRef {

	@JsonIgnore
	private final Path file;

	public FileLoadableRef(UUID uuid, String path, FilterType type, Path file) {
		super(uuid, path, null, null, type);
		this.file = file;
	}

	@Override
	public JsonNode readTree(RemoteBase client) {
		try {
			try(Reader in = Files.newBufferedReader(file)) {
				return JSON.readTree(in);
			}
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

}
