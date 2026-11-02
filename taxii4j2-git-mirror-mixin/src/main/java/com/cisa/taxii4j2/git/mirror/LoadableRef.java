/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.mirror;

import java.io.IOException;
import java.io.Reader;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Iterator;
import java.util.UUID;

import org.apache.logging.log4j.Level;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.client.RemoteBase;

import jakarta.ws.rs.core.MediaType;

public class LoadableRef extends Ref {

	@JsonIgnore
	private final String url;

	@JsonIgnore
	private final FilterType type;

	public LoadableRef(UUID uuid, String path, String sha, String url, FilterType type) {
		super(uuid, path, sha);
		this.url = url;
		this.type = type;
	}

	public JsonNode readTree(RemoteBase client) {
		GitHubRepos.logger.info(String.format("LoadableRef.readTree %s", url));
		if (client != null) {
			return client.paths(client.target(url), null, MediaType.APPLICATION_JSON, null).get(JsonNode.class);
		}
		URI uri = URI.create(url);
		if (uri.getScheme().equalsIgnoreCase("file")) {
			try (Reader in = Files.newBufferedReader(Paths.get(uri))) {
				return JSON.readTree(in);
			} catch (IOException e) {
				throw new IllegalArgumentException(e);
			}
		}
		throw new IllegalArgumentException(String.format("LoadableRef.readTree: can't cope with %s", url));
	}

	public void create(RemoteBase client, Mapping mapping) {
		try {
			JsonNode root = readTree(client);
			switch (type) {
			case OBJECT:
				JsonNode objectsNode = root.get("objects");
				Iterator<JsonNode> iObject = (objectsNode != null) ? objectsNode.elements()
						: Collections.singletonList(root).iterator();
				int offset = 0;
				while (iObject.hasNext()) {
					GitHubRepos.createFile(iObject.next(), mapping, getPath(), getSha(), offset++);
				}
				break;
			case SCHEMA:
				GitHubRepos.createSchema(root, mapping, getPath(), getSha());
				break;
			default:
				break;

			}
		} catch (IllegalArgumentException e) {
			GitHubRepos.logger.log(Level.WARN, String.format("%s: %s", url, e.getMessage()));
		} catch (Exception e) {
			GitHubRepos.logger.log(Level.ERROR, String.format("Unexpected exception reading from %s", url), e);
		}
	}

}
