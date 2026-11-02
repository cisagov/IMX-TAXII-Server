/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.api;

import java.util.UUID;

import org.apache.commons.codec.digest.DigestUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.cisa.taxii4j2.client.RemoteBase;
import com.cisa.taxii4j2.data.impl.TAXIIConfig;
import com.cisa.taxii4j2.git.mirror.FilterType;
import com.cisa.taxii4j2.git.mirror.GitHubRepos;
import com.cisa.taxii4j2.git.mirror.LoadableRef;

public class OverrideLoadableRef extends LoadableRef {

	private JsonNode root;
	private String sha;

	public OverrideLoadableRef(UUID uuid, String path, FilterType type) {
		super(uuid, path, null, null, type);
		try {
			root = TAXIIConfig.readValue(path, JsonNode.class);
			sha = DigestUtils.sha256Hex(new ObjectMapper().writeValueAsBytes(root));
		} catch (Exception e) {
			GitHubRepos.logger.error("Error loading override " + path, e);
			root = null;
			sha = null;
		}
	}

	@Override
	public String getSha() {
		return sha;
	}

	@Override
	public JsonNode readTree(RemoteBase client) {
		return root;
	}
}
