/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.api;

import java.io.IOException;
import java.util.UUID;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.client.RemoteBase;
import com.cisa.taxii4j2.git.mirror.FilterType;
import com.cisa.taxii4j2.git.mirror.LoadableRef;

public class ApiLoadableRef extends LoadableRef {

	public ApiLoadableRef(UUID uuid, String path, String sha, String url, FilterType type) {
		super(uuid, path, sha, url, type);
	}

	@Override
	public JsonNode readTree(RemoteBase client) {
		try {
			return JSON.readTree(new Blob(super.readTree(client)).content());
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

}
