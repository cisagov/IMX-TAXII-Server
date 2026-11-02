/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.ext.method;

import java.net.URL;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;

public interface SchemaRepo {

	public static final Logger logger = LogManager.getLogger(SchemaRepo.class);

	public boolean putSchema(String id, JsonNode schema, boolean create);

	public URL url(String id);

	public JsonNode getSchema(String id);

	public Map<String, JsonNode> listSchema();

	public boolean deleteSchema(String id);

}
