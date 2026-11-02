/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.graph;

import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.cisa.taxii4j2.method.response.EnvelopeResponse;

public interface Graph {

	public static final Logger logger = LogManager.getLogger(Graph.class);

	public static final Set<String> terminal = Set.of("identity", "location", "language-content", "marking-definition",
			"extension-definition");

	default public EnvelopeResponse graph(String fragment, String cId, String oId, int n) {
		throw new UnsupportedOperationException();
	}

}
