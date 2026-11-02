/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.method;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jvnet.hk2.annotations.Contract;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.taxii4j2.auth.data.Issuer;

@Contract
public interface IssuerAdmin {

	public static final Logger logger = LogManager.getLogger(IssuerAdmin.class);

	public Issuer get(String iss);

	public Issuer put(Issuer issuer);

	public List<Issuer> list();

	public void delete(String iss);

	public boolean isValid(String credentials, JsonNode root);

}
