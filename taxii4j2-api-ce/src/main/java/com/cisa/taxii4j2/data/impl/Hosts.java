/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data.impl;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import jakarta.ws.rs.InternalServerErrorException;

public interface Hosts {

	public static Logger logger = LogManager.getLogger(Hosts.class);

	public URL validator();
	public URL generator();

	public URI baseUri();
	public URI taxiiPath();
	public URI adminPath();
	public URI searchPath();
	public URI schemaRepoPath();

	default public URL taxii() {
		return resolve(taxiiPath());
	}

	default public URL admin() {
		return resolve(adminPath());
	}

	default public URL search() {
		return resolve(searchPath());
	}

	default public URL schemaRepo() {
		return resolve(schemaRepoPath());
	}

	default public URL resolve(URI path) {
		try {
			return baseUri().resolve(path).toURL();
		} catch (MalformedURLException e) {
			throw new InternalServerErrorException(e);
		}
	}

}
