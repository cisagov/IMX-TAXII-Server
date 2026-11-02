/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method;

import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.cisa.taxii4j2.auth.data.Lenient;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.method.response.ApiRootResponse;
import com.cisa.taxii4j2.method.response.CollectionResponse;
import com.cisa.taxii4j2.method.response.CollectionsResponse;
import com.cisa.taxii4j2.method.response.DiscoveryResponse;
import com.cisa.taxii4j2.method.response.EnvelopeResponse;
import com.cisa.taxii4j2.method.response.ManifestResponse;
import com.cisa.taxii4j2.method.response.StatusResponse;
import com.cisa.taxii4j2.method.response.VersionsResponse;

import jakarta.ws.rs.core.Response;

public interface TAXII extends Closeable {

	public static final Logger logger = LogManager.getLogger(TAXII.class);

	public DiscoveryResponse discover(URI baseUri);

	public ApiRootResponse apiRoot(String fragment);

	public CollectionsResponse collections(String fragment);

	public CollectionResponse collection(String fragment, String cId);

	public ManifestResponse manifest(String fragment, String cId, Filters filters);

	public VersionsResponse versions(String fragment, String cId, String oId, Filters filters);

	public EnvelopeResponse objects(String fragment, String cId, Filters filters);

	default public EnvelopeResponse objects(String fragment, String cId, String oId, Filters filters) {
		if (filters == null) {
			filters = new Filters();
		} else if (filters.getId() != null) {
			return new EnvelopeResponse(new Error("Read.objects: filter facet must null", Response.Status.BAD_REQUEST));
		}
		return objects(fragment, cId, filters.setId(true, oId));
	}

	public StatusResponse status(String fragment, String id);

	public StatusResponse postObjects(String fragment, String cId, Envelope envelope);

	public void deleteObjects(String fragment, String cId, String oId, Filters filters);

	@Override
	default void close() throws IOException {

	}

	public static interface PreValidator {
		public void preValidate(List<STIXObject> storables, String cId, String statusId);
	}

	default public TAXII addPreValidator(PreValidator preValidator) {
		throw new UnsupportedOperationException();
	}

	public static interface Validator {

		public List<String> validate(STIXObject storable, String cId, Set<Lenient> lenients);

		public boolean getCheck(Set<Lenient> lenients);

		public boolean getFail(Set<Lenient> lenients);

	}

	default public TAXII addValidator(Validator validator) {
		throw new UnsupportedOperationException();
	}

	public static class ValidationResults {

		public final List<String> messages;
		public final boolean fail;

		public ValidationResults(List<String> messages, boolean fail) {
			super();
			this.messages = messages;
			this.fail = fail;
		}

	}

	default public ValidationResults validate(Set<Lenient> lenients, STIXObject storable, String cId) {
		throw new UnsupportedOperationException();
	}

	default public void required(String fragment, String cId) {
		required(fragment);
		required(cId);
	}

	default public void required(String fragmentOrCId) {
		if (fragmentOrCId == null) {
			throw new IllegalArgumentException("federation not allowed");
		}
	}

}
