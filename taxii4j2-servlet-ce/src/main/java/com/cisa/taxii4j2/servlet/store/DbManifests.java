/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.store;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import com.cisa.cti4j2.CTIMediaType;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.data.Manifest;
import com.cisa.taxii4j2.data.Manifest.Record;
import com.cisa.taxii4j2.data.Versions;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.method.impl.Manifests;
import com.cisa.taxii4j2.method.impl.Objects;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.InternalServerErrorException;

@Singleton
public class DbManifests implements Manifests {

	private final Objects objects;

	@Inject
	public DbManifests(Objects objects) throws IOException {
		super();
		this.objects = objects;
	}

	@Override
	public Manifest read(String cId, Filters filters, long max_content_length) {

		try {
			UUID.fromString(cId);
		} catch (IllegalArgumentException e) {
			throw new InternalServerErrorException(String.format("ESManifests.read: %s not UUID", cId), e);
		}

		Envelope envelope = objects.read(cId, filters, max_content_length);
		List<STIXObject> objects = envelope.getObjects();
		if (objects == null) {
			return new Manifest(null, null);
		}
		return new Manifest(envelope.getMore(),
				objects.stream()
						.map(o -> new Record(o.getId(), o.getDate_added(cId), o.getVersion(),
								String.format("%s;version=%s", CTIMediaType.STIX, o.getSpec_version())))
						.collect(Collectors.toList()));
	}

	@Override
	public Versions versions(String cId, String oId, Filters filters, long max_content_length) {

		try {
			UUID.fromString(cId);
		} catch (IllegalArgumentException e) {
			throw new InternalServerErrorException(String.format("ESManifests.versions: %s not UUID", cId), e);
		}

		if ((filters.getN(Filters.match(Filters.idKey)) != null)
				|| (filters.getN(Filters.match(Filters.versionKey)) != null)) {
			throw new IllegalArgumentException("ESManifests.versions: match[*] not allowed");
		}
		filters.setId(true, oId).setVersion(true, Filters.allKey);
		Envelope envelope = objects.read(cId, filters, max_content_length);
		List<STIXObject> objects = envelope.getObjects();
		if (objects == null) {
			return new Versions(null, null);
		}
		Timestamp first = objects.get(0).getDate_added(cId);
		Timestamp last = objects.get(objects.size() - 1).getDate_added(cId);
		return new Versions(envelope.getMore(), objects.stream().map(o -> o.getVersion()).collect(Collectors.toList()),
				first, last);
	}

}
