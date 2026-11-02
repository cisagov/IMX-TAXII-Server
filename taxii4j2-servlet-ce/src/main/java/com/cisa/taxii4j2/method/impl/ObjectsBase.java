/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.impl;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.data.impl.Storable;
import com.cisa.taxii4j2.method.impl.Nexts.Entry;
import com.cisa.taxii4j2.servlet.store.DbBase;
import com.cisa.taxii4j2.servlet.store.DbTaxii;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotFoundException;

@Singleton
public abstract class ObjectsBase implements Objects {

	private final Nexts nexts;

	protected final DbTaxii dbTaxii;
	protected final DbBase dbBase;

	@Inject
	public ObjectsBase(DbTaxii dbTaxii, Nexts nexts) {
		super();
		this.dbTaxii = dbTaxii;
		this.dbBase = dbTaxii.getDb();
		this.nexts = nexts;
	}

	protected Set<String> indices(Filters filters) {
		return indices(dbTaxii, filters);
	}

	public static Set<String> indices(DbTaxii dbTaxii, Filters filters) {
		Set<String> types = filters.getN(Filters.typeKey);
		return (types != null) ? dbTaxii.objectIndices(types) : dbTaxii.allObjectIndices();
	}

	@Override
	public Envelope envelope(String cId, Filters filters, long max_content_length) {

		try {
			UUID.fromString(cId);
		} catch (IllegalArgumentException e) {
			throw new InternalServerErrorException(String.format("OSObjects.envelope: %s not UUID", cId), e);
		}

		String next = filters.getNext();
		if (next != null) {
			Entry entry = nexts.read(next);
			cId = entry.getcId();
			filters = entry.getFilters();
		}
		Envelope prev = read(cId, filters, max_content_length);
		List<STIXObject> objects = prev.getObjects();
		Timestamp last = null;
		if ((objects != null) && !objects.isEmpty()) {
			last = objects.get(objects.size() - 1).getDate_added(cId);
//			objects.forEach(o -> o.removeMyX_());
		}
		Envelope curr = nexts.create(prev.getMore(), last, cId, filters);
		return curr.setObjects(objects, cId);
	}

	@Override
	public void refresh(String... type) {
		dbBase.refresh(Arrays.stream(type).map(t -> dbTaxii.objectIndexName(t)).toArray(String[]::new));
	}

	@Override
	public List<STIXObject> read(String oId) {
		return dbTaxii.read(oId);
	}

	@Override
	public void put(STIXObject object) {
		dbBase.put(object, dbTaxii.objectIndexName(object), Storable.encodeId(object), false);
	}

	@Override
	public void delete(String cId, String oId, Filters filters) {

		try {
			UUID.fromString(cId);
		} catch (IllegalArgumentException e) {
			throw new InternalServerErrorException(String.format("OSObjects.delete: %s not UUID", cId), e);
		}

		List<STIXObject> objects = null;

		if (oId != null) {

			/*
			 * filter by version
			 */
			objects = filters.retainVersion(read(cId, oId));
			if ((objects == null) || objects.isEmpty()) {
				throw new NotFoundException();
			}

			/*
			 * filter by spec_version
			 */
			Set<String> spec_version = filters.getSpec_version();
			if ((spec_version != null) && !spec_version.isEmpty()) {
				Iterator<STIXObject> iObject = objects.iterator();
				while (iObject.hasNext()) {
					if (!spec_version.contains(iObject.next().getSpec_version())) {
						iObject.remove();
					}
				}
			}

			if ((objects == null) || objects.isEmpty()) {
				throw new NotFoundException();
			}

			/*
			 * set the date_added to null...
			 */
			delete(cId, objects);

			return;

		}

		/*
		 * clear collection
		 */
		filters = new Filters().setVersion(true, Filters.allKey);
		while (true) {
			Envelope envelope = read(cId, filters, max_content_length);
			objects = envelope.getObjects();
			if ((objects != null) && !objects.isEmpty()) {
				delete(cId, objects);
			}
			String next = envelope.getNext();
			if (!envelope.getMore() || (next == null)) {
				return;
			}
			filters.set(true, Filters.nextKey, next);
		}

	}

	private static long max_content_length = 1L << 20;
}
