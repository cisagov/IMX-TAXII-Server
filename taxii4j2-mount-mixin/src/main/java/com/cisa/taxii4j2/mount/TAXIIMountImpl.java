/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.mount;

import java.util.AbstractMap;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.client.TAXIIClient;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.method.TAXII;
import com.cisa.taxii4j2.servlet.store.DbBase;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
public class TAXIIMountImpl implements TAXIIMount {

	private final DbBase db;
	private final String index;

	@Inject
	public TAXIIMountImpl(DbBase db) {
		super();
		this.db = db;
		index = db.createIndex(db.localizeIndexName("mounts"));
		for (MountInfo info : db.list(index, MountInfo.class)) {
			_mount(info);
		}
	}

	private static String[] parts(String s) {
		return s.split("/");
	}

	private static final Comparator<String> mpCmp = new Comparator<>() {
		@Override
		public int compare(String o1, String o2) {
			int n1 = parts(o1).length;
			int n2 = parts(o2).length;
			boolean startsWith = (n1 < n2) ? o2.startsWith(o1) : o1.startsWith(o2);
			return startsWith ? 0 : o1.compareTo(o2);
		}
	};

	private final TreeMap<String, TAXIIClient> taxiis = new TreeMap<>(mpCmp);

	@Override
	public Set<Map.Entry<String, TAXIIClient>> mounts() {
		synchronized (taxiis) {
			return Collections.unmodifiableSet(new HashSet<>(taxiis.entrySet()));
		}
	}

	@Override
	public Map.Entry<String, TAXIIClient> taxii(String mp) {
		synchronized (taxiis) {
			/*
			 * Using ceiling() and floor() here because want / need to return both the found
			 * key and value (and can't do that with get())...
			 */
			Map.Entry<String, TAXIIClient> ceiling = taxiis.ceilingEntry(mp);
			if (ceiling == null) {
				return null;
			}
			Map.Entry<String, TAXIIClient> floor = taxiis.floorEntry(mp);
			if (floor == null) {
				return null;
			}
			return (ceiling.getKey().compareTo(floor.getKey()) == 0) ? ceiling : null;
		}
	}

	@Override
	public Mounted taxii(String mp, TAXII taxii) {
		String mountPoint = null;
		String fragment = mp;
		Map.Entry<String, TAXIIClient> entry = taxii(mp);
		if (entry != null) {
			mountPoint = entry.getKey().toString();
			fragment = mp.substring(entry.getKey().length() + 1);
			taxii = entry.getValue();
		}
		return new Mounted(mountPoint, fragment, taxii);
	}

	@Override
	public Map.Entry<String, TAXIIClient> mount(MountInfo mountInfo) {
		Map.Entry<String, TAXIIClient> mount = _mount(mountInfo);
		if (mount != null) {
			db.put(mountInfo, index, mountInfo.getMp());
		}
		return mount;
	}

	private Map.Entry<String, TAXIIClient> _mount(MountInfo mountInfo) {
		synchronized (taxiis) {

			String mp = mountInfo.getMp().trim();
			if (mp.endsWith("/")) {
				mp = mp.substring(0, mp.length() - 1);
			}
			if (taxii(mp) != null) {
				throw new IllegalArgumentException();
			}

			TAXIIClient taxii = TAXIIClient.factory(mountInfo.getInfo());
			try {
				Error error = taxii.discover(null).error;
				if (error != null) {
					throw new IllegalArgumentException(JSON.writeValueAsString(error));
				}
			} catch (Exception e) {
				throw new IllegalArgumentException(e);
			}

			taxiis.put(mp, taxii);
			return taxii(mp);

		}
	}

	@Override
	public Map.Entry<String, TAXIIClient> unmount(String mp) {
		synchronized (taxiis) {
			TAXIIClient taxii = taxiis.remove(mp);
			if (taxii != null) {
				db.delete(mp, index, MountInfo.class);
				return new AbstractMap.SimpleImmutableEntry<>(mp, taxii);
			}
			return null;
		}
	}

}
