/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.cisa.taxii4j2.client.TAXIIClient;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.ext.method.SchemaRepo;
import com.cisa.taxii4j2.git.mirror.GitHubRepos;
import com.cisa.taxii4j2.git.mirror.method.impl.TAXIIImplMirror;
import com.cisa.taxii4j2.method.STIXValidator;
import com.cisa.taxii4j2.method.TAXII;
import com.cisa.taxii4j2.method.impl.Objects;
import com.cisa.taxii4j2.method.impl.Statuses;
import com.cisa.taxii4j2.method.impl.TAXIIImpl;
import com.cisa.taxii4j2.method.impl.TAXIIImplBP;
import com.cisa.taxii4j2.method.impl.TAXIIImplValidate;
import com.cisa.taxii4j2.method.response.ApiRootResponse;
import com.cisa.taxii4j2.method.response.CollectionResponse;
import com.cisa.taxii4j2.method.response.CollectionsResponse;
import com.cisa.taxii4j2.method.response.DiscoveryResponse;
import com.cisa.taxii4j2.method.response.EnvelopeResponse;
import com.cisa.taxii4j2.method.response.ManifestResponse;
import com.cisa.taxii4j2.method.response.StatusResponse;
import com.cisa.taxii4j2.method.response.VersionsResponse;
import com.cisa.taxii4j2.mount.TAXIIMount;
import com.cisa.taxii4j2.mount.TAXIIMount.Mounted;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
public class TAXIICompose0 implements TAXII {

	private final TAXII taxii;
	private final TAXIIMount mount;

	@Inject
	public TAXIICompose0(TAXIIMount mount,
			Objects objects, Statuses statuses, STIXValidator validator, SchemaRepo schemaRepo) {

		super();

		this.mount = mount;

		taxii = TAXIIImpl.instance();
		TAXIIImplBP.compose(taxii);
		TAXIIImplMirror.compose(taxii, objects, statuses);
		TAXIIImplValidate.compose(taxii, validator, (id) -> GitHubRepos.getSchema(id),
				(id) -> schemaRepo.getSchema(id));

}

	@Override
	public DiscoveryResponse discover(URI baseUri) {
		DiscoveryResponse dr = taxii.discover(baseUri);
		if (dr.error != null) {
			return dr;
		}
		List<String> roots = dr.ok.getApi_roots();
		if (roots == null) {
			roots = new ArrayList<>();
		}
		for (Map.Entry<String, TAXIIClient> m : mount.mounts()) {
			DiscoveryResponse mdr = m.getValue().discover(baseUri);
			if (mdr.error != null) {
				continue;
			}
			List<String> mRoots = mdr.ok.getApi_roots();
			if (mRoots != null) {
				for (String r : mRoots) {
					URI uri = URI.create(r);
					URI prefix = uri.relativize(baseUri);
					URI suffix = baseUri.relativize(uri);
					uri = prefix.resolve(m.getKey() + "/").resolve(suffix);
					roots.add(uri.toString());
				}
			}
		}
		if (!roots.isEmpty()) {
			dr.ok.setApi_roots(roots);
		}
		return dr;
	}

	@Override
	public ApiRootResponse apiRoot(String fragment) {
		Mounted mounted = mount.taxii(fragment, taxii);
		return mounted.taxii.apiRoot(mounted.fragment);
	}

	@Override
	public CollectionsResponse collections(String fragment) {
		Mounted mounted = mount.taxii(fragment, taxii);
		return mounted.taxii.collections(mounted.fragment);
	}

	@Override
	public CollectionResponse collection(String fragment, String cId) {
		Mounted mounted = mount.taxii(fragment, taxii);
		return mounted.taxii.collection(mounted.fragment, cId);
	}

	@Override
	public ManifestResponse manifest(String fragment, String cId, Filters filters) {
		Mounted mounted = mount.taxii(fragment, taxii);
		return mounted.taxii.manifest(mounted.fragment, cId, filters);
	}

	@Override
	public VersionsResponse versions(String fragment, String cId, String oId, Filters filters) {
		Mounted mounted = mount.taxii(fragment, taxii);
		return mounted.taxii.versions(mounted.fragment, cId, oId, filters);
	}

	@Override
	public EnvelopeResponse objects(String fragment, String cId, Filters filters) {
		Mounted mounted = mount.taxii(fragment, taxii);
		return mounted.taxii.objects(mounted.fragment, cId, filters);
	}

	@Override
	public StatusResponse status(String fragment, String id) {
		Mounted mounted = mount.taxii(fragment, taxii);
		return mounted.taxii.status(mounted.fragment, id);
	}

	@Override
	public StatusResponse postObjects(String fragment, String cId, Envelope envelope) {
		Mounted mounted = mount.taxii(fragment, taxii);
		return mounted.taxii.postObjects(mounted.fragment, cId, envelope);
	}

	@Override
	public void deleteObjects(String fragment, String cId, String oId, Filters filters) {
		Mounted mounted = mount.taxii(fragment, taxii);
		mounted.taxii.deleteObjects(mounted.fragment, cId, oId, filters);
	}

}
