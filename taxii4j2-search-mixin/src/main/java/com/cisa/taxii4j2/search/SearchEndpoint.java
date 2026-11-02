/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.search;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.cisa.taxii4j2.auth.data.Fragment;
import com.cisa.taxii4j2.auth.data.RWCollection;
import com.cisa.taxii4j2.auth.data.TAXIICredentials;
import com.cisa.taxii4j2.auth.method.RootCollectionRead;
import com.cisa.taxii4j2.data.Collections.Collection;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.search.Search.Founds;
import com.cisa.taxii4j2.search.Search.PagedQuery;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.NotAllowedException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.UriInfo;

@Path("ext/v1.0")
public class SearchEndpoint {

	@Context
	private UriInfo uriInfo;

	private final Search search;
	private final RootCollectionRead rcr;

	@Inject
	public SearchEndpoint(Search search, RootCollectionRead rcr) {
		super();
		this.search = search;
		this.rcr = rcr;
	}

	@POST
	@Path("{fragment:.+}/collections/{cId}/search")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Founds search(@HeaderParam(HttpHeaders.AUTHORIZATION) String credentials,
			@PathParam("fragment") String fragment, @PathParam("cId") String cId, PagedQuery query) {
		Collection c = rcr.readCollection(cId);
		if (!c.isCan_read()) {
			throw new NotAllowedException(String.format("can't read collection \"%s\"", cId));
		}
		cId = c.getId();
		Fragment f = rcr.readFragment(fragment);
		Set<String> readers = new HashSet<>(f.getRw(cId).getReaders());
		readers.retainAll(TAXIICredentials.getUser(credentials).getRoles());
		if (readers.isEmpty()) {
			throw new NotAllowedException(String.format("can't read collection \"%s\" on root \"%s\"", cId));
		}
		return search.search(fragment, cId, new Filters(uriInfo.getQueryParameters()), query);
	}

	@POST
	@Path("search")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Founds searchAll(@HeaderParam(HttpHeaders.AUTHORIZATION) String credentials, PagedQuery query) {
		Map<String, Set<String>> fcPairs = new HashMap<>();
		Set<String> roles = TAXIICredentials.getUser(credentials).getRoles();
		for (Fragment f : rcr.listFragments()) {
			try {
				for (RWCollection rw : f.getRws()) {
					try {
						Set<String> readers = new HashSet<>(rw.getReaders());
						readers.retainAll(roles);
						if (readers.isEmpty()) {
							continue;
						}
						String cId = rw.getId();
						if (rcr.readCollection(cId).isCan_read()) {
							fcPairs.computeIfAbsent(f.getFragment(), x -> new HashSet<>()).add(cId);
						}
					} catch (Exception e) {
						// there weren't any readers (most likely)...
					}
				}
			} catch (Exception e) {
				// there may not be any collections on this root...
			}
		}
		return search.search(fcPairs, new Filters(uriInfo.getQueryParameters()), query);
	}

}
