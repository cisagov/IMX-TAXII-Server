/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet;

import java.net.URI;

import com.cisa.cti4j2.CTIMediaType;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.data.impl.PropsHosts;
import com.cisa.taxii4j2.method.TAXII;
import com.cisa.taxii4j2.method.response.ApiRootResponse;
import com.cisa.taxii4j2.method.response.EnvelopeResponse;
import com.cisa.taxii4j2.method.response.ManifestResponse;
import com.cisa.taxii4j2.method.response.StatusResponse;
import com.cisa.taxii4j2.method.response.VersionsResponse;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;


@Singleton
@Path("/taxii/v2.1-os/")
public class TAXIIEndpoint {

	@Context
	private UriInfo uriInfo;

	private final TAXII taxii;
	private final URI taxiiPath;

	@Inject
	public TAXIIEndpoint(TAXII taxii) throws Exception {
		super();
		this.taxii = taxii;
		taxiiPath = PropsHosts.instance().taxiiPath();
	}

	@GET
	@Path("taxii2")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response discover(@HeaderParam("X-Forwarded-Proto") String proto) {
		URI baseUri = uriInfo.getBaseUri().resolve(taxiiPath);
		try {
			if (proto != null) {
				baseUri = new URI(proto,
						baseUri.getUserInfo(),
						baseUri.getHost(),
						baseUri.getPort(),
						baseUri.getPath(),
						baseUri.getQuery(),
						baseUri.getFragment());
			}
			return EndpointUtils.builder(taxii.discover(baseUri)).build();
		} catch (WebApplicationException e) {
			return EndpointUtils.error(e);
		} catch (Exception e) {
			return EndpointUtils.error(e);
		}
	}

	private String removeTrailingSlash(String s) {
		return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
	}

	@GET
	@Path("{fragment:.+}")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response apiRoot(@PathParam("fragment") String fragment) {
		try {
			return EndpointUtils.builder(taxii.apiRoot(removeTrailingSlash(fragment))).build();
		} catch (WebApplicationException e) {
			return EndpointUtils.error(e);
		} catch (Exception e) {
			return EndpointUtils.error(e);
		}
	}

	@GET
	@Path("{fragment:.+}/collections")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response collections(@PathParam("fragment") String fragment) {
		try {
			return EndpointUtils.builder(taxii.collections(fragment)).build();
		} catch (WebApplicationException e) {
			return EndpointUtils.error(e);
		} catch (Exception e) {
			return EndpointUtils.error(e);
		}
	}

	@GET
	@Path("{fragment:.+}/collections/{cId:(.{8}-.{4}-.{4}-.{4}-.{12})}/")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response collection(@PathParam("fragment") String fragment, @PathParam("cId") String cId) {
		try {
			return EndpointUtils.builder(taxii.collection(fragment, removeTrailingSlash(cId))).build();
		} catch (WebApplicationException e) {
			return EndpointUtils.error(e);
		} catch (Exception e) {
			return EndpointUtils.error(e);
		}
	}

	@GET
	@Path("{fragment:(.+/collections/)?}{cId:(.+/)?}manifest")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response manifest(@PathParam("fragment") String fragment, @PathParam("cId") String cId) {
		fragment = fragment(fragment);
		cId = cId(cId);
		try {
			ManifestResponse manifestResponse = taxii.manifest(fragment, cId,
					new Filters(uriInfo.getQueryParameters()));
			return EndpointUtils.flBuilder(manifestResponse).build();
		} catch (WebApplicationException e) {
			return EndpointUtils.error(e);
		} catch (Exception e) {
			return EndpointUtils.error(e);
		}
	}

	@GET
	@Path("{fragment:(.+/collections/)?}{cId:(.+/)?}objects/{oId}/versions")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response versions(@PathParam("fragment") String fragment, @PathParam("cId") String cId,
			@PathParam("oId") String oId) {
		fragment = fragment(fragment);
		cId = cId(cId);
		try {
			VersionsResponse versionsResponse = taxii.versions(fragment, cId, oId,
					new Filters(uriInfo.getQueryParameters()));
			return EndpointUtils.flBuilder(versionsResponse).build();
		} catch (WebApplicationException e) {
			return EndpointUtils.error(e);
		} catch (Exception e) {
			return EndpointUtils.error(e);
		}
	}

	@GET
	@Path("{fragment:(.+/collections/)?}{cId:(.+/)?}objects")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response objects(@PathParam("fragment") String fragment, @PathParam("cId") String cId) {
		fragment = fragment(fragment);
		cId = cId(cId);
		try {
			EnvelopeResponse objectsResponse = taxii.objects(fragment, cId, new Filters(uriInfo.getQueryParameters()));
			return EndpointUtils.flBuilder(objectsResponse).build();
		} catch (WebApplicationException e) {
			return EndpointUtils.error(e);
		} catch (Exception e) {
			return EndpointUtils.error(e);
		}
	}

	@GET
	@Path("{fragment:(.+/collections/)?}{cId:(.+/)?}objects/{oId}")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response objects1(@PathParam("fragment") String fragment, @PathParam("cId") String cId,
			@PathParam("oId") String oId) {
		fragment = fragment(fragment);
		cId = cId(cId);
		try {
			EnvelopeResponse objects1Response = taxii.objects(fragment, cId,
					new Filters(uriInfo.getQueryParameters()).setId(true, removeTrailingSlash(oId)));
			if (objects1Response.ok != null && objects1Response.ok.getFirst() == null) {
				throw new NotFoundException(String.format("Object %s not found", oId));
			}
			return EndpointUtils.flBuilder(objects1Response).build();
		} catch (WebApplicationException e) {
			return EndpointUtils.error(e);
		} catch (Exception e) {
			return EndpointUtils.error(e);
		}
	}

	@GET
	@Path("{fragment:.+}/status/{id}")
	@Produces(CTIMediaType.TAXII2_1)
	@Logged
	public Response status(@PathParam("fragment") String fragment, @PathParam("id") String id) {
		try {
			return EndpointUtils.builder(taxii.status(fragment, removeTrailingSlash(id))).build();
		} catch (WebApplicationException e) {
			return EndpointUtils.error(e);
		} catch (Exception e) {
			return EndpointUtils.error(e);
		}
	}

	@POST
	@Path("{fragment:.+}/collections/{cId}/objects")
	@Consumes(CTIMediaType.TAXII2_1)
	@Logged
	public Response postObjects(@PathParam("fragment") String fragment, @PathParam("cId") String cId, String envelope) {
		try {
			ApiRootResponse arr = taxii.apiRoot(fragment);
			if (arr.error != null) {
				return EndpointUtils.builder(Response.Status.NOT_FOUND, arr).build();
			}
			long max_content_length = arr.ok.getMax_content_length();
			if (envelope.length() > max_content_length) {
				Response.Status status = Response.Status.REQUEST_ENTITY_TOO_LARGE;
				return EndpointUtils
						.builder(status,
								new StatusResponse(new Error(String.format(
										"POST objects payload size %d > api root %s max_content_length %d",
										envelope.length(), fragment, max_content_length), status)))
						.build();
			}
			StatusResponse response = taxii.postObjects(fragment, cId, Envelope.create(JSON.readTree(envelope)));
			if (response.ok != null) {
				return EndpointUtils.builder(Response.Status.ACCEPTED, response).build();
			}
			return EndpointUtils.builder(response).build();
		} catch (WebApplicationException e) {
			return EndpointUtils.error(e);
		} catch (Exception e) {
			return EndpointUtils.error(e);
		}
	}

	@DELETE
	@Path("{fragment:.+}/collections/{cId}/objects/{oId}")
	@Logged
	public Response deleteObjects(@PathParam("fragment") String fragment, @PathParam("cId") String cId,
			@PathParam("oId") String oId) {
		try {
			taxii.deleteObjects(fragment, cId, removeTrailingSlash(oId), new Filters(uriInfo.getQueryParameters()));
			return Response.ok().build();
		} catch (WebApplicationException e) {
			return EndpointUtils.error(e);
		} catch (Exception e) {
			return EndpointUtils.error(e);
		}
	}

//	@DELETE
//	@Path("{fragment:.+}/collections/{cId}/objects")
//	@Logged
//	public Response deleteObjects(@PathParam("fragment") String fragment, @PathParam("cId") String cId) {
//		try {
//			taxii.deleteObjects(fragment, cId, null, new Filters(uriInfo.getQueryParameters()));
//			return Response.ok().build();
//		} catch (WebApplicationException e) {
//			return EndpointUtils.error(e);
//		} catch (Exception e) {
//			return EndpointUtils.error(e);
//		}
//	}

	private String fragment(String fragment) {
		return ((fragment != null) && !fragment.isBlank())
				? fragment.substring(0, fragment.lastIndexOf("/collections/"))
				: null;
	}

	private String cId(String cId) {
		return ((cId != null) && !cId.isBlank()) ? cId.substring(0, cId.lastIndexOf("/")) : null;
	}
}
