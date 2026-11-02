/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.mount;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.cisa.taxii4j2.client.TAXIIClient;
import com.cisa.taxii4j2.mount.TAXIIMount.MountInfo;
import com.cisa.taxii4j2.servlet.Logged;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Path("taxii")
public class TAXIIMountEndpoint {

	private final TAXIIMount config;

	@Inject
	public TAXIIMountEndpoint(TAXIIMount config) {
		super();
		this.config = config;
	}

	@DELETE
	@Path("mount/{mountPoint}")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public MountInfo unmount(@PathParam("mountPoint") String mountPoint) {
		Map.Entry<String, TAXIIClient> entry = config.unmount(mountPoint);
		return (entry != null) ? new MountInfo(entry) : null;
	}

	@POST
	@Path("mount")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public MountInfo mount(MountInfo mountInfo) {
		Map.Entry<String, TAXIIClient> entry = config.mount(mountInfo);
		return (entry != null) ? new MountInfo(entry) : null;
	}

	@GET
	@Path("mounts")
	@Produces(MediaType.APPLICATION_JSON)
	@Logged
	public Set<MountInfo> mounts() {
		return config.mounts().stream().map(m -> new MountInfo(m)).collect(Collectors.toSet());
	}

}
