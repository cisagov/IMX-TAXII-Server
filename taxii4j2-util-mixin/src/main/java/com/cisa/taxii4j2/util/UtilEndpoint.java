/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.cisa.cti4j2.CTIMediaType;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.auth.method.BulkAdmin.Configuration;
import com.cisa.taxii4j2.auth.method.RootCollectionRead;
import com.cisa.taxii4j2.client.RemoteInfo;

import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.EntityPart;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.UriInfo;

@Path("ext/v1.0/util")
public class UtilEndpoint {

	private final RootCollectionRead rcr;

	private static final Logger logger = LogManager.getLogger(UtilEndpoint.class);

	@Inject
	public UtilEndpoint(RootCollectionRead rcr) {
		super();
		this.rcr = rcr;
	}

	@POST
	@Path("conf")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(CTIMediaType.TAXII2_1)
	public Configuration conf(RemoteInfo info) {
		try {
			return ConfExport.run(info);
		} catch (IOException | URISyntaxException e) {
			logger.error("Error in ext/v1.0/util/conf", e);
			throw new BadRequestException(e);
		}
	}

	@POST
	@Path("pconf")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(CTIMediaType.TAXII2_1)
	public Configuration pconf(RemoteInfo info) {
		try {
			return PConfExport.run(info);
		} catch (Exception e) {
			logger.error("Error in ext/v1.0/util/pconf", e);
			throw new BadRequestException(e);
		}
	}

	@Context
	private UriInfo uriInfo;

	@POST
	@Path("{fragment:.+}/collections/{cId}/export")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces("application/zip")
	public InputStream exporter(@PathParam("fragment") String fragment, @PathParam("cId") String cId, RemoteInfo info) {
		try {
			java.nio.file.Path infoPath = Files.createTempFile("info", ".json");
			Files.writeString(infoPath, JSON.writeValueAsString(info));
			java.nio.file.Path zipPath = Files.createTempFile("export", ".zip");
			String filterParameters = uriInfo.getQueryParameters().isEmpty() ? null : uriInfo.getRequestUri().getQuery();
			try (Getter getter = new ZipGetter(new String[] { infoPath.toString(), fragment,
					rcr.readCollection(cId).getId(), zipPath.toString(), filterParameters })) {
				getter.run();
			}
			return Files.newInputStream(zipPath);
		} catch (Exception e) {
			logger.error(String.format("Error in ext/v1.0/util/%s/collections/%s/export", fragment, cId), e);
			throw new BadRequestException(e);
		}
	}

	@POST
	@Path("{fragment:.+}/collections/{cId}/import")
	@Consumes(MediaType.MULTIPART_FORM_DATA)
	@Produces(MediaType.TEXT_PLAIN)
	public InputStream importer(@PathParam("fragment") String fragment, @PathParam("cId") String cId,
			@FormParam("info") String info, @FormParam("file") EntityPart file) {
		try {
			java.nio.file.Path infoPath = Files.createTempFile("info", ".json");
			Files.writeString(infoPath, info);
			java.nio.file.Path filePath = Files.createTempFile("import", ".zip");
			Files.copy(file.getContent(), filePath, StandardCopyOption.REPLACE_EXISTING);
			java.nio.file.Path errPath = Files.createTempFile("error", ".txt");
			try (ZipPoster importer = new ZipPoster(new String[] { infoPath.toString(), fragment,
					rcr.readCollection(cId).getId(), errPath.toString(), filePath.toString() })) {
				importer.run();
			}
			return Files.newInputStream(errPath);
		} catch (Exception e) {
			logger.error(String.format("Error in ext/v1.0/util/%s/collections/%s/import", fragment, cId), e);
			throw new BadRequestException(e);
		}
	}

	@POST
	@Path("{fragment:.+}/collections/{cId}/load")
	@Consumes(MediaType.MULTIPART_FORM_DATA)
	@Produces(MediaType.TEXT_PLAIN)
	public InputStream loader(@PathParam("fragment") String fragment, @PathParam("cId") String cId,
			@FormParam("info") String info, @FormParam("file") EntityPart file) {
		try {
			java.nio.file.Path infoPath = Files.createTempFile("info", ".json");
			try (Writer out = Files.newBufferedWriter(infoPath)) {
				out.write(info);
			}
			java.nio.file.Path filePath = Files.createTempFile("envelope", ".json");
			Files.copy(file.getContent(), filePath, StandardCopyOption.REPLACE_EXISTING);
			java.nio.file.Path errPath = Files.createTempFile("error", ".txt");
			try (DirPoster loader = new DirPoster(new String[] { infoPath.toString(), fragment,
					rcr.readCollection(cId).getId(), errPath.toString(), filePath.toString() })) {
				loader.run();
			}
			return Files.newInputStream(errPath);
		} catch (Exception e) {
			logger.error(String.format("Error in ext/v1.0/util/%s/collections/%s/load", fragment, cId), e);
			throw new BadRequestException(e);
		}
	}

}
