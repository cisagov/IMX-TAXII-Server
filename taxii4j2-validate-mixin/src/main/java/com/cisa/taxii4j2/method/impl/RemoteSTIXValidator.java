/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;

import org.apache.logging.log4j.Level;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.cisa.cti4j2.CTIMediaType;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.archive.DirImporter;
import com.cisa.taxii4j2.client.RemoteBase;
import com.cisa.taxii4j2.data.impl.PropsHosts;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.data.impl.TAXIIConfig;
import com.cisa.taxii4j2.git.api.GitHub;
import com.cisa.taxii4j2.git.api.GitHub.Handler;
import com.cisa.taxii4j2.git.api.GitHub.Info;
import com.cisa.taxii4j2.method.STIXValidator;
import com.cisa.taxii4j2.servlet.Dirs;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.core.MediaType;

@Singleton
public class RemoteSTIXValidator extends RemoteBase implements STIXValidator {

	private final Handler handler = new Handler() {

		private final Path schemaDir = Dirs.instance().schema();

		private Path parent(Path path) throws IOException {
			Path parent = path.getParent();
			parent = (parent != null) ? schemaDir.resolve(path.getParent()) : schemaDir;
			Files.createDirectories(parent);
			return parent;
		}

		@Override
		public String getSha(Path path) throws IOException {
			String sha = null;
			try {
				sha = Files.readString(parent(path).resolve(String.format(".%s", path.getFileName())));
			} catch (Exception e) {
				// NOP
			}
			logger.debug(String.format("getSha(%s) = %s", path, sha));
			return sha;
		}

		@Override
		public void putSha(Path path, String sha) throws IOException {
			Files.writeString(parent(path).resolve(String.format(".%s", path.getFileName())), sha);
			logger.debug(String.format("putSha(%s, %s)", path, sha));
		}

		@Override
		public void accept(Path path, String content, String sha) throws IOException {
			Files.writeString(parent(path).resolve(path.getFileName()), content);
			logger.debug(String.format("accept(%s, %d)", path, content.length()));
			putSha(path, sha);
		}

		@Override
		public void link(Path link, Path target) throws Exception {
			Path fsTarget = parent(target).resolve(target.getFileName());
			if (!Files.exists(fsTarget)) {
				throw new IOException(String.format("target %s doesn't exist...", fsTarget));
			}
			Path fsLink = parent(link).resolve(link.getFileName());
			Files.createSymbolicLink(fsLink, fsLink.getParent().relativize(fsTarget));
			logger.debug(String.format("link(%s, %s)", link, target));
		}

		@Override
		public void delete(Path path) throws Exception {
			Path parent = parent(path);
			Path dir = parent.resolve(path.getFileName());
			if (Files.exists(dir)) {
				Files.walkFileTree(dir, new SimpleFileVisitor<Path>() {

					@Override
					public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
						Files.deleteIfExists(dir);
						return FileVisitResult.CONTINUE;
					}

					@Override
					public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
						Files.deleteIfExists(file);
						return FileVisitResult.CONTINUE;
					}

				});
			}
			Files.deleteIfExists(parent.resolve(String.format(".%s", path.getFileName())));
			logger.debug(String.format("delete(%s)", path));
		}

	};

	@Override
	public void update() throws IOException {

		Path schemaDir = Dirs.instance().schema();

		new Thread() {

			@Override
			public void run() {
				List<String> files = TAXIIConfig.getSchemas();
				if (files != null) {
					for (String file : files) {
						Info info = null;
						try (InputStream in = TAXIIConfig.open(file)) {
							info = JSON.readValue(new InputStreamReader(in), Info.class);
							GitHub.accept(info, handler);
						} catch (Exception e) {
							logger.warn(e.getMessage());
							String repo = info.getRepo();
							try {
								if (handler.getSha(Paths.get(repo)) == null) {
									logger.debug(String.format("bootstrapping schema %s...", repo));
									DirImporter.factory(Dirs.instance().boostrap().resolve("schema")
											.resolve(String.format("%s.tgz", repo)), schemaDir);
								}
							} catch (Exception e1) {
								logger.log(Level.WARN, String.format("schema load fail on %s", repo), e1);
							}
						}
					}
				}
			}

		}.start();
	}

	@Inject
	public RemoteSTIXValidator() throws IOException {
		super(PropsHosts.instance().validator(), CTIMediaType.STIX, MediaType.APPLICATION_JSON, null);
		update();
	}

	private static final String objectKey = "object";
	private static final String optionsKey = "options";

	@Override
	public Result validate(STIXObject o, Options options) {
		ObjectNode payload = JSON.factory.objectNode();
		payload.set(objectKey, JSON.convertValue(o, JsonNode.class));
		payload.set(optionsKey, JSON.convertValue(options, JsonNode.class));
		return postHelper(payload, Result.class, null, "validate", o.getSpec_version().replaceFirst("\\.", ""));
	}

	@Override
	public int configure(Options config) {
		return postHelper(config, null, "configure").getStatus();
	}

}
