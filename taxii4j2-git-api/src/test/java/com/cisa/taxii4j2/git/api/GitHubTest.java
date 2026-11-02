/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.api;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;

import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.git.api.GitHub.Handler;
import com.cisa.taxii4j2.git.api.GitHub.Info;

public class GitHubTest {

	private static final Logger logger = LogManager.getLogger(GitHub.class);

	@Test
	public void test() {
		try {
			final URI uri = ClassLoader.getSystemResource("infos").toURI();
			if (!uri.getScheme().equals("file")) {
				try {
					FileSystems.newFileSystem(uri, Map.of("create", "true"));
				} catch (FileSystemAlreadyExistsException e) {
					logger.warn(String.format("%s: already exists", uri));
				}
			}
			Handler handler = new Handler() {

				@Override
				public void delete(Path path) throws Exception {
					logger.debug(String.format("delete(%s)", path));
				}

				@Override
				public String getSha(Path path) throws IOException {
					String sha = null;
					logger.debug(String.format("getSha(%s) = %s", path, sha));
					return sha;
				}

				@Override
				public void putSha(Path path, String sha) throws IOException {
					logger.debug(String.format("putSha(%s, %s)", path, sha));
				}

				@Override
				public void accept(Path path, String content, String sha) throws IOException {
					logger.debug(String.format("accept(%s, %d)", path, content.length()));
					putSha(path, sha);
				}

				@Override
				public void link(Path link, Path target) throws Exception {
					logger.debug(String.format("link(%s, %s)", link, target));
				}

			};
			Files.walkFileTree(Paths.get(uri), new SimpleFileVisitor<Path>() {

				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
					try (InputStream in = Files.newInputStream(file)) {
						Info info = JSON.readValue(new InputStreamReader(in), Info.class);
						GitHub.accept(info, handler);
					} catch (Exception e) {
						throw new IOException(e);
					}
					return FileVisitResult.CONTINUE;
				}

			});
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

}
