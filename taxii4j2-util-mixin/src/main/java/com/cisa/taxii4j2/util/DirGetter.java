/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.util;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.AbstractMap;
import java.util.Map;

import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.data.Envelope;

public class DirGetter extends Getter {

	public static void main(String[] args) {
		try (Getter getter = new DirGetter(args)) {
			getter.run();
		} catch (Exception e) {
			logger.fatal(e.getMessage());
		}
	}

	private final Path dir;
	private final MessageDigest hasher;

	private static class LastFinder extends SimpleFileVisitor<Path> {

		private Timestamp last = null;

		@Override
		public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
			try {
				Timestamp later = DirGetter.decode(file).getValue();
				if ((last == null) || (later.compareTo(last) > 0)) {
					last = later;
				}
			} catch (Exception e) {

			}
			return FileVisitResult.CONTINUE;
		}

	}

	private static final String separator = "<=>";

	private static String encode(Envelope envelope) {
		return String.format("%s%s%s", envelope.getFirst(), separator, envelope.getLast());
	}

	private static Map.Entry<Timestamp, Timestamp> decode(Path file) {
		String[] parts = file.getFileName().toString().split(separator);
		return new AbstractMap.SimpleImmutableEntry<Timestamp, Timestamp>(Timestamp.valueOf(parts[0]),
				Timestamp.valueOf(parts[1]));
	}

	public DirGetter(String[] args) throws IOException, NoSuchAlgorithmException {

		super(args);

		dir = Paths.get(args[3]);
		Files.createDirectories(dir);
		LastFinder finder = new LastFinder();
		Files.walkFileTree(dir, finder);
		Timestamp last = finder.last;
		if (last != null) {
			filters.setAdded_after(finder.last);
		}
		logger.info(String.format("starting at %s...", filters.getAdded_after()));

		hasher = MessageDigest.getInstance("SHA-256");

	}

	@Override
	public void accept(Envelope envelope) {
		try {
			String json = JSON.writeValueAsString(envelope);
			Path subDir = dir.resolve(Integer.toHexString(hasher.digest(json.getBytes())[0] & 0xf));
			Files.createDirectories(subDir);
			Path file = subDir.resolve(encode(envelope));
			Files.writeString(file, json);
			logger.info(file.toString());
		} catch (IOException e) {
			logger.fatal(e.getMessage());
		}
	}

}
