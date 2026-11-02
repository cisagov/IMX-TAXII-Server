/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.archive;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;

public class DirImporter extends Importer {

	private final Path dst;

	public static void factory(Path src, Path dst) throws Exception {
		factory(Files.newInputStream(src), dst);
	}

	private DirImporter(Path src, Path dst) throws IOException {
		super(src);
		this.dst = dst;
	}

	private DirImporter(InputStream in, Path dst) throws IOException {
		super(in);
		this.dst = dst;
	}

	@Override
	public void accept(ArchiveEntry entry) {
		Path path = dst.resolve(entry.getName());
		Path parent = path.getParent();
		try {
			try {
				TarArchiveEntry tae = TarArchiveEntry.class.cast(entry);
				if(tae.isSymbolicLink()) {
					if(parent != null) {
						Files.createDirectories(parent);
					}
					Files.createSymbolicLink(path, Paths.get(tae.getLinkName()));
					return;
				}
			} catch(ClassCastException e) {

			}
			if (entry.isDirectory()) {
				Files.createDirectories(path);
			} else {
				if(parent != null) {
					Files.createDirectories(parent);
				}
				Files.copy(getaIn(), path);
			}
		} catch (IOException e) {
			logger.warn(String.format("%s: %s", e.getMessage(), path));
		}
	}

	public static void factory(InputStream in, Path dst) throws Exception {
		try (Importer importer = new DirImporter(in, dst)) {
			importer.run();
		}
	}
}
