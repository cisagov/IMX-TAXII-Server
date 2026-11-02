/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.archive;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.compress.compressors.CompressorException;
import org.apache.commons.compress.compressors.CompressorStreamFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Importer implements AutoCloseable, Consumer<ArchiveEntry> {

	protected static final Logger logger = LogManager.getLogger(Importer.class);

	private ArchiveInputStream<ArchiveEntry> aIn;

	public static void factory(Path path) throws Exception {
		factory(Files.newInputStream(path));
	}

	public static void factory(InputStream in) throws Exception {
		try (Importer importer = new Importer(in)) {
			importer.run();
		}
	}

	protected void run() throws IOException {
		aIn.forEach(c -> accept(c));
	}

	protected Importer(Path path) throws IOException {
		this(Files.newInputStream(path));
	}

	protected String type;

	protected Importer(InputStream in) throws IOException {
		try {
			in = CompressorStreamFactory.getSingleton().createCompressorInputStream(new BufferedInputStream(in));
		} catch (CompressorException e) {
			// not compressed?
		}
		try {
			in = new BufferedInputStream(in);
			type = ArchiveStreamFactory.detect(in);
			aIn = new ArchiveStreamFactory().createArchiveInputStream(type, in);
		} catch (ArchiveException e) {
			in.close();
		}
	}

	@Override
	public void close() throws Exception {
		if (aIn != null) {
			aIn.close();
			aIn = null;
		}
	}

	@Override
	public void accept(ArchiveEntry entry) {
		logger.debug(entry.getName());
	}

	public ArchiveInputStream<ArchiveEntry> getaIn() {
		return aIn;
	}

}
