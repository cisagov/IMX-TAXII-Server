/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import com.cisa.taxii4j2.data.Envelope;

public class ZipGetter extends Getter {

	private final ZipOutputStream out;
	private int i = 0;

	protected ZipGetter(String[] args) throws IOException {
		super(args);
		out = new ZipOutputStream(Files.newOutputStream(Paths.get(args[3])));
		for (int i = 0; i < 16; ++i) {
			out.putNextEntry(new ZipEntry(String.format("%X/", i)));
			out.closeEntry();
		}
	}

	@Override
	public void accept(Envelope t) {
		try {
			String name = String.format("%X/%04X.json", i & 0xf, i >> 4);
			out.putNextEntry(new ZipEntry(name));
			out.write(t.toString().getBytes());
			out.closeEntry();
			logger.info(name);
			++i;
		} catch (IOException e) {
			logger.fatal(e.getMessage());
		}
	}

	@Override
	public void close() throws Exception {
		out.finish();
		out.close();
		super.close();
	}

}
