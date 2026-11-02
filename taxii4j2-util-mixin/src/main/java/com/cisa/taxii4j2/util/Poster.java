/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.util;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.client.TAXIIClient;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.data.Status;
import com.cisa.taxii4j2.data.impl.JSONSTIXObject;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.method.response.StatusResponse;

public class Poster implements Consumer<JsonNode>, AutoCloseable {

	private static final long sleep = 15 * 1000L;
	private static final long maxSleep = 5 * 60 * 1000L;

	private final TAXIIClient client;
	private final String fragment;
	private final String cId;

	private final PrintStream err;

	private final int mcl;

	private static final int nThreads = 4;
	private final ExecutorService exec = Executors.newFixedThreadPool(nThreads);

	private List<STIXObject> objects = new ArrayList<>();
	private int cl = 0;

	protected static final Logger logger = LogManager.getLogger(Poster.class);

	protected Poster(String[] args) throws IOException {
		this(args[0], args[1], args[2], new PrintStream(Files.newOutputStream(Paths.get(args[3]))));
	}

	protected Poster(String infoPath, String fragment, String cId, PrintStream err) throws IOException {
		super();
		this.client = TAXIIClient.factory(infoPath);
		this.err = err;
		this.fragment = fragment;
		this.cId = cId;
		mcl = Math.round(client.apiRoot(fragment).ok.getMax_content_length() * 0.8F);
	}

	@Override
	public void accept(JsonNode object) {
		try {
			if (object.isEmpty())
				return;

			int length = JSON.writeTreeAsString(object).length();
			if (length >= mcl) {
				err.println(String.format("individual object too big (%d >= %d) - skipping...", length, mcl));
				return;
			}
			if (cl + length >= mcl) {
				post();
			}
			objects.add(new JSONSTIXObject(object));
			cl += length;
		} catch (IOException e) {
			logger.error("Error in accept()", e);
			throw new IllegalArgumentException();
		}
	}

	protected void post() {

		if (objects.isEmpty()) {
			return;
		}

		Envelope envelope = new Envelope(objects);
		objects = new ArrayList<>();
		cl = 0;
		final StatusResponse sr = client.postObjects(fragment, cId, envelope);
		error(sr.error);
		System.out.println(String.format("posted %d as %s...", envelope.getObjects().size(), sr.ok.getId()));

		exec.submit(new Runnable() {

			private final String id = sr.ok.getId();
			private final long then = System.currentTimeMillis();

			@Override
			public void run() {
				System.out.println(String.format("watching %s...", id));
				while (true) {
					try {
						Thread.sleep(sleep);
					} catch (InterruptedException e) {
						err.println(e.getMessage());
						return;
					}
					StatusResponse sr = client.status(fragment, id);
					error(sr.error);
					Status ok = sr.ok;
					int pending_count = ok.getPending_count();
					if (pending_count == 0) {
						List<Status.Details> failures = ok.getFailures();
						if (failures != null) {
							failures.forEach(f -> err.println(f));
						}
						System.out.println(String.format("...%s complete (%d/%d)", id, ok.getSuccess_count(),
								ok.getFailure_count()));
						return;
					}
					System.out.println(String.format("...%s still has %d pending...", id, pending_count));
					if (System.currentTimeMillis() - then >= maxSleep) {
						err.println(ok);
						System.out.println(String.format("...%s timed out (%d still pending)", id, pending_count));
						return;
					}
				}
			}
		});
	}

	@Override
	public void close() throws Exception {
		exec.shutdown();
		while (!exec.awaitTermination(5, TimeUnit.SECONDS)) {
			System.out.println("tick...");
		}
		client.close();
		err.close();
	}

	private static void error(Error e) {
		if (e == null) {
			return;
		}
		System.err.println(e);
		System.exit(-1);
	}

	protected Iterator<JsonNode> iObject(JsonNode root) {
		if(root.isArray()) {
			return root.elements();
		}
		JsonNode objects = root.get("objects");
		if(objects != null) {
			return objects.elements();
		}
		return Collections.singleton(root).iterator();
	}

}
