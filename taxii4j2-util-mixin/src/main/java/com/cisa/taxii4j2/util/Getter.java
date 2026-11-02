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
import java.util.function.Consumer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.cisa.taxii4j2.client.TAXIIClient;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.method.response.EnvelopeResponse;

public abstract class Getter implements AutoCloseable, Consumer<Envelope> {

	private final TAXIIClient client;
	private final String fragment;
	private final String cId;
	protected final Filters filters;

	protected Getter(String[] args) throws IOException {
		super();
		client = TAXIIClient.factory(args[0]);
		fragment = args[1];
		cId = args[2];
		filters = filters(args);
	}

	protected static Filters filters(String[] args) {
		return filters((args.length > 4) ? args[4] : null);
	}

	protected static Filters filters(String qps) {
		return filters(new Filters(qps));
	}

	protected static Filters filters(Filters filters) {
		if (filters == null) {
			filters = new Filters();
		}
		filters.setLimit(filters.getLimit());
		if (filters.get(Filters.versionKey) == null) {
			filters.setVersion(true, Filters.allKey);
		}
		return filters;
	}

	protected static Logger logger = LogManager.getLogger(Getter.class);

	public void run() throws InterruptedException {
		client.setReadTimeout(300000);
		while (true) {
			int retriesLeft = 3;
			long millis = 8000;
			Envelope envelope = null;
			while (--retriesLeft >= 0) {
				EnvelopeResponse response = client.objects(fragment, cId, filters);
				envelope = response.ok;
				if (envelope != null) {
					break;
				}
				Error error = response.error;
				if (error != null) {
					logger.info(error.toString());
				} else {
					logger.fatal("response error was null!!!");
				}
				Thread.sleep(millis);
				millis <<= 1;
			}
			if (envelope == null) {
				logger.fatal(String.format("failed: %s", filters));
				System.exit(-1);
			}
			accept(envelope);
			if (!envelope.getMore()) {
				break;
			}
			filters.setAdded_after(envelope.getLast());
		}
	}

	protected void error(Exception e) {
		System.err.println(e.getMessage());
		try (InputStream in = ClassLoader.getSystemResourceAsStream("exportUsage.txt")) {
			System.err.println(new String(in.readAllBytes()));
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		System.exit(-1);
	}

	@Override
	public void close() throws Exception {
		client.close();
	}

}
