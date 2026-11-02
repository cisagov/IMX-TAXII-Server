/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job.taxii;

import static org.junit.Assert.fail;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.Ignore;
import org.junit.Test;

import com.cisa.cti4j2.CTIDuration;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.client.RemoteInfo;
import com.cisa.taxii4j2.client.job.ClientJob;
import com.cisa.taxii4j2.client.job.Configuration;
import com.cisa.taxii4j2.client.job.Snapshot;

public class TAXIIClientJobTest {

	/* Ignoring these tests until we work out a way to spin up a TAXII server with certs. */

	/*
	 * To set up for this test, load the user identified in server-91-pkcs12.json.
	 * Sample curl:
	 * curl -k --user "imx-admin:$TAXII_PASSWORD" -d @server-91-pkcs12.json -H 'Content-Type: application/json' https://localhost:9443/admin/v1.0/pkcs12/byo
	 *
	 * Note: all passwords used for the self signed cert are "password"
	 */

	@Ignore
	@Test
	public void snapshot() {
		System.err.print("\n\n\n");
		try (InputStream snapshotIn = ClassLoader.getSystemResourceAsStream("snapshot.json");
				InputStream authIn = ClassLoader.getSystemResourceAsStream("server-91-pkcs12-auth.json");
				OutputStream out = Files.newOutputStream(Paths.get("./snapshot.txt"))) {
			System.setOut(new PrintStream(out));
			Snapshot snapshot = JSON.readValue(new InputStreamReader(snapshotIn), TAXIISnapshot.class);
			System.err.println(snapshot);
			TAXIIConfiguration configuration = new TAXIIConfiguration(
					JSON.readValue(new InputStreamReader(authIn), RemoteInfo.class), "cti-stix-common-objects",
					"location", 7, CTIDuration.ofSeconds(10), null, null);
			try (ClientJob clientJob = new TAXIIClientJob(configuration, snapshot)) {
				System.err.println(clientJob.getSnapshot());
				clientJob.start();
				while (clientJob.isRunning()) {
					Thread.sleep(1000);
				}
				Thread.sleep(10000);
			}
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	@Ignore
	@Test
	public void test() {
		try (InputStream in = ClassLoader.getSystemResourceAsStream("server-91-pkcs12-auth.json");
				OutputStream out = Files.newOutputStream(Paths.get("./entire.txt"));
				ClientJob clientJob = new TAXIIClientJob(JSON.readValue(new InputStreamReader(in), RemoteInfo.class),
						"cti-stix-common-objects", "location", 7, CTIDuration.ofSeconds(10), null, null)) {

			Configuration configuration = clientJob.getConfiguration();
			String json = JSON.writeValueAsString(configuration);
			System.err.println(json);
			configuration = JSON.readValue(json, TAXIIConfiguration.class);
			System.err.println(configuration);

			System.setOut(new PrintStream(out));
			clientJob.start();
			Thread.sleep(1000);
			clientJob.stop();

			Snapshot snapshot = clientJob.getSnapshot();
			json = JSON.writeValueAsString(snapshot);
			System.err.println("-------------------------------------------------------------------");
			System.err.println(json);
			snapshot = JSON.readValue(json, TAXIISnapshot.class);
			System.err.println(snapshot);
			System.err.println("-------------------------------------------------------------------");

			clientJob.start();
			while (clientJob.isRunning()) {
				Thread.sleep(1000);
			}

			Thread.sleep(10000);

		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

}
