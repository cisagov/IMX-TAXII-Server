/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job.misp;

import static org.junit.Assert.fail;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.Ignore;
import org.junit.Test;

import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.client.job.ClientJob;
import com.cisa.taxii4j2.client.job.Configuration;
import com.cisa.taxii4j2.client.job.Snapshot;

public class MISPClientJobTest {

	@Ignore
	@Test
	public void snapshot() {
		System.err.print("\n\n\n");
		try (InputStream configIn = ClassLoader.getSystemResourceAsStream("misp-configuration.json");
				InputStream snapshotIn = ClassLoader.getSystemResourceAsStream("misp-snapshot.json");
				OutputStream out = Files.newOutputStream(Paths.get("./snapshot.txt"))) {
			Configuration configuration = JSON.readValue(new InputStreamReader(configIn), Configuration.class);
			System.err.println(configuration);
			MISPSnapshot snapshot = JSON.readValue(new InputStreamReader(snapshotIn), MISPSnapshot.class);
			System.err.println(snapshot);
			System.setOut(new PrintStream(out));
			try (ClientJob clientJob = new MISPClientJob(configuration, snapshot)) {
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
		try (InputStream in = ClassLoader.getSystemResourceAsStream("misp-configuration.json");
				OutputStream out = Files.newOutputStream(Paths.get("./entire.txt"));
				ClientJob clientJob = new MISPClientJob(
						JSON.readValue(new InputStreamReader(in), Configuration.class))) {

			Configuration configuration = clientJob.getConfiguration();
			String json = JSON.writeValueAsString(configuration);
			System.err.println(json);
			configuration = JSON.readValue(json, Configuration.class);
			System.err.println(configuration);

			System.setOut(new PrintStream(out));
			clientJob.start();
			Thread.yield();
			clientJob.stop();

			Snapshot snapshot = clientJob.getSnapshot();
			json = JSON.writeValueAsString(snapshot);
			System.err.println("-------------------------------------------------------------------");
			System.err.println(json);
			snapshot = JSON.readValue(json, MISPSnapshot.class);
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
