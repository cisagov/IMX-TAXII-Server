/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client;

import java.io.IOException;
import java.io.Reader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.glassfish.jersey.client.ClientProperties;

import com.cisa.cti4j2.CTIMediaType;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.data.Collections.Collection;
import com.cisa.taxii4j2.data.Discovery;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.data.Manifest;
import com.cisa.taxii4j2.data.Versions;
import com.cisa.taxii4j2.method.TAXII;
import com.cisa.taxii4j2.method.latency.EndpointHealth;
import com.cisa.taxii4j2.method.latency.Health;
import com.cisa.taxii4j2.method.latency.LSConsumer;
import com.cisa.taxii4j2.method.latency.LatencySample;
import com.cisa.taxii4j2.method.latency.RootHealth;
import com.cisa.taxii4j2.method.response.ApiRootResponse;
import com.cisa.taxii4j2.method.response.CollectionResponse;
import com.cisa.taxii4j2.method.response.CollectionsResponse;
import com.cisa.taxii4j2.method.response.DiscoveryResponse;
import com.cisa.taxii4j2.method.response.EnvelopeResponse;
import com.cisa.taxii4j2.method.response.ManifestResponse;
import com.cisa.taxii4j2.method.response.StatusResponse;
import com.cisa.taxii4j2.method.response.TAXIIResponse;
import com.cisa.taxii4j2.method.response.VersionsResponse;

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

public class TAXIIClient implements TAXII {

	private static final String urlKey = "CLIENT_URL";
	private static final String usernameKey = "CLIENT_USERNAME";
	private static final String pkcs10Key = "CLIENT_PKCS10";
	private static final String pkcs12Key = "CLIENT_PKCS12";
	private static final String passwordKey = "CLIENT_PASSWORD";
	private static final String providerKey = "CLIENT_PROVIDER";
	private static final String proxy_uriKey = "CLIENT_PROXY_URI";

	private static final Map<RemoteInfo, TAXIIClient> byInfo = new TreeMap<>();
	private static final Map<RemoteInfo, TAXIIClient> byUuid = new TreeMap<>(
			(a, b) -> a.getUuid().compareTo(b.getUuid()));
	private static final Lock lock = new ReentrantLock();

	public static TAXIIClient instance(RemoteInfo info) {
		try {
			lock.lock();
			return byInfo.get(info);
		} finally {
			lock.unlock();
		}
	}

	public static TAXIIClient instance(UUID uuid) {
		try {
			lock.lock();
			return byUuid.get(new RemoteInfo.Key(uuid));
		} finally {
			lock.unlock();
		}
	}

	public static TAXIIClient instance() {
		try {
			lock.lock();
			if (byUuid.size() != 1) {
				logger.warn("this may not be the client you're looking for...");
			}
			return byUuid.isEmpty() ? null : byUuid.values().iterator().next();
		} finally {
			lock.unlock();
		}
	}

	private EndpointHealth endpointHealth(List<LatencySample> samples, String label) {
		return EndpointHealth.create(samples.stream().filter(s -> s.getLabel().equals(label)));
	}

	public Health getHealth(Instant end, Duration duration) {
		List<LatencySample> samples = sampleConsumer.read(end, duration);
		EndpointHealth taxii2 = endpointHealth(samples, taxii2Label);
		List<RootHealth> roots = new ArrayList<>();
		if (taxii2 != null) {
			for (Map.Entry<String, Set<String>> entry : knownRoots.entrySet()) {
				EndpointHealth collections = endpointHealth(samples, entry.getKey());
				if (collections != null) {
					List<EndpointHealth> objects = new ArrayList<>();
					for (String object : entry.getValue()) {
						EndpointHealth oeh = endpointHealth(samples, object);
						if (oeh != null) {
							objects.add(oeh);
						}
					}
					roots.add(new RootHealth(collections, objects));
				}
			}
		}
		return new Health(new Timestamp(end), taxii2, roots);
	}

	public int getConnectTimeout() {
		return connectTimeout.get();
	}

	public int setConnectTimeout(int timeout) {
		return setConnectTimeout(timeout, true);
	}

	public int setConnectTimeout(int timeout, boolean canReduce) {
		return setTimeout(this.connectTimeout, timeout, canReduce);
	}

	private static int setTimeout(AtomicInteger member, int timeout, boolean canReduce) {
		int prev, next;
		do {
			prev = member.get();
			next = canReduce ? timeout : Math.max(timeout, prev);
		} while (!member.compareAndSet(prev, next));
		return next;
	}

	public int getReadTimeout() {
		return readTimeout.get();
	}

	public int setReadTimeout(int timeout) {
		return setReadTimeout(timeout, true);
	}

	public int setReadTimeout(int timeout, boolean canReduce) {
		return setTimeout(this.readTimeout, timeout, canReduce);
	}

	public RemoteInfo getInfo() {
		return info;
	}

	public static Set<RemoteInfo> list() {
		try {
			lock.lock();
			return byUuid.keySet();
		} finally {
			lock.unlock();
		}
	}

	@Override
	public void close() throws IOException {
		try {
			lock.lock();
			byInfo.remove(info);
			byUuid.remove(info);
		} finally {
			lock.unlock();
		}
		if (exec != null) {
			exec.shutdownNow();
		}
		try {
			client.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		TAXII.super.close();
	}

	public static class Factory implements org.glassfish.hk2.api.Factory<TAXIIClient> {

		@Override
		public TAXIIClient provide() {
			RemoteInfo info = RemoteInfo.factory(null, System.getenv(urlKey), null, System.getenv(proxy_uriKey),
					System.getenv(usernameKey), System.getenv(passwordKey), System.getenv(pkcs10Key),
					System.getenv(providerKey), System.getenv(pkcs12Key));
			return factory(info);
		}

		@Override
		public void dispose(TAXIIClient instance) {

		}

	}

	private final RemoteInfo info;

	public static TAXIIClient factory(String path) throws IOException {
		return factory(path, defaultEstimateLatency);
	}

	public static TAXIIClient factory(String path, boolean estimateLatency) throws IOException {
		return factory(Paths.get(path), estimateLatency);
	}

	public static TAXIIClient factory(Path path) throws IOException {
		return factory(path, defaultEstimateLatency);
	}

	public static TAXIIClient factory(Path path, boolean estimateLatency) throws IOException {
		try (Reader inInfo = Files.newBufferedReader(path)) {
			RemoteInfo info = JSON.readValue(inInfo, RemoteInfo.class);
			return factory(info, estimateLatency);
		}
	}

	public static TAXIIClient factory(RemoteInfo info) {
		return factory(info, defaultEstimateLatency);
	}

	public static TAXIIClient factory(RemoteInfo info, boolean estimateLatency) {
		try {
			lock.lock();
			logger.debug(String.format("TAXIIClient.factory(%s)", info));
			TAXIIClient client = byInfo.get(info);
			logger.debug(String.format("TAXIIClient.factory: client = %s", client));
			return (client != null) ? client : new TAXIIClient(info, estimateLatency);
		} finally {
			lock.unlock();
		}
	}

	private TAXIIClient(RemoteInfo info, boolean estimateLatency) {
		super();

		logger.debug("existing clients...");
		byInfo.keySet().forEach(k -> {
			logger.debug(String.format("\t%2d %s", info.compareTo(k), k));
		});

		if (byInfo.containsKey(info)) {
			throw new IllegalArgumentException();
		}

		this.info = info;

		byInfo.put(info, this);
		byUuid.put(info, this);

		client = new RemoteBearerBase(info, CTIMediaType.TAXII2_1, CTIMediaType.TAXII2_1);
		URL url = info.getUrl();
		taxii2Label = url.toString();

		if (estimateLatency) {

			exec = Executors.newSingleThreadScheduledExecutor();

			Runtime.getRuntime().addShutdownHook(new Thread() {
				@Override
				public void run() {
					if (exec != null) {
						exec.shutdownNow();
					}
				}
			});

			sampleConsumer = LSConsumer.getService();
			if (sampleConsumer == null) {
				return;
			}

			Properties properties = new Properties();
			properties.setProperty(LSConsumer.NAME, String.format("%s-latency-samples", info.getUuid())); // url.getHost()));
			sampleConsumer.configure(properties);

			exec.scheduleWithFixedDelay(new Runnable() {
				@Override
				public void run() {
					@SuppressWarnings("resource")
					TAXIIClient client = TAXIIClient.this;
					URI baseUri = null;
					try {
						baseUri = url.toURI();
					} catch (URISyntaxException e) {
						/*
						 * can't happen
						 */
					}
					final int connectTimeout = client.connectTimeout.get();
					final int readTimeout = client.readTimeout.get();
					LatencySample sample = new LatencySample(connectTimeout, readTimeout, taxii2Label);
					DiscoveryResponse dr = client.time((c) -> c.discover(null, connectTimeout, readTimeout), sample);
					if (dr.error != null) {
						return;
					}
					List<String> roots = dr.ok.getApi_roots();
					if (roots == null) {
						return;
					}
					for (String uri : roots) {
						String fragment = removeTrailingSlash(baseUri.relativize(URI.create(uri)).toString());
						Set<String> knownCIds = knownRoots.computeIfAbsent(fragment, k -> new HashSet<>());
						sample = new LatencySample(connectTimeout, readTimeout, fragment);
						CollectionsResponse csr = client
								.time((c) -> c.collections(fragment, connectTimeout, readTimeout), sample);
						if (csr.error != null) {
							continue;
						}
						List<Collection> collections = csr.ok.collections;
						if (collections == null) {
							continue;
						}
						for (Collection collection : collections) {
							if (!collection.isCan_read()) {
								continue;
							}
							String cId = collection.getId();
							knownCIds.add(cId);
							sample = new LatencySample(connectTimeout, readTimeout, cId);
							client.time((c) -> c.objects(fragment, cId, new Filters().setLimit(1), connectTimeout,
									readTimeout), sample);
						}
					}
				}
			}, 1, delay, unit);

		}
	}

	private static final boolean defaultEstimateLatency = true;

	private final RemoteBearerBase client;
	private LSConsumer sampleConsumer;
	private final String taxii2Label;
	private final Map<String, Set<String>> knownRoots = new HashMap<>();

	private ScheduledExecutorService exec;

	private static final long delay = 5;
	private static final TimeUnit unit = TimeUnit.MINUTES;
	private final AtomicInteger connectTimeout = new AtomicInteger(10 * 1000); // ten seconds
	private final AtomicInteger readTimeout = new AtomicInteger(1 * 60 * 1000); // one minute

	private static final String collections = "collections";
	private static final String manifest = "manifest/";
	private static final String versions = "versions/";
	private static final String objects = "objects";
	private static final String status = "status";
	private static final String taxii2 = "taxii2/";

	private <T extends TAXIIResponse<?>> T time(Function<TAXIIClient, T> command, LatencySample sample) {
		Instant then = Instant.now();
		T t = command.apply(this);
		sample.set(new Timestamp(then), (int) Duration.between(then, Instant.now()).toMillis(),
				(t.error != null) ? t.error.getHttp_status() : null);
		sampleConsumer.accept(sample);
		return t;
	}

	private static String addTrailingSlash(String s) {
		return s.endsWith("/") ? s : (s + "/");
	}

	private static String removeTrailingSlash(String s) {
		return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
	}

	private Invocation.Builder builder(Integer connectTimeout, Integer readTimeout, MultivaluedMap<String, String> qps,
			String... paths) {
		Invocation.Builder builder = client.paths(qps, paths);
		builder.property(ClientProperties.CONNECT_TIMEOUT,
				(connectTimeout != null) ? connectTimeout.intValue() : this.connectTimeout.get());
		builder.property(ClientProperties.READ_TIMEOUT,
				(readTimeout != null) ? readTimeout.intValue() : this.readTimeout.get());
		return builder;
	}

	private Response getHelper(Integer connectTimeout, Integer readTimeout, MultivaluedMap<String, String> qps,
			String... paths) {
		return builder(connectTimeout, readTimeout, qps, paths).get();
	}

	private <T> T getHelper(Integer connectTimeout, Integer readTimeout, Class<T> clazz,
			MultivaluedMap<String, String> qps, String... paths) {
		return builder(connectTimeout, readTimeout, qps, paths).get().readEntity(clazz);
	}

	private <T> T postHelper(Integer connectTimeout, Integer readTimeout, Class<T> clazz, Object entity,
			MultivaluedMap<String, String> qps, String... paths) {
		return builder(connectTimeout, readTimeout, qps, paths).post(Entity.entity(entity, client.consumes))
				.readEntity(clazz);
	}

	@Override
	public DiscoveryResponse discover(URI baseUri) {
		return discover(baseUri, null, null);
	}

	public DiscoveryResponse discover(URI baseUri, Integer connectTimeout, Integer readTimeout) {
		DiscoveryResponse response = DiscoveryResponse
				.valueOf(getHelper(connectTimeout, readTimeout, String.class, null, taxii2));
		Discovery src = response.ok;
		if ((src != null) && (baseUri != null)) {
			List<String> roots = src.getApi_roots();
			if (roots != null) {
				URI remote = client.target().getUri();
				roots = roots.stream().map(r -> {
					URI path = remote.relativize(URI.create(r));
					return baseUri.resolve(path).toString();
				}).collect(Collectors.toList());
				response = new DiscoveryResponse(null, new Discovery(src, roots));
			}
		}
		return response;
	}

	@Override
	public ApiRootResponse apiRoot(String fragment) {
		return apiRoot(fragment, null, null);
	}

	public ApiRootResponse apiRoot(String fragment, Integer connectTimeout, Integer readTimeout) {
		required(fragment);
		return ApiRootResponse
				.valueOf(getHelper(connectTimeout, readTimeout, String.class, null, addTrailingSlash(fragment)));
	}

	@Override
	public CollectionsResponse collections(String fragment) {
		return collections(fragment, null, null);
	}

	public CollectionsResponse collections(String fragment, Integer connectTimeout, Integer readTimeout) {
		required(fragment);
		return CollectionsResponse.valueOf(
				getHelper(connectTimeout, readTimeout, String.class, null, fragment, addTrailingSlash(collections)));
	}

	@Override
	public CollectionResponse collection(String fragment, String cId) {
		return collection(fragment, cId, null, null);
	}

	public CollectionResponse collection(String fragment, String cId, Integer connectTimeout, Integer readTimeout) {
		required(fragment, cId);
		return CollectionResponse.valueOf(getHelper(connectTimeout, readTimeout, String.class, null, fragment,
				collections, addTrailingSlash(cId)));
	}

	@Override
	public ManifestResponse manifest(String fragment, String cId, Filters filters) {
		return manifest(fragment, cId, filters, null, null);
	}

	public ManifestResponse manifest(String fragment, String cId, Filters filters, Integer connectTimeout,
			Integer readTimeout) {
		required(fragment, cId);
		Response response = getHelper(connectTimeout, readTimeout, filters.getQps(), fragment, collections, cId,
				manifest);
		String json = response.readEntity(String.class);
		ManifestResponse manifest = ManifestResponse.valueOf(json);
		Manifest ok = manifest.ok;
		if (ok != null) {
			ok.setFirstLast(response);
		}
		return manifest;
	}

	@Override
	public VersionsResponse versions(String fragment, String cId, String oId, Filters filters) {
		return versions(fragment, cId, oId, filters, null, null);
	}

	public VersionsResponse versions(String fragment, String cId, String oId, Filters filters, Integer connectTimeout,
			Integer readTimeout) {
		required(fragment, cId);
		Response response = getHelper(connectTimeout, readTimeout, filters.getQps(), fragment, collections, cId,
				objects, oId, versions);
		VersionsResponse versions = VersionsResponse.valueOf(response.readEntity(String.class));
		Versions ok = versions.ok;
		if (ok != null) {
			ok.setFirstLast(response);
		}
		return versions;
	}

	@Override
	public EnvelopeResponse objects(String fragment, String cId, Filters filters) {
		return objects(fragment, cId, filters, null, null);
	}

	public EnvelopeResponse objects(String fragment, String cId, Filters filters, Integer connectTimeout,
			Integer readTimeout) {
		required(fragment, cId);
		Response response = getHelper(connectTimeout, readTimeout, filters.getQps(), fragment, collections, cId,
				addTrailingSlash(objects));
		String json = response.readEntity(String.class);
//		System.err.println(json);
		EnvelopeResponse envelope = EnvelopeResponse.valueOf(json);
		Envelope ok = envelope.ok;
		if (ok != null) {
			ok.setFirstLast(response);
		}
		return envelope;
	}

	@Override
	public StatusResponse status(String fragment, String id) {
		return status(fragment, id, null, null);
	}

	public StatusResponse status(String fragment, String id, Integer connectTimeout, Integer readTimeout) {
		return StatusResponse.valueOf(
				getHelper(connectTimeout, readTimeout, String.class, null, fragment, status, addTrailingSlash(id)));
	}

	@Override
	public StatusResponse postObjects(String fragment, String cId, Envelope envelope) {
		return postObjects(fragment, cId, envelope, null, null);
	}

	public StatusResponse postObjects(String fragment, String cId, Envelope envelope, Integer connectTimeout,
			Integer readTimeout) {
		required(fragment, cId);
		return StatusResponse.valueOf(postHelper(connectTimeout, readTimeout, String.class, envelope, null, fragment,
				collections, cId, addTrailingSlash(objects)));
	}

	@Override
	public void deleteObjects(String fragment, String cId, String oId, Filters filters) {
		deleteObjects(fragment, cId, oId, filters, null, null);
	}

	public void deleteObjects(String fragment, String cId, String oId, Filters filters, Integer connectTimeout,
			Integer readTimeout) {
		required(fragment, cId);
		builder(connectTimeout, readTimeout, filters.getQps(), fragment, collections, cId, objects,
				addTrailingSlash(oId)).delete();
	}

}
