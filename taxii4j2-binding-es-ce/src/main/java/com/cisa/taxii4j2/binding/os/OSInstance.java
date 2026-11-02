/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.binding.os;

import java.io.IOException;
import java.net.ConnectException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.CredentialsProvider;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.async.HttpAsyncClientBuilder;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.logging.log4j.Level;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.client.json.JsonData;
import org.opensearch.client.json.JsonpMapper;
import org.opensearch.client.json.JsonpUtils;
import org.opensearch.client.json.jackson.JacksonJsonpMapper;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.FieldValue;
import org.opensearch.client.opensearch._types.OpenSearchException;
import org.opensearch.client.opensearch._types.query_dsl.BoolQuery;
import org.opensearch.client.opensearch._types.query_dsl.QueryBuilders;
import org.opensearch.client.opensearch._types.query_dsl.TermQuery;
import org.opensearch.client.opensearch._types.query_dsl.RangeQuery;
import org.opensearch.client.opensearch.cat.SnapshotsResponse;
import org.opensearch.client.opensearch.core.GetResponse;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.snapshot.CreateRepositoryResponse;
import org.opensearch.client.opensearch.snapshot.CreateSnapshotResponse;
import org.opensearch.client.opensearch.snapshot.DeleteSnapshotResponse;
import org.opensearch.client.opensearch.snapshot.GetRepositoryResponse;
import org.opensearch.client.opensearch.snapshot.Repository;
import org.opensearch.client.opensearch.snapshot.RestoreSnapshotResponse;
import org.opensearch.client.opensearch.snapshot.SnapshotStatusResponse;
import org.opensearch.client.transport.OpenSearchTransport;
import org.opensearch.client.transport.rest_client.RestClientTransport;

import com.cisa.taxii4j2.data.impl.TAXIIConfig;
import com.cisa.taxii4j2.servlet.store.DbBase;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotFoundException;

@Singleton
public class OSInstance implements DbBase {

	private OpenSearchTransport transport;
	protected OpenSearchClient client;

	@Override
	public <T> T client(Class<T> clazz) {
		return clazz.cast(client);
	}

	private static final String keywordSuffix = ".keyword";

	@Override
	public String localizeIndexName(String index) {
		return legalizeIndexName(String.format("%s-%s", TAXIIConfig.taxii4j2UUID(), index));
	}

	@Override
	public String keyword(String property) {
		return !property.endsWith(keywordSuffix) ? property + keywordSuffix : property;
	}

	private final String prefix;

	@Inject
	public OSInstance() throws IOException {

		super();

		prefix = legalizeIndexName(TAXIIConfig.taxii4j2UUID());

		if (client != null) {
			return;
		}

		if (OSConfig.getPassword() == null) {
			logger.log(Level.FATAL, "Elasticsearch MUST have basic authentication!!!");
			System.exit(-1);
		}

		HttpHost host = new HttpHost(OSConfig.getScheme(), OSConfig.getHost(), OSConfig.getPort());

		final BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
		credentialsProvider.setCredentials(new AuthScope(host),
				new UsernamePasswordCredentials(OSConfig.getUsername(), OSConfig.getPassword().toCharArray()));

		final long maxSleep = 32000;
		long sleep = 1000;
		HttpGet request = new HttpGet(host.toURI());
		try (CloseableHttpClient tester = HttpClientBuilder.create().setDefaultCredentialsProvider(credentialsProvider)
				.build()) {
			while (true) {
				try (CloseableHttpResponse response = tester.execute(request)) {
					if (response.getCode() == HttpStatus.SC_OK) {
						break;
					}
				} catch (Exception e) {
					// falling through
				}
				logger.info(String.format("ES @ %s waiting %d ms...", host, sleep));
				try {
					Thread.sleep(sleep);
				} catch (InterruptedException e) {
					logger.log(Level.WARN, "ES.init", e);
				}
				sleep <<= 1;
				if (sleep > maxSleep) {
					String msg = String.format("Failed waiting for ES @ %s...", host);
					logger.log(Level.FATAL, msg);
					throw new ConnectException(msg);
				}
			}
		}

		RestClientBuilder builder = RestClient.builder(host);
		builder = builder.setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() {
			@Override
			public HttpAsyncClientBuilder customizeHttpClient(HttpAsyncClientBuilder httpClientBuilder) {
				return httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
			}
		});
		RestClient restClient = builder.build();
		transport = new RestClientTransport(restClient, new JacksonJsonpMapper());
		client = new OpenSearchClient(transport);

		/*
		 * snapshot repository
		 */

		GetRepositoryResponse grr = client.snapshot().getRepository();
		Map<String, Repository> repositories = grr.result();
		if ((repositories != null) && repositories.containsKey(repositoryName)) {
			logger.info(String.format("found snapshot repository %s", repositoryName));
		} else {
			CreateRepositoryResponse crr = client.snapshot().createRepository(
					r -> r.name(repositoryName).type("fs").settings(s -> s.location(repositoryLocation)));
			if (!crr.acknowledged()) {
				logger.fatal(String.format("failed to create snapshot repository %s @ %s", repositoryName,
						repositoryLocation));
			}
		}
	}

	private static final String repositoryName = "repository";
	private static final String repositoryLocation = "/opt/snapshots";

	private static final String illegal = "[^-a-z0-9_.]";
	private static final Matcher badStarts = Pattern.compile("^[-_+]+").matcher("");
	private static final String[] dots = { ".", ".." };

	@Override
	public String legalizeIndexName(String in) {
		if (Arrays.binarySearch(dots, in) >= 0) {
			return String.format("safe-%s", in);
		}
		String out = in.toLowerCase().replaceAll(illegal, "-");
		badStarts.reset(out);
		if (badStarts.find()) {
			out = "safe-" + out;
		}
		return out;
	}

	@Override
	public String createIndex(String name) {
		try {
			client.indices().get(i -> i.index(name));
		} catch (Exception e) {
			try {
				client.indices().create(c -> c.index(name));
			} catch (Exception e1) {
				logger.log(Level.FATAL, "ES.createIndex", e1);
			}
		}
		return name;
	}

	@Override
	public <T> T get(String id, String index, Class<T> clazz) {
		try {
			GetResponse<T> response = client.get(g -> g.index(index).id(id), clazz);
			if (!response.found()) {
				throw new NotFoundException(String.format("id \"%s\" not found in index \"%s\"", id, index));
			}
			return response.source();
		} catch (OpenSearchException e) {
			int status = e.status();
			if (status == HttpStatus.SC_NOT_FOUND) {
				throw new NotFoundException(String.format("index \"%s\" not found", index));
			}
			throw new ClientErrorException(status, e);
		} catch (IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public <T> Map<String, T> map(String index, Class<T> clazz, Integer size) {
		try {
			SearchResponse<T> response = client
					.search(s -> s.index(index).size((size != null) ? Math.min(size, maxSize) : maxSize), clazz);
			return response.hits().hits().stream().collect(Collectors.toMap(h -> h.id(), h -> h.source()));
		} catch (OpenSearchException e) {
			int status = e.status();
			if (status == HttpStatus.SC_NOT_FOUND) {
				throw new NotFoundException(String.format("index \"%s\" not found", index));
			}
			throw new ClientErrorException(status, e);
		} catch (IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public <T, C extends java.util.Collection<T>> C collect(String index, Class<T> clazz, Supplier<C> ts,
			Integer size) {
		try {
			SearchResponse<T> response = client
					.search(s -> s.index(index).size((size != null) ? Math.min(size, maxSize) : maxSize), clazz);
			return response.hits().hits().stream().map(h -> h.source()).collect(Collectors.toCollection(ts));
		} catch (OpenSearchException e) {
			int status = e.status();
			if (status == HttpStatus.SC_NOT_FOUND) {
//				throw new NotFoundException(String.format("index \"%s\" not found", index));
				return ts.get();
			}
			throw new ClientErrorException(status, e);
		} catch (IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public <T> T delete(String id, String index, Class<T> clazz) {
		T t = get(id, index, clazz);
		try {
			client.delete(d -> d.index(index).id(id));
		} catch (OpenSearchException e) {
			int status = e.status();
			if (status == HttpStatus.SC_NOT_FOUND) {
				throw new NotFoundException(String.format("index \"%s\" not found", index));
			}
			throw new ClientErrorException(status, e);
		} catch (IOException e) {
			throw new InternalServerErrorException(e);
		}
		return t;
	}

	@Override
	public <T> T put(T info, String index, String id, boolean create) {
		try {
			client.index(i -> i.index(index).id(id).document(info));
			return info;
		} catch (OpenSearchException e) {
			int status = e.status();
			if (status == HttpStatus.SC_NOT_FOUND) {
				throw new NotFoundException(String.format("index \"%s\" not found", index));
			}
			throw new ClientErrorException(status, e);
		} catch (IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public void refresh(String... index) {
		try {
			client.indices().refresh(r -> r.index(Arrays.asList(index)));
		} catch (OpenSearchException | IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public <T> List<T> search(Map<String, String> kvs, Class<T> clazz, int from, int _size,
			Collection<String> indices) {
		final int size = Integer.min(_size, maxSize);
		BoolQuery.Builder bool = new BoolQuery.Builder();
		for (Map.Entry<String, String> kv : kvs.entrySet()) {
			TermQuery conj = QueryBuilders.term().field(kv.getKey()).value(FieldValue.of(kv.getValue())).build();
			bool.must(conj.toQuery());
		}
		try {
			SearchResponse<T> response = client(OpenSearchClient.class).search(
					s -> s.index(new ArrayList<>(indices)).from(from).size(size).query(bool.build().toQuery()), clazz);
			return response.hits().hits().stream().map(h -> h.source()).collect(Collectors.toList());
		} catch (OpenSearchException e) {
			int status = e.status();
			if (status == HttpStatus.SC_NOT_FOUND) {
				return Collections.emptyList();
			}
			throw new ClientErrorException(status, e);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

	@Override
	public <T> List<T> searchWithRange(Map<String, String> kvs, Map<String, Pair<Integer, Integer>> ranges, Class<T> clazz,
			int _size, Collection<String> indices) {
		final int size = Integer.min(_size, maxSize);
		BoolQuery.Builder bool = new BoolQuery.Builder();
		for (Map.Entry<String, String> kv : kvs.entrySet()) {
			TermQuery conj = QueryBuilders.term().field(kv.getKey()).value(FieldValue.of(kv.getValue())).build();
			bool.must(conj.toQuery());
		}
		for (Map.Entry<String, Pair<Integer, Integer>> kv: ranges.entrySet()) {
			RangeQuery conj = QueryBuilders.range().field(kv.getKey())
					.gte(JsonData.of(kv.getValue().getLeft()))
					.lt(JsonData.of(kv.getValue().getRight())).build();
			bool.must(conj.toQuery());
		}
		try {
			SearchResponse<T> response = client(OpenSearchClient.class).search(
					s -> s.index(new ArrayList<>(indices)).size(size).query(bool.build().toQuery()), clazz);
			return response.hits().hits().stream().map(h -> h.source()).collect(Collectors.toList());
		} catch (OpenSearchException e) {
			int status = e.status();
			if (status == HttpStatus.SC_NOT_FOUND) {
				return Collections.emptyList();
			}
			throw new ClientErrorException(status, e);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}


	@Override
	public void close() throws Exception {
		transport.close();
	}

	@Override
	public String deleteIndex(String index) {
		try {
			client.indices().delete(d -> d.index(index));
			return index;
		} catch (OpenSearchException e) {
			int status = e.status();
			if (status == HttpStatus.SC_NOT_FOUND) {
				return null;
			}
			throw new ClientErrorException(status, e);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

	@Override
	public Set<String> allIndices() {
		try {
			return client.cat().indices().valueBody().stream().map(r -> r.index()).filter(i -> i.startsWith(prefix))
					.collect(Collectors.toSet());
		} catch (OpenSearchException | IOException e) {
			logger.warn(e.getMessage());
			return Collections.emptySet();
		}
	}

	@Override
	public String listSnapshots() {
		try {
			SnapshotsResponse sr = client.cat().snapshots();
			return sr.toJsonString();
		} catch (OpenSearchException | IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public String createSnapshot(String name) {
		try {
			CreateSnapshotResponse crr = client.snapshot().create(c -> c.repository(repositoryName).snapshot(name));
			return crr.toJsonString();
		} catch (OpenSearchException | IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public String getSnapshotStatus(String name) {
		try {
			SnapshotStatusResponse ssr = client.snapshot().status(s -> s.repository(repositoryName).snapshot(name));
			return ssr.toJsonString();
		} catch (OpenSearchException | IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public String deleteSnapshot(String name) {
		try {
			DeleteSnapshotResponse dsr = client.snapshot().delete(d -> d.repository(repositoryName).snapshot(name));
			return dsr.toJsonString();
		} catch (OpenSearchException | IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

	@Override
	public String restoreSnapshot(String name) {
		try {
			client.indices().delete(d -> d.index(new ArrayList<>(allIndices())));
			RestoreSnapshotResponse rr = client.snapshot()
					.restore(r -> r.repository(repositoryName).snapshot(name).waitForCompletion(true));
			return rr.toJsonString();
		} catch (OpenSearchException | IOException e) {
			throw new InternalServerErrorException(e);
		}
	}

}
