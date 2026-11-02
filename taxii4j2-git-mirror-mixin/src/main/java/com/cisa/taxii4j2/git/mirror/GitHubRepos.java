/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.mirror;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.networknt.schema.JsonSchemaException;
import com.networknt.schema.SpecVersionDetector;
import com.cisa.cti4j2.CommonProperty;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.Timestamp;
import com.cisa.cti4j2.Type;
import com.cisa.taxii4j2.data.impl.JSONSTIXObject;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.data.impl.Storable;
import com.cisa.taxii4j2.data.impl.TAXIIConfig;
import com.cisa.taxii4j2.git.mirror.method.TAXIIMirror.MirrorState;
import com.cisa.taxii4j2.git.mirror.method.impl.DbTaxiiRef;
import com.cisa.taxii4j2.servlet.store.DbBase;
import com.cisa.taxii4j2.servlet.store.DbTaxii;

import jakarta.ws.rs.NotFoundException;

public class GitHubRepos {

	private static DbTaxii dbTaxii;

	private static String filterIndex;
	private static String schemaIndex;

	private static final String idKey = "$id";
	private static final String jsonSuffix = ".json";

	private static final int corePoolSize = 4;
	private static final ScheduledExecutorService exec = Executors.newScheduledThreadPool(corePoolSize);

	private static class State {
		private final ReentrantLock lock = new ReentrantLock();
		private Future<?> updater;
		private final Map<UUID, Future<?>> running = new HashMap<>();
	}

	private static final Map<UUID, State> states = new ConcurrentHashMap<>();

	static {
		Runtime.getRuntime().addShutdownHook(new Thread() {

			@Override
			public void run() {
				exec.shutdown();
				try {
					if (exec.awaitTermination(10, TimeUnit.MINUTES)) {
						return;
					}
					List<Runnable> stranded = exec.shutdownNow();
					logger.warn(String.format("GitHubRepos exec shutdown timed out stranding %d threads...",
							stranded.size()));
				} catch (InterruptedException e) {
					logger.log(Level.WARN, "GitHubRepos.shutdown", e);
				}
			}

		});
	}

	public static void start() {
		for (GitHubRepo filter : db().list(filterIndex(), GitHubRepo.class)) {
			states.put(filter.getUuid(), new State());
			update(filter.getUuid());
			start(filter);
		}
	}

	private static void start(GitHubRepo gh) {
		String update_rate = gh.getUpdate_rate();
		if (update_rate != null) {
			try {
				String[] parts = update_rate.split("\\s+");
				long period = Long.valueOf(parts[0]);
				Future<?> updater = exec.scheduleAtFixedRate(new Runnable() {
					@Override
					public void run() {
						update(gh.getUuid());
					}
				}, period, period, TimeUnit.valueOf(parts[1].toUpperCase()));
				states.get(gh.getUuid()).updater = updater;
			} catch (Exception e) {
				logger.warn(String.format("GitHubRepos.start: %s", e.getMessage()));
			}
		}
	}

	static DbTaxii dbTaxii() {
		if (dbTaxii == null) {
			dbTaxii = TAXIIConfig.serviceLocator().getService(DbTaxii.class);
		}
		return dbTaxii;
	}

	static DbBase db() {
		return dbTaxii().getDb();
	}

	static String filterIndex() {
		if (filterIndex == null) {
			filterIndex = db().createIndex(db().localizeIndexName("github-filters"));
		}
		return filterIndex;
	}

	static String schemaIndex() {
		if (schemaIndex == null) {
			schemaIndex = db().createIndex(db().localizeIndexName("github-schema"));
		}
		return schemaIndex;
	}

	public static Ref getRef(STIXObject prev) {
		JsonNode refNode = prev.asObjectNode().get(DbTaxiiRef.refKey);
		return (refNode != null) ? JSON.convertValue(refNode, Ref.class) : null;
	}

	private static void _write(GitHubRepo filter) {
		db().put(filter, filterIndex(), filter.getUuid().toString());
		db().refresh(filterIndex());
	}

	private static GitHubRepo _read(UUID uuid) {
		return db().get(uuid.toString(), filterIndex(), GitHubRepo.class);
	}

	public static MirrorState create(GitHubRepo filter) {

		UUID uuid = filter.getUuid();
		if (uuid == null) {
			uuid = UUID.randomUUID();
			filter.setUuid(uuid);
		}

		State state = new State();
		if (states.putIfAbsent(uuid, state) != null) {
			throw new IllegalArgumentException("GitHubRepos.create: duplicate filter UUID");
		}

		if (!filter.isValid()) {
			throw new IllegalArgumentException("GitHubRepos.create: one or more mappings overlap...");
		}

		try {
			state.lock.lock();
			Set<Mapping> mappings = filter.getMappings();
			filter.setMappings(null);
			filter.hasChanged();
			_write(filter);
			if (mappings != null) {
				for (Mapping mapping : mappings) {
					add(filter.getUuid(), mapping);
				}
			}
			return state(uuid);
		} finally {
			state.lock.unlock();
		}

	}

	private static MirrorState state(UUID uuid) {
		State state = states.get(uuid);
		if (state == null) {
			throw new NotFoundException();
		}
		try {
			state.lock.lock();
			Map<UUID, Future<?>> running = state.running;
			Iterator<Map.Entry<UUID, Future<?>>> iEntry = running.entrySet().iterator();
			while (iEntry.hasNext()) {
				Map.Entry<UUID, Future<?>> entry = iEntry.next();
				Future<?> future = entry.getValue();
				if (future.isCancelled() || future.isDone()) {
					iEntry.remove();
				}
			}
			return new MirrorState(_read(uuid), running.keySet());
		} finally {
			state.lock.unlock();
		}
	}

	public static MirrorState add(UUID uuid, Mapping mapping) {

		State state = states.get(uuid);
		if (state == null) {
			throw new NotFoundException();
		}

		try {

			state.lock.lock();

			UUID mUuid = mapping.getUuid();
			if (mUuid == null) {
				mUuid = UUID.randomUUID();
				mapping.setUuid(mUuid);
			}

			GitHubRepo filter = _read(uuid);
			Set<Mapping> mappings = filter.getMappings();
			if (mappings != null) {
				for (Mapping m1 : mappings) {
					if (filter.intersects(mapping, m1)) {
						throw new IllegalArgumentException(
								"GitHubRepos.add: the new mapping overlaps a current mapping...");
					}
				}
			}

			filter.add(mapping);
			_write(filter);
			state.running.put(mUuid, exec.submit(new Runnable() {
				@Override
				public void run() {
					filter.create(mapping);
				}
			}));

			return state(uuid);

		} finally {
			state.lock.unlock();
		}
	}

	public static MirrorState remove(UUID uuid, UUID mUuid) {
		State state = states.get(uuid);
		if (state == null) {
			throw new NotFoundException();
		}
		try {
			state.lock.lock();
			GitHubRepo filter = _read(uuid);
			state(uuid);
			if (state.running.containsKey(mUuid)) {
				throw new IllegalStateException("GitHubRepos.remove mapping: busy");
			}
			if (!filter.remove(mUuid)) {
				throw new NotFoundException();
			}
			_write(filter);
			return state(uuid);
		} finally {
			state.lock.unlock();
		}
	}

	public static MirrorState update(UUID uuid) {

		State state = states.get(uuid);
		if (state == null) {
			throw new NotFoundException();
		}

		try {

			state.lock.lock();

			/*
			 * update and check running...
			 */
			state(uuid);
			if (!state.running.isEmpty()) {
				throw new IllegalStateException("GitHubRepos.update: busy");
			}

			GitHubRepo filter = _read(uuid);
			if (filter.hasChanged()) {
				_write(filter);
				Set<Mapping> mappings = filter.getMappings();
				if (mappings != null) {
					for (Mapping mapping : mappings) {
						state.running.put(mapping.getUuid(), exec.submit(new Runnable() {
							@Override
							public void run() {
								filter.update(mapping);
							}
						}));
					}
				}
				state.running.put(uuid, exec.submit(new Runnable() {
					@Override
					public void run() {
						filter.update();
					}
				}));
			}

			return state(uuid);

		} finally {
			state.lock.unlock();
		}

	}

	public static final Logger logger = LogManager.getLogger(GitHubRepos.class);

	public static JsonNode getSchema(String id) {
		try {
			JsonNode root = db().get(id, schemaIndex(), JsonNode.class);
			return JSON.readTree(root.get(Mapping.schemaKey).asText());
		} catch (Exception e) {
			logger.log(Level.WARN, e.getMessage());
			return null;
		}
	}

	public static List<MirrorState> list() {
		synchronized (states) {
			return db().list(filterIndex(), GitHubRepo.class).stream().map(filter -> state(filter.getUuid()))
					.collect(Collectors.toList());
		}
	}

	public static void createFile(JsonNode root, Mapping mapping, String ghPath, String sha, Integer offset) {

		STIXObject object = new JSONSTIXObject(root);

		/*
		 * ensure that this is a viable object...we can be certain that it has a
		 * version, fake or not, since even SCOs have an implied version...
		 */
		String id = object.getId();

		/*
		 * ok, now let's clean up the object (sheesh)
		 */
		log(id, object.removeEmptyArrays());
		log(id, object.trimTexts());

		/*
		 * decorate the object
		 */
		object.asObjectNode().set(DbTaxiiRef.refKey, JSON.toJsonNode(new Ref(mapping.getUuid(), ghPath, sha,
				STIXObject.encodeId(object), dbTaxii().objectIndexName(object), offset)));
		Set<String> cIds = mapping.getcIds();
		if (cIds != null) {
			for (String cId : cIds) {
				object.asObjectNode().put(STIXObject.date_addedKey(cId), new Timestamp().toString());
			}
		}

		/*
		 * directly add to index (!!! NO VALIDATION !!!)
		 */
		DbTaxii db = dbTaxii();
		db.getDb().put(object, db.objectIndexName(object), Storable.encodeId(object), false);

	}

	public static void createSchema(JsonNode schema, Mapping mapping, String ghPath, String sha) {
		try {
			SpecVersionDetector.detect(schema);
			Relocate relocate = mapping.getRelocate();
			if (relocate != null) {
				JsonNode id = schema.get(idKey);
				if (id != null) {
					String value = relocate.apply(id.asText());
					ObjectNode.class.cast(schema).put(idKey, value);
				}
			}
			ObjectNode root = JSON.factory.objectNode();
			root.put(Mapping.schemaKey, JSON.writeTreeAsString(schema));
			String id = getSchemaId(ghPath, schema);
			String index = GitHubRepos.schemaIndex();
			root.set(DbTaxiiRef.refKey, JSON.toJsonNode(new Ref(mapping.getUuid(), ghPath, sha, id, index, 0)));
			GitHubRepos.db().put(root, index, id, false);
		} catch (JsonSchemaException | IOException e1) {

		}

	}

	private static String getSchemaId(String ghPath, JsonNode schema) {

		String prefix = Type.EXTENSION_DEFINITION.toSTIXType();

		/*
		 * first, try the easy button (extract from path)
		 */
		String id = Paths.get(ghPath).getFileName().toString();
		int index = id.lastIndexOf(jsonSuffix);
		if (index >= 0) {
			id = id.substring(0, index);
		}
		if (id.startsWith(prefix)) {
			return id;
		}

		/*
		 * nope - try to extract from schema itself
		 */
		try {
			JsonNode eps = schema.findValue(CommonProperty.EXTENSIONS.getJsonKey()).findValue("properties");
			Iterator<String> iFieldName = eps.fieldNames();
			while (iFieldName.hasNext()) {
				String fieldName = iFieldName.next();
				if (fieldName.startsWith(prefix)) {
					return fieldName;
				}
			}
		} catch (Exception e) {

		}

		/*
		 * must not have been able to extract from schema...
		 */
		return id;

	}

	private static void log(String id, List<String> messages) {
		if (messages.isEmpty()) {
			return;
		}
		String message = messages.stream().reduce(id + ":\n", (prev, curr) -> prev += "\t" + curr + "\n");
		logger.info(message);
	}

	public static MirrorState read(UUID uuid) {
		return state(uuid);
	}

	public static boolean remove(UUID uuid) {
		State state = states.get(uuid);
		if (state == null) {
			throw new NotFoundException();
		}
		try {
			state.lock.lock();
			state(uuid);
			if (!state.running.isEmpty()) {
				throw new IllegalStateException("GitHubRepos.remove: busy");
			}
			Future<?> updater = state.updater;
			if (updater != null) {
				updater.cancel(false);
			}
			db().delete(uuid.toString(), filterIndex(), GitHubRepo.class);
			db().refresh(filterIndex());
			states.remove(uuid);
			return true;
		} finally {
			state.lock.unlock();
		}
	}

}
