/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client.job;

import java.io.Closeable;
import java.io.IOException;
import java.time.Duration;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.CTIDuration;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.client.RemoteInfo;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.impl.STIXObject;

/**
 * Provides "at least once" delivery of objects...it is likely that, especially
 * if stopped and restarted, objects will be duplicated. It is up to consumer to
 * cope, sorry...
 */
public abstract class ClientJob implements Consumer<Envelope>, Runnable, Closeable {

	public abstract class Worker implements Runnable {

		@JsonIgnore
		private Envelope envelope;

		@JsonIgnore
		private WorkerParams actual;

		protected void setEnvelope(Envelope envelope) {

			this.envelope = envelope;
			logger.debug(String.format("envelope.size(): %d %s", envelope.size(), this));

			if(!envelope.isEmpty()) {
				Timestamp actualBegin = (actual != null) ? actual.getBegin() : envelope.getFirst();
				actual = new WorkerParams(actualBegin, envelope.getLast().plus(resolution()));
				logger.debug(String.format("actual: %s", actual));
			}

		}

		@JsonIgnore
		public WorkerParams getActual() {
			return actual;
		}

		@JsonIgnore
		public boolean isEmpty() {
			return envelope.isEmpty();
		}

		@Override
		public void run() {

			// If workerParams were submitted, keep running if the end is in the future.
			// If we generated worker params, run until empty.
			while (hasWorkers ? (getEnd().compareTo(Timestamp.now()) > 0) : !isEmpty()) {

				if (!isEmpty()) {
					accept(envelope);
				}

				boolean upsert = false;
				try {
					lock.lock();

					/*
					 * cancel moot workers
					 */
					Iterator<Map.Entry<WorkerParams, Future<?>>> iEntry = workers.entrySet().iterator();
					while (iEntry.hasNext()) {
						Map.Entry<WorkerParams, Future<?>> entry = iEntry.next();
						WorkerParams worker = entry.getKey();
						if ((getParams().compareTo(worker) != 0) && actual.contains(worker)) {
							logger.debug(String.format("cancelling %s (%s)", worker, this));
							entry.getValue().cancel(true);
							iEntry.remove();
							availableWorkers.release();
							upsert = true;
						}
					}

					upsert |= bumpNextWorker();
				} finally {
					lock.unlock();
				}

				if(upsert) {
					upsert();
				}

				if (actual.contains(getParams())) {
					break;
				}

				setEnvelope(objects());

				if (hasWorkers && isEmpty()) {
					try {
						Thread.sleep(Duration.ofMinutes(15).toMillis());
					} catch (InterruptedException e) {
						logger.debug("Wait for retry interrupted");
					}
				}

			}

			try {
				lock.lock();
				workers.remove(getParams());
				availableWorkers.release();
			} finally {
				lock.unlock();
			}
			upsert();

			logger.debug(String.format("%s exiting", this));

		}

		public boolean bumpNextWorker() {
			boolean upsert = actual.getEnd().compareTo(nextWorker) > 0;
			if (upsert) {
				nextWorker = actual.getEnd();
				if (nextWorker.compareTo(now) > 0) {
					nextWorker = now;
				}
				logger.debug(String.format("bumped nextWorker to %s (%s)", nextWorker, this));
			}
			return upsert;
		}

		protected abstract Envelope objects();

		protected Timestamp getEnd() {
			return getParams().getEnd();
		}

		protected abstract WorkerParams getParams();

		@Override
		public String toString() {
			return getParams().toString();
		}

	}

	protected abstract CTIDuration resolution();

	public static final Logger logger = LogManager.getLogger(ClientJob.class);

	private final Semaphore availableWorkers;
	private final Map<WorkerParams, Future<?>> workers = new TreeMap<>();
	private final Lock lock = new ReentrantLock();

	private final RemoteInfo info;
	private final int workerCount;
	private final CTIDuration workerDuration;
	protected Timestamp nextWorker;
	private Timestamp now;
	private boolean hasWorkers;

	public Configuration getConfiguration() {
		try {
			lock.lock();
			return configurationFactory(info, workerCount, workerDuration, nextWorker);
		} finally {
			lock.unlock();
		}
	}

	protected abstract Configuration configurationFactory(RemoteInfo info, int workerCount, CTIDuration workerDuration,
			Timestamp nextWorker);

	public Snapshot getSnapshot() {
		try {
			lock.lock();
			return snapshotFactory(workers.keySet(), nextWorker);
		} finally {
			lock.unlock();
		}
	}

	protected abstract Snapshot snapshotFactory(Set<WorkerParams> wps, Timestamp nextWorker);

	public void setSnapshot(Snapshot snapshot) {
		if (isRunning()) {
			throw new IllegalStateException();
		}
		try {
			lock.lock();
			Set<? extends WorkerParams> workerParams = snapshot.getWorkerParams();
			int size = (workerParams != null) ? workerParams.size() : 0;
			if (size > workers.size() + availableWorkers.availablePermits()) {
				throw new IllegalArgumentException();
			}
			availableWorkers.release(workers.size());
			workers.clear();
			if (workerParams != null) {
				for (WorkerParams wps : workerParams) {
					try {
						availableWorkers.acquire();
					} catch (InterruptedException e) {
						throw new IllegalArgumentException(e);
					}
					workers.put(wps, null);
				}
			}
			nextWorker = snapshot.getNextWorker();
			hasWorkers = snapshot.hasWorkerParams();
		} finally {
			lock.unlock();
		}
	}

	public abstract Snapshot remoteSnapshotFactory(JsonNode root);

	public ClientJob(RemoteInfo info, int workerCount, CTIDuration workerDuration, Timestamp nextWorker) {
		super();

		exec = Executors.newScheduledThreadPool(workerCount + 1);

		Runtime.getRuntime().addShutdownHook(new Thread() {
			@Override
			public void run() {
				if (exec != null) {
					exec.shutdownNow();
				}
			}
		});

		this.info = info;
		this.availableWorkers = new Semaphore(workerCount);
		this.workerCount = workerCount;
		this.workerDuration = workerDuration;
		this.nextWorker = nextWorker;

	}

	protected void setNextWorker(Timestamp nextWorker) {
		this.nextWorker = nextWorker;
	}

	protected abstract Worker workerFactory(WorkerParams wps);

	protected abstract Worker workerFactory(Timestamp begin, Timestamp end, WorkerParams wps);

	@Override
	public void run() {
		now = Timestamp.now();

		/*
		 * if restarting, need to launch old workers?...
		 */
		try {
			lock.lock();
			Iterator<WorkerParams> iParams = workers.keySet().iterator();
			while(iParams.hasNext()) {
				WorkerParams wps = iParams.next();
				if (workers.get(wps) == null) {
					Worker worker = workerFactory(wps);
					if(!worker.isEmpty()) {
						workers.put(wps, exec.submit(worker));
						logger.debug(String.format("restarting %s", worker));
					} else {
						iParams.remove();
						availableWorkers.release();
						logger.debug(String.format("restart empty %s", worker));
					}
				}
			}
		} finally {
			lock.unlock();
		}

		while (true) {
			try {
				availableWorkers.acquire();
			} catch (InterruptedException e) {
				me = null;
				upsert();
				return;
			}
			try {
				lock.lock();

				// If the snapshot had workers defined, just run those workers until they are done.
				if (hasWorkers) {
					if (workers.isEmpty())
						break;
					else
						continue;
				}

				if (nextWorker.compareTo(now) == 0) {
					logger.debug("nextWorker == now");
					break;
				}
				// When generating workers, use now as the end date
				// so that we can restart correctly.
				Timestamp end = nextWorker.plus(workerDuration);
				if (end.compareTo(now) > 0) {
					end = now;
				}
				if (end.compareTo(nextWorker) <= 0) {
					break;
				}
				Worker worker = workerFactory(nextWorker, end, null);
				if (worker.isEmpty()) {
					logger.debug("worker empty");
					nextWorker = end;
					availableWorkers.release();
				} else {
					logger.debug(String.format("creating worker: %s", worker));
					nextWorker = end;
					worker.bumpNextWorker();
					workers.put(worker.getParams(), exec.submit(worker));
					upsert();
				}

			} finally {
				lock.unlock();
			}
		}
		stop();
		logger.debug("ClientJob exiting...");
	}

	public void upsert() {
		System.err.println(getSnapshot());
	}

	@Override
	public void accept(Envelope envelope) {
		for (STIXObject object : envelope.getObjects()) {
			System.out.println(STIXObject.encodeId(object));
		}
	}

	@Override
	public void close() throws IOException {
		stop();
		exec.shutdownNow();
	}

	private final ScheduledExecutorService exec;
	private Future<?> me;

	synchronized public boolean start() {
		if (me == null) {
			me = exec.submit(this);
			return true;
		}
		return false;
	}

	synchronized public boolean stop() {
		if (me != null) {
			upsert();
			me.cancel(true);
			me = null;
			return true;
		}
		return false;
	}

	synchronized public boolean isRunning() {
		return me != null;
	}

}
