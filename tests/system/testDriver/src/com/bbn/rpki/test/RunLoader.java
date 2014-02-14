/*
 * Created on Dec 12, 2011
 */
package com.bbn.rpki.test;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

import com.bbn.rpki.test.objects.Constants;
import com.bbn.rpki.test.objects.TypescriptLogger;
import com.bbn.rpki.test.objects.Util;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class RunLoader {
	private static RunLoader singleton;

	private static final String RCLI_LOG = "rcli.log";

	private static final String RSYNC_AUR_LOG = "rsync_aur.log";

	/**
	 * @return the singleton instance
	 */
	public static RunLoader singleton() {
		if (singleton == null) {
			singleton = new RunLoader();
		}
		return singleton;
	}

	private Process process;

	private Thread watcher;

	private boolean stopping;

	private TypescriptLogger typescriptLogger;

	private RunLoader() {
		// Private constructor;
	}

	/**
	 * Start the loader
	 */
	public void start() {
		assert process == null;
		try {
			Util.killProcessesRunning("rcli");
			Util.killProcessesRunning("rsync_aur/rsync_listener");
			new File(Constants.LOG_DIR, RunLoader.RCLI_LOG).delete();
			new File(Constants.LOG_DIR, RunLoader.RSYNC_AUR_LOG).delete();
			String rpkiPort = Util.config_get("RPKIPort");
			process = Runtime.getRuntime().exec("rcli -w " + rpkiPort + " -p",
					null, null);
			if (typescriptLogger != null) {
				typescriptLogger.suckOn(
						new InputStreamReader(process.getErrorStream()),
						"stderr");
				typescriptLogger.suckOn(
						new InputStreamReader(process.getInputStream()),
						"stdout");
			}
			stopping = false;
			watcher = new Thread("Loader watcher");
			watcher.start();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Override Thread.run() to watch the process and barf it it terminates
	 * prematurely.
	 */
	public void run() {
		try {
			process.waitFor();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		assert stopping;
	}

	/**
	 *
	 */
	public void stop() {
		stopping = true;
		process.destroy();
		try {
			watcher.join();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		process = null;
	}

	/**
	 * @param typescriptLogger
	 */
	public void setTypescriptLogger(TypescriptLogger typescriptLogger) {
		this.typescriptLogger = typescriptLogger;
	}
}
