/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.bbn.rpki.test.objects.Constants;
import com.bbn.rpki.test.objects.Util;

/**
 * A task for re-initializing the cache
 *
 * @author tomlinso
 */
public class InitializeCache extends TaskFactory {

	private static final String TASK_NAME = "InitializeCache";

	protected class Task extends TaskFactory.Task {
		protected Task() {
			super(TASK_NAME);
		}

		/**
		 */
		@Override
		public void run() {
			Util.deleteDirectories(new File(Constants.OBJECT_PATH, REPOSITORY),
					new File(Constants.LOG_DIR));

			Util.initDB();
			model.clearDatabase();
		}

		/**
		 * @see com.bbn.rpki.test.tasks.TaskFactory#getLogDetail()
		 */
		@Override
		protected String getLogDetail() {
			return null;
		}
	}

	private static final String REPOSITORY = "REPOSITORY";

	/**
	 * @param model
	 */
	public InitializeCache(Model model) {
		super(model);
	}

	@Override
	protected Task reallyCreateTask(String relativeTaskName) {
		assert TASK_NAME.equals(relativeTaskName);
		return new Task();
	}

	/**
	 * @see com.bbn.rpki.test.tasks.TaskFactory#appendBreakdowns(java.util.List)
	 */
	@Override
	protected void appendBreakdowns(List<Breakdown> list) {
		// There are no breakdowns to append
	}

	@Override
	protected Collection<String> getRelativeTaskNames() {
		return Collections.singleton(TASK_NAME);
	}
}
