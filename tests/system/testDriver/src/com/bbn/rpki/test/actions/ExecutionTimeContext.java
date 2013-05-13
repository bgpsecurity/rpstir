/*
 * Created on Oct 12, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.tasks.TaskFactory;
import com.bbn.rpki.test.tasks.TaskFactory.Task;

/**
 * Provides a context within which execution times may estimated.
 * 
 * Records the numbers of object updates of various kinds that will occur and the task breakdowns
 * that will upload the objects. Also recorded are cache check invocations.
 * 
 * For example, there is execution time overhead associated with performing an scp to a repository
 * publication point. This overhead is incurred only once per publication point per upload task.
 * Additionally there is time spent per file and per byte. This version applies the per file burden,
 * but ignores the per byte burden.
 *
 * @author rtomlinson
 */
public class ExecutionTimeContext {
  public static final long MINIMAL_TIME = 100;
  public static final long CACHE_CHECK_TIME = 5000;
  private final Map<CA_Object, Set<Object>> publishCerts = new HashMap<CA_Object, Set<Object>>();
  private final Map<CA_Object, Set<Object>> unpublishCerts = new HashMap<CA_Object, Set<Object>>();
  private final Map<CA_Object, Set<Object>> publishOthers = new HashMap<CA_Object, Set<Object>>();
  private final List<TaskFactory.Task> expectedTasks = new ArrayList<TaskFactory.Task>();

  public void publishCert(CA_Object publisher, Object subject) {
    Set<Object> subjects = publishCerts.get(publisher);
    if (subjects == null) {
      subjects = new HashSet<Object>();
      publishCerts.put(publisher, subjects);
    }
    subjects.add(subject);
  }

  public void unpublishCert(CA_Object publisher, Object subject) {
    Set<Object> subjects = unpublishCerts.get(publisher);
    if (subjects == null) {
      subjects = new HashSet<Object>();
      unpublishCerts.put(publisher, subjects);
    }
    subjects.add(subject);
  }

  /**
   * @param task
   */
  public void addTask(Task task) {
    expectedTasks.add(task);
  }
}
