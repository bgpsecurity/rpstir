/*
 * Created on Nov 7, 2011
 */
package com.bbn.rpki.test.activity;

import com.bbn.rpki.test.model.TaskDescription;
import com.bbn.rpki.test.model.TestModel;

/**
 * Constructs some activities for testing.
 *
 * @author RTomlinson
 */
public class TestActivity {
  TestActivity(TestModel testModel) {
    TaskDescription taskDescription = testModel.getTaskDescription("create");
  }
}
