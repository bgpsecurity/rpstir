/*
 * Created on Feb 14, 2012
 */
package com.bbn.rpki.test.tasks;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.bbn.rpki.test.actions.EpochEvent;

/**
 * Starts with a collection of EpochEvents and groups coincident EpochEvents into Epochs.
 * Then imposes the constraints on the individual EpochEvents onto the Epochs. Finally,
 * the Epochs are sorted. Such that all predecessor Epochs come before their successors.
 *
 * @author tomlinso
 */
public class EpochSorter {
  private final List<Epoch> epochs = new ArrayList<Epoch>();
  private final Map<Epoch, Set<Epoch>> predecessors = new HashMap<Epoch, Set<Epoch>>();

  /**
   * @param epochEvents the epochs to sort
   */
  public EpochSorter(Collection<EpochEvent> epochEvents) {
    for (EpochEvent epochEvent : epochEvents) {
      epochEvent.setEpoch(null);
    }
    for (EpochEvent epochEvent : epochEvents) {
      addEpochEvent(epochEvent);
    }
  }

  /**
   * computes the index of all epochs and assigns that to the EpochEvents
   * within the epoch.
   * 
   * @return the Epoch collection sorted into a proper succession of epoch events.
   */
  public List<Epoch> sort() {
    int maxEpochIndex = -1;
    for (Epoch epoch: epochs) {
      epoch.setEpochIndex(null);
      Set<Epoch> epochPredecessors = new HashSet<Epoch>();
      predecessors.put(epoch, epochPredecessors);
      for (EpochEvent epochEvent : epoch.getEpochEvents()) {
        for (EpochEvent predecessor : epochEvent.getPredecessorEpochEvents()) {
          Epoch predecessorEpoch = predecessor.getEpoch();
          assert predecessorEpoch != null;
          assert predecessor.getSuccessorEpochEvents().contains(epochEvent);
          epochPredecessors.add(predecessorEpoch);
        }
      }
    }
    for (Epoch epoch: epochs) {
      int epochIndex = computeEpochIndex(epoch);
      if (epochIndex > maxEpochIndex) {
        maxEpochIndex = epochIndex;
      }
    }
    Epoch[] retArray = new Epoch[maxEpochIndex + 1];
    Arrays.fill(retArray, null);
    for (Epoch epoch : epochs) {
      int epochIndex = epoch.getEpochIndex();
      if (retArray[epochIndex] == null) {
        retArray[epochIndex] = epoch;
      } else {
        retArray[epochIndex].subsumeEpoch(epoch);
      }
    }
    return Arrays.asList(retArray);
  }

  /**
   * The epochIndex of any Epoch is one greater than the maximum epochIndex
   * of all its predecessors.
   * @param epoch
   * @return
   */
  private int computeEpochIndex(Epoch epoch) {
    Integer epochIndex = epoch.getEpochIndex();
    if (epochIndex == null) {
      int ix = 0;
      for (Epoch predecessorEpoch : predecessors.get(epoch)) {
        int predecessorIndex = computeEpochIndex(predecessorEpoch);
        ix = Math.max(ix, predecessorIndex + 1);
      }
      epochIndex = ix;
      epoch.setEpochIndex(epochIndex);
    }
    return epochIndex;
  }

  /**
   * Find EpochGroups coincident with the given epochEvent.
   * Combine EpochGroups that are mutually coincident with the given epochEvent.
   * Return the EpochGroup thus found or a brand new one i
   * 
   * @param epochEvent
   * @return
   */
  private Epoch findEpoch(EpochEvent epochEvent) {
    Epoch epoch = null;
    List<EpochEvent> pendingEpochEvents = new ArrayList<EpochEvent>(1 + epochEvent.getCoincidentEpochs().size());
    Collection<EpochEvent> coincidentEpochs = epochEvent.getCoincidentEpochs();
    for (EpochEvent coincidentEpochEvent : coincidentEpochs) {
      Epoch testEpoch = coincidentEpochEvent.getEpoch();
      if (testEpoch != null) {
        if (epoch != null) {
          if (testEpoch == epoch) {
            continue;
          }
          epoch.subsumeEpoch(testEpoch);
          epochs.remove(testEpoch);
        } else {
          epoch = testEpoch;
        }
      } else {
        pendingEpochEvents.add(coincidentEpochEvent);
      }
    }
    if (epoch == null) {
      epoch = new Epoch();
      epochs.add(epoch);
    }
    pendingEpochEvents.add(epochEvent);
    for (EpochEvent pendingEpochEvent : pendingEpochEvents) {
      epoch.addEpochEvent(pendingEpochEvent);
    }
    return epoch;
  }

  /**
   * 
   * @param epochEvent
   */
  private void addEpochEvent(EpochEvent epochEvent) {
    Epoch epoch = epochEvent.getEpoch();
    if (epoch == null) {
      findEpoch(epochEvent);
    }
  }
}
