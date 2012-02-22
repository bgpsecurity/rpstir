/*
 * Created on Feb 14, 2012
 */
package com.bbn.rpki.test.tasks;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.bbn.rpki.test.actions.Epoch;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class EpochSorter {
  private final Map<Epoch, EpochGroup> map = new HashMap<Epoch, EpochGroup>();

  private final List<EpochGroup> groups = new ArrayList<EpochGroup>();

  /**
   * @param epochs the epochs to sort
   */
  public EpochSorter(Collection<Epoch> epochs) {
    for (Epoch epoch : epochs) {
      addEpoch(epoch);
    }
  }

  /**
   * computes the epoch index of all groups and assigns that to the epochs
   * within the group.
   * @return the epoch collection sorted into groups of coincident epochs
   */
  public List<EpochGroup> sort() {
    Set<EpochGroup> processedGroups = new HashSet<EpochGroup>();
    int maxEpochIndex = 0;
    for (EpochGroup group: groups) {
      int epochIndex = computeEpochIndex(group, processedGroups);
      if (epochIndex > maxEpochIndex) {
        maxEpochIndex = epochIndex;
      }
      for (Epoch epoch : group.getEpochs()) {
        epoch.setEpochIndex(group.getEpochIndex());
      }
    }
    List<EpochGroup> ret = new ArrayList<EpochGroup>(maxEpochIndex + 1);
    for (int i = 0; i <= maxEpochIndex; i++) {
      EpochGroup group = new EpochGroup();
      group.setEpochIndex(i);
      ret.add(group);
    }
    for (Epoch epoch : map.keySet()) {
      int epochIndex = map.get(epoch).getEpochIndex();
      epoch.setEpochIndex(epochIndex);
      ret.get(epochIndex).addEpoch(epoch);
    }
    return ret;
  }

  private int computeEpochIndex(EpochGroup group, Set<EpochGroup> visited) {
    if (visited.add(group)) {
      int ix = 0;
      for (EpochGroup predecessorGroup : group.getPredecessors()) {
        int predecessorIndex = computeEpochIndex(predecessorGroup, visited);
        ix = Math.max(ix, predecessorIndex + 1);
      }
      group.setEpochIndex(ix);
    }
    return group.getEpochIndex();
  }

  private EpochGroup findGroup(Epoch epoch, Set<Epoch> visited) {
    EpochGroup group = null;
    for (Epoch coincidentEpoch : epoch.getCoincidentEpochs()) {
      if (visited.add(coincidentEpoch)) {
        group = map.get(coincidentEpoch);
        if (group != null) {
          break;
        }
        group = findGroup(coincidentEpoch, visited);
        if (group != null) {
          break;
        }
      }
    }
    if (group == null) {
      group = new EpochGroup();
      groups.add(group);
    }
    group.add(epoch);
    map.put(epoch, group);
    return group;
  }

  private void addEpoch(Epoch epoch) {
    EpochGroup group = map.get(epoch);
    if (group == null) {
      HashSet<Epoch> visited = new HashSet<Epoch>();
      group = findGroup(epoch, visited);
      for (Epoch predecessor : epoch.getPredecessorEpochs()) {
        visited.clear();
        EpochGroup predecessorGroup = findGroup(predecessor, visited);
        assert predecessor.getSuccessorEpochs().contains(epoch);
        group.addPredecessor(predecessorGroup);
      }
    }
  }
}
