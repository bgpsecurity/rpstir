/*
 * Created on Feb 21, 2012
 */
package com.bbn.rpki.test.tasks;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.bbn.rpki.test.actions.Epoch;

/**
 * Contains a Epochs that are simultaneous
 *
 * @author tomlinso
 */
public class EpochGroup {
  private final List<Epoch> epochs = new ArrayList<Epoch>();
  private final Set<EpochGroup> predecessors = new HashSet<EpochGroup>();
  private int epochIndex;

  void add(Epoch epoch) {
    epochs.add(epoch);
  }

  void addPredecessor(EpochGroup group) {
    assert group != null;
    predecessors.add(group);
  }

  /**
   * @return the epochs
   */
  public int getEpochCount() {
    return epochs.size();
  }

  /**
   * @return the predecessors
   */
  public Set<EpochGroup> getPredecessors() {
    return predecessors;
  }

  /**
   * @return the epochIndex
   */
  public int getEpochIndex() {
    return epochIndex;
  }

  /**
   * @param index
   * @return the epoch at the specified index
   */
  public Epoch getEpoch(int index) {
    return epochs.get(index);
  }

  /**
   * @param epochIndex the epochIndex to set
   */
  public void setEpochIndex(int epochIndex) {
    this.epochIndex = epochIndex;
  }

  /**
   * @param epoch
   */
  public void addEpoch(Epoch epoch) {
    epochs.add(epoch);
  }

  /**
   * @return the epochs
   */
  public Iterable<Epoch> getEpochs() {
    return epochs;
  }

  /**
   * @param child
   * @return the index of the specified child
   */
  public int indexOf(Object child) {
    return epochs.indexOf(child);
  }

  @Override
  public String toString() {
    return "Epoch Group " + epochIndex;
  }
}