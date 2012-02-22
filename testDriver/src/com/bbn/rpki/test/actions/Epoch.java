/*
 * Created on Feb 13, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.AbstractSet;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.jdom.Element;

/**
 * Identifies an Epoch for corresponding to a particular point time such as
 * when (the certificate containing) a particular allocation becomes valid.
 * Epochs may be ordered relative to other epochs: before, after and coincident.
 * Epochs are "named" such that other epochs can be identified for the purpose
 * of establishing these orderings.
 *
 * @author tomlinso
 */
public final class Epoch implements XMLConstants {

  interface OthersAccessor {
    void add(Epoch other, boolean locked);
  }

  private final AbstractAction action;
  private final String description;

  /**
   * @param action
   * @param description
   */
  public Epoch(AbstractAction action, String description) {
    this.action = action;
    this.description = description;
  }

  private class LockableSet extends AbstractSet<Epoch> {
    private final Set<Epoch> locked = new HashSet<Epoch>();
    private final Set<Epoch> unlocked = new HashSet<Epoch>();
    /**
     * @see java.util.AbstractCollection#iterator()
     */
    @Override
    public Iterator<Epoch> iterator() {
      return new Iterator<Epoch>() {
        private final Iterator<Epoch> lockedIterator = locked.iterator();
        private final Iterator<Epoch> unlockedIterator = unlocked.iterator();

        @Override
        public boolean hasNext() {
          return lockedIterator.hasNext() || unlockedIterator.hasNext();
        }

        @Override
        public Epoch next() {
          if (lockedIterator.hasNext()) {
            return lockedIterator.next();
          }
          return unlockedIterator.next();
        }

        @Override
        public void remove() {
          throw new UnsupportedOperationException();
        }
      };
    }

    /**
     * @see java.util.AbstractCollection#contains(java.lang.Object)
     */
    @Override
    public boolean contains(Object o) {
      return locked.contains(o) || unlocked.contains(o);
    }

    /**
     * @see java.util.AbstractCollection#add(java.lang.Object)
     */
    @Override
    public boolean add(Epoch e) {
      return unlocked.add(e);
    }

    public boolean addLocked(Epoch e) {
      return locked.add(e);
    }

    /**
     * @see java.util.AbstractCollection#remove(java.lang.Object)
     */
    @Override
    public boolean remove(Object o) {
      return unlocked.remove(o);
    }

    /**
     * @see java.util.AbstractCollection#addAll(java.util.Collection)
     */
    @Override
    public boolean addAll(Collection<? extends Epoch> c) {
      return unlocked.addAll(c);
    }

    /**
     * @see java.util.AbstractCollection#size()
     */
    @Override
    public int size() {
      return locked.size() + unlocked.size();
    }

    /**
     * @param other
     * @return if in the locked subset
     */
    public boolean isLocked(Epoch other) {
      return locked.contains(other);
    }
  }

  private final LockableSet predecessorEpochs = new LockableSet();
  private final LockableSet successorEpochs = new LockableSet();
  private final LockableSet coincidentEpochs = new LockableSet();
  private int epochIndex;

  /**
   * @return a description suitable for a combo box
   */
  public String getDescription() {
    return description;
  }

  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return getDescription();
  }

  /**
   * @return the predecessors
   */
  public Collection<Epoch> getPredecessorEpochs() {
    return predecessorEpochs;
  }

  /**
   * @return the successors
   */
  public Collection<Epoch> getSuccessorEpochs() {
    return successorEpochs;
  }

  /**
   * @return the coincident
   */
  public Collection<Epoch> getCoincidentEpochs() {
    return coincidentEpochs;
  }

  /**
   * Find all epochs that must follow this one. This includes all direct successors of this epoch
   * plus those that are constrained to follow the successors or those that are coincident with any
   * successor.
   * @return all epochs constrained to follow this one
   */
  public Set<Epoch> findSuccessorEpochs() {
    Set<Epoch> visited = new HashSet<Epoch>();
    Set<Epoch> ret = new HashSet<Epoch>();
    findSuccessorEpochs(ret, visited);
    return ret;
  }

  private void findSuccessorEpochs(Set<Epoch> ret, Set<Epoch> visited) {
    if (visited.add(this)) {
      ret.addAll(successorEpochs);
      HashSet<Epoch> visited2 = new HashSet<Epoch>(visited);
      HashSet<Epoch> visited3 = new HashSet<Epoch>(visited);
      for (Epoch successor : successorEpochs) {
        successor.findSuccessorEpochs(ret, visited2);
        successor.findCoincidentEpochs(ret, visited);
      }
      for (Epoch coincident : coincidentEpochs) {
        coincident.findSuccessorEpochs(ret, visited3);
      }
    }
  }

  /**
   * @return all epochs constrained to precede this one
   */
  public Set<Epoch> findPredecessorEpochs() {
    Set<Epoch> visited = new HashSet<Epoch>();
    Set<Epoch> ret = new HashSet<Epoch>();
    findPredecessorEpochs(ret, visited);
    return ret;
  }

  private void findPredecessorEpochs(Set<Epoch> ret, Set<Epoch> visited) {
    if (visited.add(this)) {
      ret.addAll(predecessorEpochs);
      HashSet<Epoch> visited2 = new HashSet<Epoch>(visited);
      HashSet<Epoch> visited3 = new HashSet<Epoch>(visited);
      for (Epoch predecessor : predecessorEpochs) {
        predecessor.findPredecessorEpochs(ret, visited2);
        predecessor.findCoincidentEpochs(ret, visited);
      }
      for (Epoch coincident : coincidentEpochs) {
        coincident.findPredecessorEpochs(ret, visited3);
      }
    }
  }

  /**
   * @return all epochs coincident with this one
   */
  public Set<Epoch> findCoincidentEpochs() {
    Set<Epoch> visited = new HashSet<Epoch>();
    Set<Epoch> ret = new HashSet<Epoch>();
    findCoincidentEpochs(ret, visited);
    return ret;
  }

  private void findCoincidentEpochs(Set<Epoch> ret, Set<Epoch> visited) {
    if (visited.add(this)) {
      ret.addAll(coincidentEpochs);
      for (Epoch coincident : coincidentEpochs) {
        coincident.findCoincidentEpochs(ret, visited);
      }
    }
  }

  /**
   * @param other the Epoch to add as a predecessor
   * @param locked
   * @return true if other epoch could be added (is not locked to another epoch)
   */
  public boolean addPredecessor(Epoch other, boolean locked) {
    if (isCoincident(other) && !canRemoveCoincident(other)) {
      return false;
    }
    if (isCoincident(other) && !canRemoveCoincident(other)) {
      return false;
    }
    removeSuccessor(other);
    removeCoincident(other);
    if (locked) {
      predecessorEpochs.addLocked(other);
      other.successorEpochs.addLocked(this);
    } else {
      predecessorEpochs.add(other);
      other.successorEpochs.add(this);
    }
    return true;
  }

  /**
   * @param other
   * @return true if the predecessor can be removed (is present and not locked)
   */
  public boolean canRemovePredecessor(Epoch other) {
    return predecessorEpochs.contains(other) && !predecessorEpochs.isLocked(other);
  }

  /**
   * @param other the other Epoch to remove
   */
  public void removePredecessor(Epoch other) {
    predecessorEpochs.remove(other);
    other.successorEpochs.remove(this);
  }

  /**
   * @param other
   * @return true if other is a predecessor of this epoch
   */
  public boolean isPredecessor(Epoch other) {
    return predecessorEpochs.contains(other);
  }

  /**
   * @param other the Epoch to add as a predecessor
   * @param locked true if the added successor should be locked
   * @return true if other epoch could be added (is not locked to another epoch)
   */
  public boolean addSuccessor(Epoch other, boolean locked) {
    if (isPredecessor(other) && !canRemovePredecessor(other)) {
      return false;
    }
    if (isCoincident(other) && !canRemoveCoincident(other)) {
      return false;
    }
    removePredecessor(other);
    removeCoincident(other);
    if (locked) {
      successorEpochs.addLocked(other);
      other.predecessorEpochs.addLocked(this);
    } else {
      successorEpochs.add(other);
      other.predecessorEpochs.add(this);
    }
    return true;
  }

  /**
   * @param other
   * @return true if the successor can be removed (is present and not locked)
   */
  public boolean canRemoveSuccessor(Epoch other) {
    return successorEpochs.contains(other) && !successorEpochs.isLocked(other);
  }

  /**
   * @param other the othger Epoch to remove
   */
  public void removeSuccessor(Epoch other) {
    successorEpochs.remove(other);
    other.predecessorEpochs.remove(this);
  }

  /**
   * @param other
   * @return true if other is a successor of this epoch
   */
  public boolean isSuccessor(Epoch other) {
    return successorEpochs.contains(other);
  }

  /**
   * @param other the other Epoch which is coincident with this Epoch
   * @param locked
   * @return true if other epoch could be added (is not locked to another epoch)
   */
  public boolean addCoincident(Epoch other, boolean locked) {
    if (isPredecessor(other) && !canRemovePredecessor(other)) {
      return false;
    }
    if (isSuccessor(other) && !canRemoveSuccessor(other)) {
      return false;
    }
    removePredecessor(other);
    removeSuccessor(other);
    if (locked) {
      coincidentEpochs.addLocked(other);
      other.coincidentEpochs.addLocked(this);
    } else {
      coincidentEpochs.add(other);
      other.coincidentEpochs.add(this);
    }
    return true;
  }

  /**
   * @param other
   * @return true if the coincident can be removed (is present and not locked)
   */
  public boolean canRemoveCoincident(Epoch other) {
    return coincidentEpochs.contains(other) && !coincidentEpochs.isLocked(other);
  }

  /**
   * @param other the other Epoch to remove
   */
  public void removeCoincident(Epoch other) {
    coincidentEpochs.remove(other);
    other.coincidentEpochs.remove(this);
  }

  /**
   * @param other
   * @return true if this Epoch is coincident with the other Epoch
   */
  public boolean isCoincident(Epoch other) {
    return coincidentEpochs.contains(other);
  }

  /**
   * @param tag
   * @param actionContext
   * @return an Element encoding this Epoch
   */
  public Element toXML(String tag, ActionContext actionContext) {
    Element element = new Element(tag);
    String id = actionContext.getRef(this);
    element.setAttribute(ATTR_ID, id);
    writeOthers(element, actionContext, TAG_SUCCESSOR, successorEpochs);
    writeOthers(element, actionContext, TAG_PREDECESSOR, predecessorEpochs);
    writeOthers(element, actionContext, TAG_COINCIDENT, coincidentEpochs);
    return element;
  }

  private void writeOthers(Element element, ActionContext actionContext, String tag, LockableSet others) {
    for (Epoch other : others) {
      Element otherElement = new Element(tag);
      otherElement.setAttribute(ATTR_REF, actionContext.getRef(other));
      otherElement.setAttribute(ATTR_LOCKED, String.valueOf(others.isLocked(other)));
      element.addContent(otherElement);
    }
  }

  /**
   * @param action
   * @param description
   * @param element
   * @param actionContext
   */
  public Epoch(AbstractAction action, String description, Element element, ActionContext actionContext) {
    this.action = action;
    this.description = description;
    readOthers(element, actionContext, TAG_SUCCESSOR, new OthersAccessor() {
      @Override
      public void add(Epoch epoch, boolean locked) {
        addSuccessor(epoch, locked);
      }
    });
    readOthers(element, actionContext, TAG_PREDECESSOR, new OthersAccessor() {
      @Override
      public void add(Epoch epoch, boolean locked) {
        addPredecessor(epoch, locked);
      }
    });
    readOthers(element, actionContext, TAG_COINCIDENT, new OthersAccessor() {
      @Override
      public void add(Epoch epoch, boolean locked) {
        addCoincident(epoch, locked);
      }
    });
  }

  private void readOthers(Element element, ActionContext actionContext, String tag, OthersAccessor othersAccessor) {
    @SuppressWarnings("unchecked")
    List<Element> children = element.getChildren(tag);
    for (Element otherElement : children) {
      String ref = otherElement.getAttributeValue(ATTR_REF);
      boolean locked = Boolean.valueOf(otherElement.getAttributeValue(ATTR_LOCKED));
      Epoch other = actionContext.getEpoch(ref);
      if (other != null) {
        othersAccessor.add(other, locked);
      }
    }
  }

  /**
   * @param epochIndex the epochIndex to set
   */
  public void setEpochIndex(int epochIndex) {
    this.epochIndex = epochIndex;
  }

  /**
   * @return the epochIndex
   */
  public int getEpochIndex() {
    return epochIndex;
  }

  /**
   * @return the action
   */
  public AbstractAction getAction() {
    return action;
  }
}
