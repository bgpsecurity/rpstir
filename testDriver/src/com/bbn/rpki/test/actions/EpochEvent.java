/*
 * Created on Feb 13, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.AbstractSet;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.jdom.Element;

import com.bbn.rpki.test.tasks.Epoch;

/**
 * Identifies an Epoch for corresponding to a particular point time such as
 * when (the certificate containing) a particular allocation becomes valid.
 * Epochs may be ordered relative to other epochs: before, after and coincident.
 * Epochs are "named" such that other epochs can be identified for the purpose
 * of establishing these orderings.
 *
 * @author tomlinso
 */
public final class EpochEvent implements XMLConstants {

  interface OthersAccessor {
    void add(EpochEvent epochEvent, EpochEvent other, boolean locked);
  }

  private static final OthersAccessor successorAccessor = new OthersAccessor() {
    @Override
    public void add(EpochEvent epochEvent, EpochEvent otherEvent, boolean locked) {
      epochEvent.addSuccessor(otherEvent, locked);
    }
  };

  private static final OthersAccessor predecessorAccessor = new OthersAccessor() {
    @Override
    public void add(EpochEvent epochEvent, EpochEvent otherEvent, boolean locked) {
      epochEvent.addPredecessor(otherEvent, locked);
    }
  };

  private static final OthersAccessor coincidentAccessor = new OthersAccessor() {
    @Override
    public void add(EpochEvent epochEvent, EpochEvent otherEvent, boolean locked) {
      epochEvent.addCoincident(otherEvent, locked);
    }
  };

  private final AbstractAction action;
  private final String name;
  private Epoch epoch = null;

  /**
   * @param action
   * @param name
   */
  public EpochEvent(AbstractAction action, String name) {
    this.action = action;
    this.name = name;
  }

  private class LockableSet extends AbstractSet<EpochEvent> {
    private final Set<EpochEvent> locked = new HashSet<EpochEvent>();
    private final Set<EpochEvent> unlocked = new HashSet<EpochEvent>();
    /**
     * @see java.util.AbstractCollection#iterator()
     */
    @Override
    public Iterator<EpochEvent> iterator() {
      return new Iterator<EpochEvent>() {
        private final Iterator<EpochEvent> lockedIterator = locked.iterator();
        private final Iterator<EpochEvent> unlockedIterator = unlocked.iterator();

        @Override
        public boolean hasNext() {
          return lockedIterator.hasNext() || unlockedIterator.hasNext();
        }

        @Override
        public EpochEvent next() {
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
    public boolean add(EpochEvent e) {
      return unlocked.add(e);
    }

    public boolean addLocked(EpochEvent e) {
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
    public boolean addAll(Collection<? extends EpochEvent> c) {
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
    public boolean isLocked(EpochEvent other) {
      return locked.contains(other);
    }
  }

  private final LockableSet predecessorEpochs = new LockableSet();
  private final LockableSet successorEpochs = new LockableSet();
  private final LockableSet coincidentEpochs = new LockableSet();

  /**
   * @return a description suitable for a combo box
   */
  public String getName() {
    return name;
  }

  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return getName() + (action == null ? "" : action.getId());
  }

  /**
   * @return the predecessors
   */
  public Collection<EpochEvent> getPredecessorEpochEvents() {
    return predecessorEpochs;
  }

  /**
   * @return the successors
   */
  public Collection<EpochEvent> getSuccessorEpochEvents() {
    return successorEpochs;
  }

  /**
   * @return the coincident
   */
  public Collection<EpochEvent> getCoincidentEpochs() {
    return coincidentEpochs;
  }

  /**
   * Find all epochs that must follow this one. This includes all direct successors of this epoch
   * plus those that are constrained to follow the successors or those that are coincident with any
   * successor.
   * @return all epochs constrained to follow this one
   */
  public Set<EpochEvent> findSuccessorEpochs() {
    Set<EpochEvent> visited = new HashSet<EpochEvent>();
    Set<EpochEvent> ret = new HashSet<EpochEvent>();
    findSuccessorEpochs(ret, visited);
    return ret;
  }

  private void findSuccessorEpochs(Set<EpochEvent> ret, Set<EpochEvent> visited) {
    if (visited.add(this)) {
      ret.addAll(successorEpochs);
      HashSet<EpochEvent> visited2 = new HashSet<EpochEvent>(visited);
      HashSet<EpochEvent> visited3 = new HashSet<EpochEvent>(visited);
      for (EpochEvent successor : successorEpochs) {
        successor.findSuccessorEpochs(ret, visited2);
        successor.findCoincidentEpochs(ret, visited);
      }
      for (EpochEvent coincident : coincidentEpochs) {
        coincident.findSuccessorEpochs(ret, visited3);
      }
    }
  }

  /**
   * @return all epochs constrained to precede this one
   */
  public Set<EpochEvent> findPredecessorEpochs() {
    Set<EpochEvent> visited = new HashSet<EpochEvent>();
    Set<EpochEvent> ret = new HashSet<EpochEvent>();
    findPredecessorEpochs(ret, visited);
    return ret;
  }

  private void findPredecessorEpochs(Set<EpochEvent> ret, Set<EpochEvent> visited) {
    if (visited.add(this)) {
      ret.addAll(predecessorEpochs);
      HashSet<EpochEvent> visited2 = new HashSet<EpochEvent>(visited);
      HashSet<EpochEvent> visited3 = new HashSet<EpochEvent>(visited);
      for (EpochEvent predecessor : predecessorEpochs) {
        predecessor.findPredecessorEpochs(ret, visited2);
        predecessor.findCoincidentEpochs(ret, visited);
      }
      for (EpochEvent coincident : coincidentEpochs) {
        coincident.findPredecessorEpochs(ret, visited3);
      }
    }
  }

  /**
   * @return all epochs coincident with this one
   */
  public Set<EpochEvent> findCoincidentEpochs() {
    Set<EpochEvent> visited = new HashSet<EpochEvent>();
    Set<EpochEvent> ret = new HashSet<EpochEvent>();
    findCoincidentEpochs(ret, visited);
    return ret;
  }

  private void findCoincidentEpochs(Set<EpochEvent> ret, Set<EpochEvent> visited) {
    if (visited.add(this)) {
      ret.addAll(coincidentEpochs);
      for (EpochEvent coincident : coincidentEpochs) {
        coincident.findCoincidentEpochs(ret, visited);
      }
    }
  }

  /**
   * @param other the Epoch to add as a predecessor
   * @param locked
   * @return true if other epoch could be added (is not locked to another epoch)
   */
  public boolean addPredecessor(EpochEvent other, boolean locked) {
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
  public boolean canRemovePredecessor(EpochEvent other) {
    return predecessorEpochs.contains(other) && !predecessorEpochs.isLocked(other);
  }

  /**
   * @param other the other Epoch to remove
   */
  public void removePredecessor(EpochEvent other) {
    predecessorEpochs.remove(other);
    other.successorEpochs.remove(this);
  }

  /**
   * @param other
   * @return true if other is a predecessor of this epoch
   */
  public boolean isPredecessor(EpochEvent other) {
    return predecessorEpochs.contains(other);
  }

  /**
   * @param other the Epoch to add as a predecessor
   * @param locked true if the added successor should be locked
   * @return true if other epoch could be added (is not locked to another epoch)
   */
  public boolean addSuccessor(EpochEvent other, boolean locked) {
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
  public boolean canRemoveSuccessor(EpochEvent other) {
    return successorEpochs.contains(other) && !successorEpochs.isLocked(other);
  }

  /**
   * @param other the othger Epoch to remove
   */
  public void removeSuccessor(EpochEvent other) {
    successorEpochs.remove(other);
    other.predecessorEpochs.remove(this);
  }

  /**
   * @param other
   * @return true if other is a successor of this epoch
   */
  public boolean isSuccessor(EpochEvent other) {
    return successorEpochs.contains(other);
  }

  /**
   * @param other the other Epoch which is coincident with this Epoch
   * @param locked
   * @return true if other epoch could be added (is not locked to another epoch)
   */
  public boolean addCoincident(EpochEvent other, boolean locked) {
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
  public boolean canRemoveCoincident(EpochEvent other) {
    return coincidentEpochs.contains(other) && !coincidentEpochs.isLocked(other);
  }

  /**
   * @param other the other Epoch to remove
   */
  public void removeCoincident(EpochEvent other) {
    coincidentEpochs.remove(other);
    other.coincidentEpochs.remove(this);
  }

  /**
   * @param other
   * @return true if this Epoch is coincident with the other Epoch
   */
  public boolean isCoincident(EpochEvent other) {
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
    for (EpochEvent other : others) {
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
  public EpochEvent(AbstractAction action, String description, Element element, ActionContext actionContext) {
    this.action = action;
    this.name = description;
    String id = element.getAttributeValue(ATTR_ID);
    actionContext.registerEpochEvent(this, id);
    OthersAccessor othersAccessor;
    for (Element child : children(element)) {
      String tag = child.getName();
      String ref = child.getAttributeValue(ATTR_REF);
      boolean locked = Boolean.valueOf(child.getAttributeValue(ATTR_LOCKED));
      EpochEvent other = actionContext.getEpochEvent(ref);
      if (other != null) {
        if (TAG_SUCCESSOR.equals(tag)) {
          othersAccessor = successorAccessor;
        } else if (TAG_PREDECESSOR.equals(tag)) {
          othersAccessor = predecessorAccessor;
        } else if (TAG_COINCIDENT.equals(tag)) {
          othersAccessor = coincidentAccessor;
        } else {
          continue;
        }
        othersAccessor.add(this, other, locked);
      }
    }
  }

  @SuppressWarnings("unchecked")
  private Iterable<Element> children(Element element) {
    return element.getChildren();
  }

  /**
   * @return the action
   */
  public AbstractAction getAction() {
    return action;
  }

  /**
   * @return the epoch
   */
  public Epoch getEpoch() {
    return epoch;
  }

  /**
   * @param epoch the epoch to set
   */
  public void setEpoch(Epoch epoch) {
    this.epoch = epoch;
  }
}
