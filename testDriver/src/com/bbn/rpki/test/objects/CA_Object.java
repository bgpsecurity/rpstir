/*
 * Created on Nov 7, 2011
 */
package com.bbn.rpki.test.objects;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.jdom.Element;

import com.bbn.rpki.test.actions.ActionManager;
import com.bbn.rpki.test.actions.XMLConstants;

/**
 * Represents the state of a particular CA in the testbed. At any moment, there
 * may be a current certificate reflecting allocations issued (and published) by another CA.
 * The validity period of the certificate is determined from the set of active allocations
 * received by this CA. The validity start time is the latest start time of any active allocation
 * and the validity end time is the earliest end time of any active allocation. If a new allocation
 * is "published", then in general, a new certificate must be published and the old certificate
 * revoked.
 * 
 * @author RTomlinson
 */
public class CA_Object extends Allocator {

  /**
   * Interface to be implemented when iteration over the tree.
   *
   * @author tomlinso
   */
  public interface IterationAction {
    /**
     * Implementation performs the desired action
     * @param caObject
     * @return true to continue the iteration
     */
    boolean performAction(CA_Object caObject);
  }
  /** the certificate itself */
  private Certificate certificate;

  private int nextChildSN;
  private final CA_Object parent;
  private final List<CA_Object> children = new ArrayList<CA_Object>();
  final List<Roa> roas = new ArrayList<Roa>();
  final List<RevokedCertificate> revokedCertificates = new ArrayList<RevokedCertificate>();
  private String nickName;
  private String subjKeyFile;
  private int manNum = 0;
  private String serverName;
  /**
   * @return the breakAway
   */
  public boolean isBreakAway() {
    return serverName != null;
  }

  private long validityStartTime;
  private long validityEndTime;
  /**
   * @param parent
   * @param nickname
   * @param serverName
   * @param subjKeyFile
   */
  public CA_Object(CA_Object parent,
                   String nickname,
                   String serverName,
                   String subjKeyFile) {
    this.nextChildSN = 0;
    setNickname(nickname);
    this.parent = parent;
    this.subjKeyFile = null;
    setServerName(serverName);
    this.subjKeyFile = subjKeyFile;
  }

  /**
   * Construct from XML
   * @param parent
   * @param element
   */
  public CA_Object(CA_Object parent, Element element) {
    this(parent,
         element.getAttributeValue(XMLConstants.ATTR_NICKNAME),
         element.getAttributeValue(XMLConstants.ATTR_SERVER_NAME),
         element.getAttributeValue(XMLConstants.ATTR_SUBJ_KEY_FILE));
    ActionManager.singleton().recordCA_Object(this);
    for (Element childElement : getChildren(element, XMLConstants.TAG_NODE)) {
      CA_Object childCA = new CA_Object(this, childElement);
      children.add(childCA);
    }
  }

  @SuppressWarnings("unchecked")
  private Collection<Element> getChildren(Element element, String tag) {
    return element.getChildren(tag);
  }

  /**
   * @return an element encoding this node
   */
  public Element toXML() {
    Element element = new Element(XMLConstants.TAG_NODE);
    element.setAttribute(XMLConstants.ATTR_NICKNAME, nickName);
    if (subjKeyFile != null) {
      element.setAttribute(XMLConstants.ATTR_SUBJ_KEY_FILE, subjKeyFile);
    }
    if (isBreakAway()) {
      element.setAttribute(XMLConstants.ATTR_SERVER_NAME, serverName);
    }
    for (CA_Object childCA : children) {
      Element childElement = childCA.toXML();
      element.addContent(childElement);
    }
    return element;
  }

  /**
   * @return the current certificate for this
   */
  public Certificate getCertificate() {
    if (isModified()) {
      if  (this.certificate != null) {
        if (!this.certificate.hasExpired()) {
          parent.revokedCertificates.add(new RevokedCertificate(this.certificate));
        }
        this.certificate = null;
      }
      if (hasResources()) {
        // Initialize our certificate
        if (parent != null) {
          String dirPath = REPO_PATH + parent.getSIA_path();
          this.certificate = new CA_cert(parent,
                                         validityStartTime,
                                         validityEndTime,
                                         dirPath,
                                         nickName,
                                         getSIA_path(),
                                         getRcvdRanges(IPRangeType.as),
                                         getRcvdRanges(IPRangeType.ipv4),
                                         getRcvdRanges(IPRangeType.ipv6),
                                         this.subjKeyFile);
        } else {
          String dirPath = REPO_PATH + getServerName() + "/";
          this.certificate = new SS_cert(parent,
                                         validityStartTime,
                                         validityEndTime,
                                         getSIA_path(),
                                         nickName,
                                         dirPath,
                                         getRcvdRanges(IPRangeType.as),
                                         getRcvdRanges(IPRangeType.ipv4),
                                         getRcvdRanges(IPRangeType.ipv6),
                                         subjKeyFile);
        }
        // Save this in case we need a new cert with the same key
        this.subjKeyFile = this.certificate.subjkeyfile;
      } else {
        this.certificate = null;
      }
      setModified(false);
    }
    return this.certificate;
  }

  /**
   * @return the parent
   */
  public CA_Object getParent() {
    return parent;
  }

  /**
   * @return the validityStartTime
   */
  public long getValidityStartTime() {
    return validityStartTime;
  }

  /**
   * @param validityStartTime the validityStartTime to set
   */
  public void setValidityStartTime(long validityStartTime) {
    this.validityStartTime = validityStartTime;
  }

  /**
   * @return the validityEndTime
   */
  public long getValidityEndTime() {
    return validityEndTime;
  }

  /**
   * @param validityEndTime the validityEndTime to set
   */
  public void setValidityEndTime(long validityEndTime) {
    this.validityEndTime = validityEndTime;
  }

  /**
   * Take an allocation from our parent according to the specified pairs and rangeType
   * 
   * @param pairs
   * @param rangeType
   * @param validityStartTime
   * @param validityEndTime
   * @param allocationId
   */
  public void takeAllocation(List<? extends Pair> pairs, IPRangeType rangeType,
                             long validityStartTime, long validityEndTime,
                             AllocationId allocationId) {
    IPRangeList allocation = parent.subAllocate(rangeType, pairs);
    addRcvdRanges(validityStartTime, validityEndTime, allocationId, allocation);
  }

  /**
   * @param validityStartTime
   * @param validityEndTime
   * @param allocationId
   * @param allocations
   */
  public void addRcvdRanges(long validityStartTime, long validityEndTime, AllocationId allocationId,
                            IPRangeList...allocations) {
    ActionManager.singleton().recordAllocation(parent, this, allocationId, allocations);
    for (IPRangeList allocation : allocations) {
      this.addRcvdRanges(allocation);
    }
    this.validityStartTime = validityStartTime;
    this.validityEndTime = validityEndTime;
  }

  /**
   * 
   * @param allocationId
   */
  public void returnAllocation(AllocationId allocationId) {
    for (IPRangeType rangeType : IPRangeType.values()) {
      IPRangeList allocation = ActionManager.singleton().findAllocation(parent, this, rangeType, allocationId);
      if (allocation != null) {
        removeRcvdRanges(allocation);
        parent.addFreeRanges(allocation);
      }
    }
  }

  /**
   * @return the next child serial number
   */
  public int getNextChildSN() {
    return this.nextChildSN++;
  }

  /**
   * Recursively find RPKI objects
   * @param list
   */
  public void appendObjectsToWrite(List<CA_Obj> list) {
    // Create the directory for the objects we're about to store
    String dir_path = REPO_PATH + getSIA_path();
    if (!new File(dir_path).isDirectory()) {
      new File(dir_path).mkdirs();
    }
    Certificate cert = getCertificate();
    if (cert != null) {
      list.add(cert);
      for (Roa obj : roas) {
        obj.appendObjectsToWrite(list);
        list.add(obj);
      }
      // Do this after processing children because a certificate may be revoked
      {
        Crl crl = new Crl(this);
        list.add(crl);
      }
      {
        Manifest manifest = new Manifest(this);
        manifest.appendObjectsToWrite(list);
        list.add(manifest);
      }
      for (CA_Object obj : children) {
        obj.appendObjectsToWrite(list);
      }
    } else {
      // no allocation so no cert, yet
    }
  }

  /**
   * @param path navigation down to requested descendant
   * @return the requested descendant
   */
  public CA_Object findNode(String...path) {
    return findNode(path, 0);
  }

  private CA_Object findNode(String[] path, int ix) {
    String name = path[ix];
    CA_Object foundChild = null;
    for (CA_Object child : children) {
      if (child.nickName.equals(name)) {
        foundChild = child;
        break;
      }
    }
    if (foundChild != null && ++ix < path.length) {
      foundChild = foundChild.findNode(path, ix);
    }
    return foundChild;
  }

  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return getCommonName();
  }

  /**
   * @return the nickName
   */
  public String getNickname() {
    return nickName;
  }

  /**
   * @param nickname
   */
  public void setNickname(String nickname) {
    this.nickName = nickname;
  }

  /**
   * @return the next manifest number
   */
  public int getNextManifestNumber() {
    return manNum++;
  }

  /**
   * @param action the action to perform on every CA_Object
   */
  public void iterate(IterationAction action) {
    action.performAction(this);
    for (CA_Object child : children) {
      child.iterate(action);
    }
  }

  /**
   * @return the number of children
   */
  public int getChildCount() {
    return children.size();
  }

  /**
   * @param index
   * @return the child at the specified index
   */
  public CA_Object getChild(int index) {
    return children.get(index);
  }

  /**
   * @param child
   * @return the index of the specified child
   */
  public int indexOf(Allocator child) {
    return children.indexOf(child);
  }

  /**
   * @return the common name
   */
  public String getCommonName() {
    if (parent != null) {
      return parent.getCommonName() + "." + nickName;
    }
    return nickName;
  }

  /**
   * @return the serverName
   */
  public String getServerName() {
    return isBreakAway() ? serverName : getParent().getServerName();
  }

  /**
   * @param serverName
   */
  public void setServerName(String serverName) {
    this.serverName = serverName;
  }

  /**
   * @return the list of revoked certificates
   */
  public List<RevokedCert> getRevokedCertList() {
    List<RevokedCert> ret = new ArrayList<RevokedCert>(revokedCertificates.size());
    for (Iterator<RevokedCertificate> it = revokedCertificates.iterator(); it.hasNext(); ) {
      RevokedCertificate revokedCertificate = it.next();
      Certificate cert = revokedCertificate.getCertificate();
      if (cert.hasExpired()) {
        it.remove();
      } else {
        ret.add(new RevokedCert(cert.serial, new Date(revokedCertificate.getRevocationTime())));
      }
    }
    return ret;
  }

  /**
   * @param child
   */
  public void addChild(CA_Object child) {
    children.add(child);
    assert child.getParent() == this;
  }

  /**
   * @param selectedCA
   */
  public void removeChild(CA_Object selectedCA) {
    children.remove(selectedCA);
  }

  /**
   * sia directory path (ends with /)
   * 
   * @return the sIA_path
   */
  public String getSIA_path() {
    if (parent != null) {
      return isBreakAway() ? (getServerName() + "/" + nickName + "/") : (parent.getSIA_path() + nickName + "/");
    } else {
      return getServerName() + "/" + nickName + "/";
    }

  }
}
