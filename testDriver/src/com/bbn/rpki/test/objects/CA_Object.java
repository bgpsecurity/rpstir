/*
 * Created on Nov 7, 2011
 */
package com.bbn.rpki.test.objects;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import com.bbn.rpki.test.actions.ActionManager;

/**
 * <Enter the description of this type here>
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
  /** sia directory path (ends with /) */
  public String SIA_path;
  /** cert common name */
  public String commonName;
  /** the certificate itself */
  private Certificate certificate;

  private int nextChildSN;
  final String bluePrintName;
  private final CA_Object parent;
  /**
   * @return the parent
   */
  public CA_Object getParent() {
    return parent;
  }

  final List<CA_Object> children = new ArrayList<CA_Object>();
  final List<Manifest> manifests = new ArrayList<Manifest>();
  final List<Roa> roas = new ArrayList<Roa>();
  final List<RevokedCertificate> revokedCertificates = new ArrayList<RevokedCertificate>();
  //  private final String manifest_path;
  private final int id;
  private final String nickName;
  private final String subjKeyFile;
  private int manNum = 0;
  private final int ttl;
  private final String serverName;
  private final boolean breakAway;
  /**
   * @param factoryBase
   * @param parent
   * @param id
   * @param subjKeyFile
   */
  public CA_Object(FactoryBase<CA_Object> factoryBase,
                   CA_Object parent,
                   int id,
                   String subjKeyFile,
                   int ttl,
                   String bluePrintName,
                   String serverName,
                   boolean breakAway) {
    this.nextChildSN = 0;
    this.ttl = ttl;
    this.bluePrintName = bluePrintName;
    this.nickName = bluePrintName + "-" + id;
    this.parent = parent;
    this.subjKeyFile = subjKeyFile;
    this.id = id;
    this.serverName = serverName;
    this.breakAway = breakAway;

    if (parent != null) {
      this.SIA_path = breakAway ? (getServerName() + "/" + nickName + "/") : (parent.SIA_path + nickName + "/");
      this.commonName = parent.commonName + "." + this.nickName;
    } else {
      this.commonName = this.nickName;
      this.SIA_path = getServerName() + "/" + nickName + "/";
    }

  }

  /**
   * @return the current certificate for this
   */
  public Certificate getCertificate() {
    if (modified) {
      if  (this.certificate != null) {
        if (!this.certificate.hasExpired()) {
          parent.revokeCertificate(this.certificate);
        }
        this.certificate = null;
      }
      if (hasResources()) {
        // Initialize our certificate
        if (parent != null) {
          String dirPath = REPO_PATH + parent.SIA_path;
          this.certificate = new CA_cert(parent,
                                         getTtl(),
                                         dirPath,
                                         nickName,
                                         SIA_path,
                                         getRcvdRanges(IPRangeType.as),
                                         getRcvdRanges(IPRangeType.ipv4),
                                         getRcvdRanges(IPRangeType.ipv6),
                                         this.subjKeyFile);
        } else {
          String dirPath = REPO_PATH + getServerName() + "/";
          this.certificate = new SS_cert(parent,
                                         getTtl(),
                                         SIA_path,
                                         nickName,
                                         dirPath,
                                         getRcvdRanges(IPRangeType.as),
                                         getRcvdRanges(IPRangeType.ipv4),
                                         getRcvdRanges(IPRangeType.ipv6),
                                         subjKeyFile);
        }
      } else {
        this.certificate = null;
      }
      setModified(false);
    }
    return this.certificate;
  }

  /**
   * @param certificate2
   */
  private void revokeCertificate(Certificate certificate) {
    revokedCertificates.add(new RevokedCertificate(certificate));
  }

  /**
   * @param pairs describe the addresses to take from the parent
   * @param allocationId
   */
  public void takeIPv4(List<? extends Pair> pairs, AllocationId allocationId) {
    IPRangeList allocation = parent.subAllocateIPv4(pairs);
    ActionManager.singleton().recordAllocation(parent, this, allocationId, allocation);
    this.addRcvdRanges(allocation);
  }

  /**
   * @param pairs describe the addresses to take from the parent
   * @param allocationId
   */
  public void takeIPv6(List<? extends Pair> pairs, AllocationId allocationId) {
    IPRangeList allocation = parent.subAllocateIPv6(pairs);
    ActionManager.singleton().recordAllocation(parent, this, allocationId, allocation);
    this.addRcvdRanges(allocation);
  }

  /**
   * @param pairs describe the addresses to take from the parent
   * @param allocationId
   */
  public void takeAS(List<? extends Pair> pairs, AllocationId allocationId) {
    IPRangeList allocation = parent.subAllocateAS(pairs);
    ActionManager.singleton().recordAllocation(parent, this, allocationId, allocation);
    this.addRcvdRanges(allocation);
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
    String dir_path = REPO_PATH + SIA_path;
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
      for (CA_Object obj : children) {
        obj.appendObjectsToWrite(list);
      }
      // Do this after processing children because a certificate may be revoked
      {
        Crl crl = new Crl(this);
        list.add(crl);
      }
      for (CA_Obj obj : manifests) {
        obj.appendObjectsToWrite(list);
        list.add(obj);
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
    return commonName;
  }

  /**
   * @return the nickName
   */
  public String getNickname() {
    return nickName;
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
    return commonName;
  }

  /**
   * @return the ttl
   */
  public int getTtl() {
    return ttl;
  }

  /**
   * @return the serverName
   */
  public String getServerName() {
    return serverName;
  }

  /**
   * @return
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
}
