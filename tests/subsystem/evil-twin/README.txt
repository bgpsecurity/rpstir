This directory contains tests for vulnerabilities to the "evil twin"
attack.

The goal of the evil twin attack is to make a good object look bad.
The malicious CA signs and publishes a certificate that reuses the
public key, subject, and SKI from a victim certificate.  This new
certificate (the "evil twin" certificate) is either:

  * invalid because it uses resources not held by the malicious CA, or

  * valid but not a valid parent of the objects signed by the victim
    certificate because the objects signed by the victim certificate
    have resources outside of the evil twin certificate.

Either way, if the RP software is buggy and considers the evil twin to
be the parent of objects that were actually signed by the victim
(because the subject, SKI, and public keys match), those good objects
would be incorrectly invalidated.

The test scripts in this directory use different toy hierarchies to
cover a wide range of scenarios.
