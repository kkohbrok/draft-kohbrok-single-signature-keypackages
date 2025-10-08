---
title: "Single Signature KeyPackages"
abbrev: "sskp"
category: info

docname: draft-mls-kohbrok-single-signature-keypackages-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Messaging Layer Security"
keyword:
 - mls
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "kkohbrok/draft-kohbrok-single-signature-keypackages"
  latest: "https://kkohbrok.github.io/draft-kohbrok-single-signature-keypackages/draft-mls-kohbrok-single-signature-keypackages.html"

author:
 -
    fullname: Raphael Robert
    organization: Phoenix R&D
    email: ietf@raphaelrobert.com
 -
    fullname: Konrad Kohbrok
    organization: Phoenix R&D
    email: konrad@ratchet.ing

normative:

informative:

...

--- abstract

TODO Abstract


--- middle

# Introduction

MLS KeyPackages require two signatures: One over the LeafNode and one over the
KeyPackage around it. This draft introduced a LeafNode component that contains a
hash over the KeyPackage fields surrounding the LeafNode. As a consequenve,
verifying the LeafNode also verifies the KeyPackage.

Saving a signature is significant, especially in the context of PQ-secure
signature schemes such as ML-DSA, where signatures are multiple orders of
magnitude larger than those of most non-PQ signature schemes.

# Single Signature KeyPackages

A SingleSignatureKeyPackage (SSKP) functions much like a regular KeyPackage with
two exceptions: It lacks the signature around the outer KeyPackage and requires
a component inside the LeafNode that contains a hash of the KeyPackage around
the inner LeafNode.

Since both parsing and processing of an SSKP is different from that of a regular
KeyPackage, this document introduces a new WireFormat
`mls_single_signature_key_package` and extends the select statement in the
definition of MLSMessage in Section 6 of {{!RFC9420}} as follows.

~~~ tls
struct {
  ...
  select (MLSMessage.wire_format) {
    ...
    case mls_single_signature_key_package:
        SingleSignatureKeyPackage key_package;
  };
} MLSMessage;

struct {
  ProtocolVersion version;
  CipherSuite cipher_suite;
  HPKEPublicKey init_key;
  Extension extensions<V>;
} KeyPackageCore

struct {
  KeyPackageCore core;
  LeafNode leaf_node;
} SingleSignatureKeyPackage
~~~

A SingleSignatureKeyPackage is created and processed like a regular KeyPackage
with the following exceptions.

- The signature around the outer KeyPackage is omitted upon creation
- As there is no signature around the outer KeyPackage, verification is skipped
  during verification
- The `app_data_dictionary` in the `leaf_node` must contain a valid
  KeyPackageCoreHash as defined in {{keypackage-core-hash-component}} under the
  `component_id` TBD.

The original purpose of the signature over the KeyPackage is now served by the
signature over the LeafNode, which by inclusion of the KeyPackageCoreHash
provides authenticity for both the LeafNode itself _and_ the KeyPackageCore
around it.

# KeyPackage core hash component

~~~ tls
struct {
  opaque key_package_core_hash;
} KeyPackageCoreHash
~~~

The KeyPackageCoreHashComponent can be created by hashing the TLS-serialized
`core` of a SingleSignatureKeyPackage using the hash function of the LeafNode's
ciphersuite.

A KeyPackageCoreHash is only valid if two conditions are met.

- The `leaf_node_source` of the LeafNode is KeyPackage
- If the LeafNode is verified in the context of a SingleSignatureKeyPackage, the
  `key_package_core_hash` is the hash of the `core` of that
  SingleSignatureKeyPackage.

# Security Considerations

Security considerations around SingleSignatureKeyPackages are the same as
regular KeyPackages, except that content of the KeyPackageCore should not be
trusted until the signature of the LeafNode was verified and the
KeyPackageCoreHash validated.

# IANA Considerations

## Component Type

This document requests the addition of a new Component Type under the heading of
"Messaging Layer Security".

- Value: TBD
- key_package_core_hash
- Where: LN
- Recommended: Y
- Reference: TBD


## WireFormat

This document requests the addition of a new WireFormat under the heading of
"Messaging Layer Security".

The `mls_single_signature_key_package` allows saving the creation and
verification of a signature that is necessary when creating a regular
KeyPackage.

- Value: TBD
- Name: mls_single_signature_key_package
- Recommended: Y
- Reference: TBD


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
