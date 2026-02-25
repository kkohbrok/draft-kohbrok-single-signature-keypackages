---
title: "Fewer signatures in MLS"
abbrev: "FSMLS"
category: info

docname: draft-kohbrok-mls-fewer-signatures-latest
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
  latest: "https://kkohbrok.github.io/draft-kohbrok-single-signature-keypackages/draft-kohbrok-mls-fewer-signatures.html"

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

This draft specifies modified versions of MLS KeyPackages and Commits that
require one less signature than their original counterparts.

--- middle

# Introduction

Both MLS KeyPackages and MLS Commit messages can be safely sent with one fewer
signature than specified in {{!RFC9420}}.

Regular MLS KeyPackages require two signatures: One over the LeafNode and one
over the KeyPackage around it. This draft introduced a LeafNode component that
contains a hash over the KeyPackage fields surrounding the LeafNode. As a
consequence, verifying the LeafNode also verifies the KeyPackage.

For Commits with an UpdatePath the issue is similar: One signature covers the
LeafNode in the UpdatePath and one signature covers the majority of the struct
that ends up being sent over the wire. This draft proposes a new type of Commit
with only one signature, although here the signature can only be ommitted if the
Commit contains an UpdatePath and if the LeafNode in the UpdatePath doesn't
change the sender's signature public key.

Saving a signature can result in a significant decrease in computational or
bandwidth cost, especially in the context of PQ-secure signature schemes such as
ML-DSA, where signatures are multiple orders of magnitude larger than those of
most non-PQ signature schemes.

# New MLSMessage variants

This document specifies two new entries for the IANA WireFormat registry, which
results in the following changes to the MLSMessage struct as defined in
{{!RFC9420}}.

~~~ tls
struct {
  ...
  select (MLSMessage.wire_format) {
    ...
    case mls_single_signature_key_package:
        SingleSignatureKeyPackage key_package;
        SSPrivateMessage private_message;
        SSPublicMessage public_message;
  };
} MLSMessage;
~~~

See {{single-signature-keypackages}} for the definition of SingleSignatureKeyPackage and {{single-signature-commits}} for the definitions of SSPrivateMessage and SSPublicMessage.

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

## KeyPackage core hash component

~~~ tls
struct {
  opaque key_package_core_hash;
} KeyPackageCoreHash
~~~

The KeyPackageCoreHash can be created by hashing the TLS-serialized `core` of a
SingleSignatureKeyPackage using the hash function of the LeafNode's ciphersuite.

A KeyPackageCoreHash is only valid if two conditions are met.

- The `leaf_node_source` of the LeafNode is KeyPackage
- If the LeafNode is verified in the context of a SingleSignatureKeyPackage, the
  `key_package_core_hash` is the hash of the `core` of that
  SingleSignatureKeyPackage.

# Single Signature Commits

A single signature commit (SSC) is a commit with an UpdatePath that is sent as
either a PublicMessage or a PrivateMessage. The difference between an SSC and a
regular commit is the same as between an SSKP and a regular KeyPackage. The
signature over the whole struct is omitted and instead a hash over its outter
part is placed as acomponent in LeafNode of the UpdatePath.

One limitation of an SSC is that it only works if the signature public key in
the UpdatePath's LeafNode is the same as the signature public key in the
sender's current leaf. As such an SSC MUST NOT be constructed if that is the
case.

The core change for SSCs as compared to regular commits is that the
FramedContentAuthData is replaced by the SSFramedContentAuthData, where the
latter lacks the signature that is part of the former.

As a consequence, other framing struct change slightly with an SSPublicMessage
or SSPrivateMessage as the final struct.

~~~ tls
struct {
  select (FramedContent.content_type) {
    case commit:
      /*
        MAC(confirmation_key,
          GroupContext.confirmed_transcript_hash)
      */
      MAC confirmation_tag;
    case application:
    case proposal:
      struct{};
  };
} SSFramedContentAuthData;

struct {
  WireFormat wire_format;
  FramedContent content;
  SSFramedContentAuthData auth;
} SSAuthenticatedContent;

struct {
  FramedContentTBS content_tbs;
  SSFramedContentAuthData auth;
} SSAuthenticatedContentTBM;

struct {
  select (PrivateMessage.content_type) {
    case application:
      opaque application_data<V>;

      case proposal:
        Proposal proposal;

      case commit:
        Commit commit;
  };

  SSFramedContentAuthData auth;
  opaque padding[length_of_padding];
} PrivateMessageContent;

struct {
  FramedContent content;
  FramedContentAuthData auth;
  select (PublicMessage.content.sender.sender_type) {
      case member:
          MAC membership_tag;
      case external:
      case new_member_commit:
      case new_member_proposal:
          struct{};
  };
} SSPublicMessage;
~~~

Both SSPublicMessages and SSPrivateMessages MUST have `content_type = commit`
and the Commit contained within MUST have an UpdatePath. If the `sender_type` of
an SSPublicMessage is `member` or if it is `new_member_commit` and the commit is
a Resync, the LeafNode in the UpdatePath MUST NOT change the signature public
key of the sender.

Otherwise, creation and processing an SSPublicMessage or SSPrivateMessage is the
same as for regular PublicMessages or PrivateMessages, except that there is no
signature to verify in the SSFramedContentAuthData. However, the LeafNode in the
UpdatePath MUST contain a CommitCoreHash component in the UpdatePath's LeafNode.

~~~ tls
struct {
  opaque commit_core_hash;
} CommitCoreHash

struct {
  opaque group_id<V>;
    uint64 epoch;
    Sender sender;
    opaque authenticated_data<V>;

    ProposalOrRef proposals<V>;
    UpdatePathNode nodes<V>;
} OutterFramedContent

struct {
  ProtocolVersion version = mls10;
  WireFormat wire_format;
  OutterFramedContent content;
  GroupContect context;
} SSFramedContentTBH
~~~

The `commit_core_hash` MUST be a hash over the commit's TLS-serialized
SSFramedContentTBH using the hash function of the group's ciphersuite.

SSFramedContentTBH is the same as FramedContentTBS as defined in {{!RFC9420}},
except that it always contains a GroupContext (because commits only have
`member` or `new_member_commit` as `sender_type`) and that it contains an
OutterFrameContent instead of a regular FramedContent. OutterFramedContent is
the same as FramedContent except that it contains only content relevant to a
Commit with an UpdatePath and that it omits the UpdatePath's LeafNode. Omitting
the LeafNode prevents a circular dependency when computing the
`commit_core_hash` for inclusion in said LeafNode.

# Security Considerations

Security considerations around the single signature variants are the same as
those of their regular MLS counterparts, except their content should not be
trusted until the signature of the LeafNode was verified and the
KeyPackageCoreHash or CommitCoreHash component was validated.

# IANA Considerations

## Component Types

This document requests the addition of two new Component Types under the heading
of "Messaging Layer Security".

### KeyPackageCoreHash

The KeyPackageCoreHash component contains a hash over the outter parts of a
SingleSignatureKeyPackage.

- Value: TBD (suggested value 0x0009)
- key_package_core_hash
- Where: LN
- Recommended: Y
- Reference: TBD

### CommitCoreHash

The CommitCoreHash component contains a hash over the parts of an
SSPublicMessage or SSPrivateMessage that would otherwise be covered by a
signature.

- Value: TBD (suggested value 0x000C)
- commit_core_hash
- Where: LN
- Recommended: Y
- Reference: TBD

## WireFormat

This document requests the addition of two new WireFormats under the heading of
"Messaging Layer Security".

### MLSSingleSignatureKeyPackage

The `mls_single_signature_key_package` allows saving the creation and
verification of a signature that is necessary when creating a regular
KeyPackage.

- Value: TBD
- Name: mls_single_signature_key_package
- Recommended: Y
- Reference: TBD

### MLSSingleSignaturePrivateMessage

The `mls_single_signature_private_message` allows saving the creation and
verification of a signature that is necessary when creating a regular
PrivateMessage with a Commit that contains an UpdatePath.

- Value: TBD
- Name: mls_single_signature_private_message
- Recommended: Y
- Reference: TBD

### MLSSingleSignaturePublicMessage

The `mls_single_signature_public_message` allows saving the creation and
verification of a signature that is necessary when creating a regular
PublicMessage with a Commit that contains an UpdatePath.

- Value: TBD
- Name: mls_single_signature_public_message
- Recommended: Y
- Reference: TBD

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
