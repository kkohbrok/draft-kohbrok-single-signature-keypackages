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

This draft specifies modified versions of MLS KeyPackage messages, as well as
MLS PublicMessages and PrivateMessages holding Commits or Update Proposals that
require one less signature than their original counterparts.

--- middle

# Introduction

Both MLS KeyPackage messages, as well as PublicMessages and PrivateMessages
holding Commits and Update Proposals can be safely sent with one fewer signature
than specified in {{!RFC9420}}, although the latter two only if certain
conditions are met.

Regular MLS KeyPackages require two signatures: One over the LeafNode and one
over the KeyPackage around it. This draft introduced a LeafNode component that
contains a hash over the KeyPackage fields surrounding the LeafNode. As a
consequence, verifying the LeafNode also verifies the KeyPackage.

For Commits with an UpdatePath or Update Proposals (sent as PublicMessage or
PrivateMessage) the issue is similar: One signature covers the LeafNode and one
signature covers the majority of the struct that ends up being sent over the
wire. This draft proposes new types of PublicMessage and PrivateMessage with
only one signature, although the signature can only be ommitted for Commits that
contain an UpdatePath and for Commits and Update Proposals if the LeafNode
doesn't change the sender's signature public key.

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
    case mls_one_signature_key_package:
      OneSignatureKeyPackage key_package;
      OSPrivateMessage private_message;
      OSPublicMessage public_message;
  };
} MLSMessage;
~~~

See {{one-signature-keypackages}} for the definition of OneSignatureKeyPackage
and {{one-signature-commits-and-update-proposals}} for the definitions of
OSPrivateMessage and OSPublicMessage.

# One Signature KeyPackages

A OneSignatureKeyPackage (OSKP) functions much like a regular KeyPackage with
two exceptions: It lacks the signature around the outer KeyPackage and requires
a component inside the LeafNode that contains a hash of the KeyPackage around
the inner LeafNode.

Since both parsing and processing of an OSKP is different from that of a regular
KeyPackage, this document introduces a new WireFormat
`mls_one_signature_key_package` and extends the select statement in the
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
} OneSignatureKeyPackage
~~~

A OneSignatureKeyPackage is created and processed like a regular KeyPackage
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
OneSignatureKeyPackage using the hash function of the LeafNode's ciphersuite.

A KeyPackageCoreHash is only valid if two conditions are met.

- The `leaf_node_source` of the LeafNode is KeyPackage
- If the LeafNode is verified in the context of a OneSignatureKeyPackage, the
  `key_package_core_hash` is the hash of the `core` of that
  OneSignatureKeyPackage.

# One Signature Commits and Update Proposals

MLS PublicMessages and PrivateMessages carrying a Commit with UpdatePath or an
Update Proposal can also be created with only one signature as long as the
signature key of the sender is not changed by the respective operation. The
resulting structs are called OSPublicMessage and OSPrivateMessage respectively.

The principle behind saving the signature is the same as for OSKPs. The
signature over the whole struct is omitted and instead a hash over the otherwise
signed part of the struct (minus the LeafNode) is placed as a component in the
LeafNode of the UpdatePath or the Update Proposal.

The core change in framing an OSPublicMessage or OSPrivateMessage as compared to
its regular counterparts is that the FramedContentAuthData is replaced by the
OSFramedContentAuthData, where the latter lacks the signature that is part of
the former.

As a consequence, other framing structs also change slightly.

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
} OSFramedContentAuthData;

struct {
  WireFormat wire_format;
  FramedContent content;
  OSFramedContentAuthData auth;
} OSAuthenticatedContent;

struct {
  FramedContentTBS content_tbs;
  OSFramedContentAuthData auth;
} OSAuthenticatedContentTBM;

struct {
  select (PrivateMessage.content_type) {
    case application:
      opaque application_data<V>;

      case proposal:
        Proposal proposal;

      case commit:
        Commit commit;
  };

  OSFramedContentAuthData auth;
  opaque padding[length_of_padding];
} OSPrivateMessageContent;

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
} OSPublicMessage;
~~~

For both OSPublicMessages and OSPrivateMessages one of the following MUST be true:

- `content_type = commit` and the Commit contained within MUST have an UpdatePath
- `content_type = proposal` and `proposal_type = update`

For Commits and Update Proposals, the signature public key in the LeafNode MUST
be the same as the sender's current LeafNode. This MUST also be true for Commits
with `sender_type = new_member_commit` that contain a Remove Proposal targeting
the sender's original leaf.

Otherwise, creation and processing an OSPublicMessage or OSPrivateMessage is the
same as for regular PublicMessages or PrivateMessages, except that there is no
signature to verify in the OSFramedContentAuthData. However, the LeafNode (in
the UpdatePath if it's a commit or in the Update if it's a Proposal) MUST
contain an UpdateCoreHash component.

# Update core hash component

The UpdateCoreHash component ensures that the signature over the LeafNode covers
whatever the omitted signature would have covered.

~~~ tls
struct {
  opaque update_core_hash;
} UpdateCoreHash

struct {
  opaque group_id<V>;
    uint64 epoch;
    Sender sender;
    opaque authenticated_data<V>;

    ContentType content_type;
    select (FramedContent.content_type) {
      case proposal:
        ProposalType proposal_type;
      case commit:
        ProposalOrRef proposals<V>;
        UpdatePathNode nodes<V>;
      case application:
        struct {};
    };
} OutterFramedContent

struct {
  ProtocolVersion version = mls10;
  WireFormat wire_format;
  OutterFramedContent content;
  GroupContext context;
} OSFramedContentTBH
~~~

The `update_core_hash` MUST be a hash over the commit's TLS-serialized
OSFramedContentTBH using the hash function of the group's ciphersuite.

OSFramedContentTBH is the same as the FramedContentTBS struct defined in
{{!RFC9420}}, except that it always contains a GroupContext (because Commits and
Update Proposals only have `member` or `new_member_commit` as `sender_type`) and
that it contains an OutterFramedContent instead of a regular FramedContent.

OutterFramedContent in turn is the same as FramedContent except that, depending
on `content_type`, it either contains only content relevant to a Commit with an
UpdatePath or an Update Proposal. In both cases, it omits the actual LeafNode.
to prevent a circular dependency when computing the `update_core_hash` for
inclusion in said LeafNode.

# Security Considerations

Security considerations around the one signature variants are the same as
those of their regular MLS counterparts, except their content should not be
trusted until the signature of the LeafNode was verified and the
KeyPackageCoreHash or UpdateCoreHash component was validated.

# IANA Considerations

## Component Types

This document requests the addition of two new Component Types under the heading
of "Messaging Layer Security".

### KeyPackageCoreHash

The KeyPackageCoreHash component contains a hash over the outter parts of a
OneSignatureKeyPackage.

- Value: TBD (suggested value 0x0009)
- key_package_core_hash
- Where: LN
- Recommended: Y
- Reference: TBD

### UpdateCoreHash

The UpdateCoreHash component contains a hash over the parts of an
OSPublicMessage or OSPrivateMessage that would otherwise be covered by a
signature.

- Value: TBD (suggested value 0x000C)
- update_core_hash
- Where: LN
- Recommended: Y
- Reference: TBD

## WireFormat

This document requests the addition of two new WireFormats under the heading of
"Messaging Layer Security".

### MLSOneSignatureKeyPackage

The `mls_one_signature_key_package` allows saving the creation and
verification of a signature that is necessary when creating a regular
KeyPackage.

- Value: TBD
- Name: mls_one_signature_key_package
- Recommended: Y
- Reference: TBD

### MLSOneSignaturePrivateMessage

The `mls_one_signature_private_message` allows saving the creation and
verification of a signature that is necessary when creating a regular
PrivateMessage that either contains a Commit with an UpdatePath or an Update
Proposal.

- Value: TBD
- Name: mls_one_signature_private_message
- Recommended: Y
- Reference: TBD

### MLSOneSignaturePublicMessage

The `mls_one_signature_public_message` allows saving the creation and
verification of a signature that is necessary when creating a regular
PublicMessage that either contains a Commit with an UpdatePath or an Update
Proposal.

- Value: TBD
- Name: mls_one_signature_public_message
- Recommended: Y
- Reference: TBD

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
