---
title: Using Messaging Layer Security (MLS) to Provide Keys for SFrame
abbrev: MLS-SFrame
docname: draft-barnes-sframe-mls-latest
category: info

ipr: trust200902
area: Security
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -  ins: R. Barnes
    name: Richard Barnes
    organization: Cisco
    email: rlb@ipv.sx
 -  ins: R. Robert
    name: Raphael Robert
    organization: Wire
    email: raphael@wire.com

--- abstract

Secure Frames (SFrame) defines a compact scheme for encrypting real-time media.
In order for SFrame to address cases where media are exchanged among many
participants (e.g., real-time conferencing), it needs to be augmented with a
group key management protocol.  The Messaging Layer Security (MLS) protocol
provides continuous group authenticated key exchange, allowing a group of
participants in a media session to authenticate each other and agree on a group
key.  This document defines how the group keys produced by MLS can be used with
SFrame to secure real-time sessions for groups.

--- middle

# Introduction

Secure Frames (SFrame) defines a compact scheme for encrypting real-time media.
In order for SFrame to address cases where media are exchanged among many
participants (e.g., real-time conferencing), it needs to be augmented with a
group key management protocol.  The Messaging Layer Security (MLS) protocol
[!I-D.ietf-mls-protocol] provides continuous group authenticated key exchange.
MLS provides several important security properties [!I-D.ietf-mls-arch]:

* Group Key Exchange: All members of the group at a given time know a secret key
  that is inaccessible to parties outside the group.

* Authentication of group members: Each member of the group can authenticate the
  other members of the group.

* Group Agreement: The members of the group all agree on the identities of the
  participants in the group.

* Forward Secrecy: There are protocol events such that if a member's state is
  compromised after the event, group secrets created before the event are safe.

* Post-compromise Security: There are protocol events such that if a member's
  state is compromised before the event, the group secrets created after the
  event are safe.

When a real-time session uses MLS as the basis for SFrame keys, these security
properties apply to real-time media as well.  In the remainder of this document,
we define how to use the secrets produced by MLS to generate the keys required
by SFrame.

[[ OPEN ISSUE: We could define an MLS extension that would provide negotiation
of SFrame parameters, notably the ciphersuite and the value E defined below. ]]

# SFrame Key Management

MLS creates a linear sequence of keys, each of which is shared among the members
of a group at a given point in time.  When a member joins or leaves the group, a
new key is produced that is known only to the augmented or reduced group.  Each
step in the lifetime of the group is know as an "epoch", and each member of the
group is assigned an "index" that is constant for the time they are in the
group.

In SFrame, we derive per-sender `base\_key` values from the group secret for an
epoch, and use the KID field to signal the epoch and sender index.  First, we
use the MLS exporter to compute a shared SFrame secret for the epoch.

~~~~~
sframe_epoch_secret = MLS-Exporter("SFrame 10 MLS", "", AEAD.Nk)

sender_base_key[index] = HKDF-Expand(sframe_epoch_secret,
                           encode_big_endian(index, 4), AEAD.Nk)
~~~~~

The Key ID (KID) field in the SFrame header provides the epoch and index values
that are needed to generate the appropriate key from the MLS key schedule.

~~~~~
KID = (sender_index << E) + (epoch % (1 << E))
~~~~~

For compactness, do not send the whole epoch number.  Instead, we send only its
low-order E bits.  The participants in the group MUST agree on the value of E
for a given session, through some negotiation not specified here.

Note that E effectively defines a re-ordering window, since no more than 2^E
epoch can be active at a given time.  The better the participants are in sync
with regard to key roll-over, and the less reordering of SFrame-protected
payloads by the network, the fewer bits of epoch are necessary.

Receivers MUST be prepared for the epoch counter to roll over, removing an old
epoch when a new epoch with the same E lower bits is introduced.

Once an SFrame stack has been provisioned with the `sframe_epoch_secret` for an
epoch, it can compute the required KIDs and `sender_base_key` values on demand,
as it needs to encrypt/decrypt for a given member.

~~~~~
        ...
         |
Epoch 17 +--+-- index=33 -> KID = 0x211
         |  |
         |  +-- index=51 -> KID = 0x331
         |
         |
Epoch 16 +--+-- index=2 --> KID = 0x20
         |
         |
Epoch 15 +--+-- index=3 --> KID = 0x3f
         |  |
         |  +-- index=5 --> KID = 0x5f
         |
         |
Epoch 14 +--+-- index=3 --> KID = 0x3e
         |  |
         |  +-- index=7 --> KID = 0x7e
         |  |
         |  +-- index=20 -> KID = 0x14e
         |
        ...
~~~~~

MLS also provides an authenticated signing key pair for each participant.  When
SFrame uses signatures, these are the keys used to generate SFrame signatures.

# Security Considerations

The security properties provided by MLS are discussed in detail in
[!I-D.ietf-mls-arch] and [!I-D.ietf-mls-protocol].  This document extends those
guarantees to SFrame.

It should be noted that the per-sender keys derived here do not provide
per-sender authentication, since any member of the group could derive the same
keys (as indeed they must in order to decrypt the protected payload).
Per-sender keys are derived only to avoid nonce collision among multiple
unsynchronized senders.  So the authentication limitations of SFrame remain:
There is per-sender authentication only when signatures are used.  Otherwise,
SFrame only authenticates membership in the group, and members are free to
impersonate each other.

# IANA Considerations

This document makes no request of IANA.

--- back

# Acknowledgements

TODO
