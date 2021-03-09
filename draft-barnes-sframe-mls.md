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
    email: ietf@raphaelrobert.com

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

Secure Frames (SFrame) defines a compact scheme for encrypting real-time media
{{!I-D.omara-sframe}}.  In order for SFrame to address cases where media are
exchanged among many participants (e.g., real-time conferencing), it needs to be
augmented with a group key management protocol.  The Messaging Layer Security
(MLS) protocol {{!I-D.ietf-mls-protocol}} provides continuous group
authenticated key exchange.  MLS provides several important security properties
{{!I-D.ietf-mls-architecture}}:

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

# SFrame Parameter Negotiation

In order to interoperate, the sender and receiver(s) of an SFrame payload need
to agree on two parameters:

* The SFrame ciphersuite
* The number of bits `E` used to signal the epoch

These parameters can be negotiated in MLS using the `sframe_parameters`
extension.  An MLS participant advertises its supported ciphersuites in its
KeyPackage.  The creator of the group chooses the values of these parameters for
the group (possibly based on a set of KeyPackages) and advises them to new
joiners in Welcome messages.

```
uint16 SFrameCipherSuite;

struct {
  SFrameCipherSuite cipher_suites<0..255>;
} SFrameCapabilities;

struct {
  SFrameCipherSuite cipher_suite;
  uint8 epoch_bits;
} SFrameParameters;
```

The values allowed for `SFrameCipherSuite` are defined in {{!I-D.omara-sframe}}
and the IANA registries it references.

When an extension of type `sframe_parameters` appears in an MLS KeyPackage, the
extension data field MUST contain an SFrameCapabilities object.  When such an
extension appears in a Welcome message, it MUST contain an SFrameParameters
object.  The ciphersuite values MUST represent valid SFrame ciphersuites.

The SFrameParameters object for a group, if present, MUST be included in the
GroupContext for the group, as an extension of type `sframe_parameters`.  This
ensures that the members of the group agree on the SFrame parameters associated
to the group.

## SFrame Parameter Selection 

Just as with MLS ciphersuite selection, the creator of an MLS group chooses the
SFrame parameters to be used for the group.  The parameters are then fixed for
the lifetime of the group.

The creator of the group needs to choose a ciphersuite and an `epoch_bits`
value.  The ciphersuite SHOULD be chosen from among those supported by the
members of the group, as expressed by those members' key packages.  Members that
don't support the chosen ciphersuite will not be able to send or receive
SFrame-encrypted media.

As discussed below, the `epoch_bits` field effectively bounds the rate at which
the epoch can change, at the cost of possible growth in the KID field.
Applications SHOULD NOT use `epoch_bits = 0`, unless they have an external
signal for which epoch's keys are in use.  Otherwise, applications should choose
a value for `epoch_bits` such that they expect to never have more than
`2^epoch_bits` epochs active at once.  That is, by the time the key for epoch `k +
2^epoch_bits` is distributed, all senders should have stopped sending with epoch
`k`.

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
                           encode_big_endian(index, 8), AEAD.Nk)
~~~~~

[[ OPEN ISSUE: MLS has its own "secret tree" that provides better forward
secrecy properties within an epoch.  (This scheme provides none.)  An
alternative approach would be to re-use the MLS secret tree, either directly or
as a data structure. ]]

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

[[ OPEN ISSUE: There might be some considerations for new joiners.  Some trial
decryption might be necessary to detect whether you're in epoch N or in epoch N
+ 1 << E. ]]

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
{{!I-D.ietf-mls-architecture}} and {{!I-D.ietf-mls-protocol}}.  This document
extends those guarantees to SFrame.

It should be noted that the per-sender keys derived here do not provide
per-sender authentication, since any member of the group could derive the same
keys (as indeed they must in order to decrypt the protected payload).
Per-sender keys are derived only to avoid nonce collision among multiple
unsynchronized senders.  So the authentication limitations of SFrame remain:
There is per-sender authentication only when signatures are used.  Otherwise,
SFrame only authenticates membership in the group, and members are free to
impersonate each other.

The Forward Secrecy and Post-compromise Security guarantees provided by an MLS 
group extend to a group of call participants, as long as all members of the MLS 
group are participants in the call. It is recommended to keep the membership 
of the MLS group as tight as possible, i.e. members should only be added once 
they become call participants and evicted as soon as they drop off the call. 
If the application already uses MLS groups that are more long terme (e.g. chat 
groups), it is recommended to set up a new ephemeral MLS group for the call by 
using the sub-group branching mechanism provided by the MLS protocol to link the 
two groups cryptographically.

# IANA Considerations

This document requests that IANA add an entry to the MLS Extension Types
registry, with the following values:

| Value            | Name                     | Message(s) | Recommended | Reference |
|:=================|:=========================|:===========|:============|:==========|
| TBD              | sframe\_parameters       | KP, GI     | Y           | RFC XXXX  |

RFC EDITOR: Please replace XXXX throughout with the RFC number assigned to
this document.

--- back

# Acknowledgements

TODO
