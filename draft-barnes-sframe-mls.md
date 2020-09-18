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

TODO

--- middle


# Introduction

TODO

# SFrame Key Management

The Messaging Layer Security (MLS) protocol provides group authenticated key
exchange {{?I-D.ietf-mls-architecture}} {{?I-D.ietf-mls-protocol}}.  In
principle, it could be used to instantiate the sender key scheme above, but it
can also be used more efficiently directly.

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

For compactness, do not send the whole epoch number.  Instead, we send only its
low-order E bits.  Note that E effectively defines a re-ordering window, since
no more than 2^E epoch can be active at a given time.  Receivers MUST be
prepared for the epoch counter to roll over, removing an old epoch when a new
epoch with the same E lower bits is introduced.  (Sender indices cannot be
similarly compressed.)

~~~~~
KID = (sender_index << E) + (epoch % (1 << E))
~~~~~

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

TODO

# IANA Considerations

TODO

--- back

# Acknowledgements

TODO
