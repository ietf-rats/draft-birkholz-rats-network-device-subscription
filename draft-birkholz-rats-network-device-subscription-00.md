---
title: Attestation Event Stream Subscription
abbrev: RATS Subscription
docname: draft-birkholz-rats-network-device-subscription-00
wg: RATS Working Group
stand_alone: true
ipr: trust200902
area: Security
kw: Internet-Draft
cat: std
pi:
  toc: 'yes'
  sortrefs: 'yes'
  symrefs: 'yes'

author:
- ins: H. Birkholz
  name: Henk Birkholz
  org: Fraunhofer SIT
  abbrev: Fraunhofer SIT
  email: henk.birkholz@sit.fraunhofer.de
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- ins: E. Voit
  name: Eric Voit
  org: Cisco Systems, Inc.
  abbrev: Cisco
  email: evoit@cisco.com
- ins: W. Pan
  name: Wei Pan
  org: Huawei Technologies
  abbrev: Huawei
  street: 101 Software Avenue, Yuhuatai District
  city: Nanjing, Jiangsu
  region: ''
  code: '210012'
  country: China
  phone: ''
  email: william.panwei@huawei.com

normative:
  I-D.ietf-rats-architecture: rats-arch
  I-D.fedorkow-rats-network-device-attestation: device-attestation
  I-D.ietf-rats-yang-tpm-charra: rats-yang-tpm
  RFC8639:
  TPM2.0:
    author:
      org: TCG
    title: "TPM 2.0 Library Specification"
    target: https://trustedcomputinggroup.org/resource/tpm-library-specification/
    seriesinfo:

informative:
  I-D.birkholz-rats-tuda: TUDA
  KGV:
    author:
      org: TCG
    title: "KGV"
    date: 2003-10
    target: https://trustedcomputinggroup.org/wp-content/uploads/TCG-NetEq-Attestation-Workflow-Outline_v1r9b_pubrev.pdf
    seriesinfo:

--- abstract

This document defines how to subscribe to a stream of attestation related Evidence on
TPM-based network devices.

--- middle

# Introduction

{{-device-attestation}} and {{-rats-yang-tpm}} define the operational prerequisites and a YANG Model for the acquisition of Evidence from a TPM-based network device.  However, there is a limitation inherent in the challenge-response interaction models upon which these documents are based.  This limitation is that it is up to the Verifier to request Evidence.  The result is that the interval between the occurrence of a security event, and the event's visibility within the Relying Party can be unacceptably long.

This limitation results in two adverse effects:   

1. Evidence is not streamed to an interested Verifier as soon as it is generated.

2. If it were to be streamed, the Evidence is not appraisable for freshness.

This specification addresses the first adverse effect by enabling a Verifier to subscribe via {{RFC8639}} to a YANG \<attestation\> Event Stream which exists upon the Attester.  When subscribed, the Attester will continuously stream a subscribed set of Evidence to the Verifier.  

The second adverse effect results from the nonce based challenge-response of {{-rats-yang-tpm}}.  In that document, an Attester must wait for a new nonce from a Verifier before it generates a new TPM Quote.  In this case, the nonce acts as an implicit timestamp that a windows of freshness is tied to.  To address delays resulting from such a synchronous wait for nonce based Evidence generation, this specification enables freshness to be asserted in an asynchronous manner. 

By removing these two adverse effects, it becomes possible for a Verifier to continuously maintain an appraisal of the Attested device without relying on continuous polling. 

# Terminology

The following terms are imported from {{-rats-arch}}: Attester, Evidence, Relying Party, and Verifier.  Also imported are the time definitions time(vg), time(ns), time(eg), time(rg), and time(ra) from that document's appendices.  The following terms at imported from {{RFC8639}}: Event Stream, Subscription, Event Stream Filter, Dynamic Subscription.

## Requirements Notation

{::boilerplate bcp14}

# Operational Model

## Sequence Diagram

{{sequence}} below is a sequence diagram which updates Figure 5 of {{-device-attestation}}.  This sequence diagram replaces the {{-device-attestation}} challenge-response interaction model with an {{RFC8639}} Dynamic Subscription to an \<attestation\> Event Stream.  The contents of the \<attestation\> Event Stream are defined below within {{attestationstream}}.  

~~~~
.----------.                        .--------------------------.
| Attester |                        | Relying Party / Verifier |
'----------'                        '--------------------------'
   time(vg)                                              |
     |<---------establish-subscription(<attestation>)--time(ns)
     |                                                   |
   time(eg)                                              |
     |--filter(<tpm-extend>)---------------------------->|
     |--<tpm12-attestation> or <tpm20-attestation>------>|
     |                                                   |
     |                      verify time(eg) Evidence @ time(rg,ra)
     |                                                   |
     ~                                                   ~
   time(vg',eg')                                         |
     |--filter(<tpm-extend>)---------------------------->|
     |--<tpm12-attestation> or <tpm20-attestation>------>|
     |                                                   |
     |                     verify time(eg') Evidence @ time(rg',ra')


~~~~
{: #sequence title="YANG Subscription Model for Remote Attestation"}

* time(vg,rg,ra) are identical to the corresponding times from Figure 5 of {{-device-attestation}}.  

* time(rg',ra') are subsequent instances of the corresponding times from Figure 5 of {{-device-attestation}}.  

* time(ns): The Verifier generates a nonce and makes an {{RFC8639}} \<establish-subscription\> request.  This request also includes the augmentations defined in this document's YANG model.  Key subscription RPC parameters include:

  * the nonce,

  * a set of PCRs of interest which the Verifier wants to appraise, and

  * an optional filter which can reduce the logged events on the \<attestation\> stream pushed to the Verifier. 

* time(eg) – An initial response of Evidence is returned to the Verifier.  This includes:

  * a replay of filtered log entries which have extended into a PCR of interest since boot are sent in the \<tpm-extend\> notification, and a

  * a signed TPM quote that contains at least the PCRs from the \<establish-subscription\> RPC are included in a \<tpm12-attestation\> or \<tpm20-attestation\>).  This quote must have included the nonce provided at time(ns).

* time(vg',eg') – This occurs when a PCR is extended subsequent to time(eg).  Immediately after the extension, the following information needs to be pushed to the Verifier:   

  * Any values extended into a PCR of interest, and 

  * a signed TPM Quote showing the result the PCR extension.

## Continuously Verifying Freshness 

As there is no new Verifier nonce provided at time(eg'), it is important to validate the freshness of TPM Quotes which are delivered at that time.  The method of doing this verification will vary based on the capabilities of the TPM cryptoprocessor used. 

### TPM 1.2 Quote

The {{RFC8639}} notification format includes the \<eventTime\> object.  This can be used to determine the amount of time subsequent to the initial subscription each notification was sent.  However, this time is not part of the signed results which are returned from the Quote, and therefore is not trustworthy as objects returned in the Quote.  Therefore, a Verifier MUST periodically issue a new nonce, and receive this nonce within a TPM quote response in order to ensure the freshness of the results.  This can be done using the \<tpm12-challenge-response-attestation\> RPC from {{-rats-yang-tpm}}.

### TPM 2 Quote

When the Attester includes a TPM2 compliant cryptoprocessor, internal time-related counters are included within the signed TPM Quote.  By including an initial nonce in the {{RFC8639}} subscription request, fresh values for these counters are pushed as part of the first TPM Quote returned to the Verifier. Then, as shown by {{-TUDA}}, subsequent TPM Quotes delivered to the Verifier can the be appraised for freshness based on the predictable incrementing of these time-related counters.

The relevant internal time-related counters defined within {{TPM2.0}} can be seen within \<tpms-clock-info\>.   These counters include the \<clock\>, \<reset-counter\>, and \<restart-counter\> objects.  Normative rules for appraising these objects are as follows:

* If the \<clock\> has incremented for no more than the same duration as both the \<eventTime\> and the Verifier's internal time since the initial time(eg) and any previous time(eg'), then the TPM Quote MAY be considered fresh. Note that {{TPM2.0}} allows for +/- 15% clock drift.  However, many chips significantly improve on this maximum drift.  If available, chip specific maximum drifts SHOULD be considered during the appraisal process.

* If the \<reset-counter\>, \<restart-counter\> has incremented.  The existing subscription MUST be terminated, and a new \<establish-subscription\> SHOULD be generated.

* If a TPM Quote on any subscribed PCR has not been pushed to the Verifier for a duration of an Attester defined heartbeat interval, then a new TPM Quote notification SHOULD be sent to the Verifier.  This may often be the case, as certain PCRs might be infrequently updated.

~~~~
.----------.                        .--------------------------.
| Attester |                        | Relying Party / Verifier |
'----------'                        '--------------------------'
   time(vg',eg')                                         |
     |-<tpm20-attestation>------------------------------>|
     |                                    :              |
     ~                           Heartbeat interval      ~
     |                                    :              |
   time(eg')                              :              |
     |-<tpm20-attestation>------------------------------>|
     |                                                   |
~~~~

{: #attestationstream}
# Remote Attestation Event Stream

The \<remote-attestation\> Event Stream is an {{RFC8639}} complaint Event Stream which is defined within this section and within the YANG Module of {{-rats-yang-tpm}}.  This Event Stream contains YANG notifications which carry Evidence assisting a Verifier in the appraisal of an Attester. Data Nodes within {{configuring}} allow the configuration of this Event Stream’s contents on an Attester.

This \<remote-attestation\> Event Stream may only be exposed on Attesters supporting {{-device-attestation}}.  As with {{-device-attestation}}, it is up to the Verifier to understand which types of cryptoprocessors and keys are acceptable.

## Subscription to the \<attestation\> Event Stream

To establish a subscription to an Attester in a way which provides provably fresh Evidence, initial randomness must be provided to the Attester. This is done via the augmentation of a \<nonce-value\> into {{RFC8639}} the \<establish-subscription\> RPC.   Additionally, a Verifier must ask for PCRs of interest from a platform.  

~~~~
  augment /sn:establish-subscription/sn:input:
    +---w nonce-value    binary
    +---w pcr-index*     tpm:pcr
~~~~

The result of the subscription will be that passing of the following information:

1. \<tpm12-attestation\> and \<tpm20-attestation\> notifications which include the provided \<nonce-value\>.  These attestation notifications MUST at least include all the \<pcr-indicies\> requested in the RPC.

2. a series of \<tpm-extend\> notifications which reference the requested PCRs on all TPM based cryptoprocessors on the Attester.

3. \<tpm12-attestation\> and \<tpm20-attestation\> notifications generated within a few seconds of the \<tpm-extend\> notifications.  These attestation notifications MUST at least include any PCRs extended.

If the Verifier does not want to see the logged extend operations for all PCRs available from an Attester, an Event Stream Filter should be applied.  This filter will remove Evidence from any PCRs which are not interesting to the Verifier. 


## Replaying a history of previous TPM extend operations

Unless it is relying on Known Good Values, a Verifier will need to acquire a history of PCR extensions since the Attester has been booted.  This history may be requested from the Attester as part of the \<establish-subscription\> RPC.  This request is accomplished by placing a very old \<replay-start-time\> within the original RPC request.  As the very old \<replay-start-time\> will pre-date the time of Attester boot, a \<replay-start-time-revision\> will be returned in the \<establish-subscription\> RPC response, indicating when the Attester booted.  Immediately following the response (and before the notifications above)  one or more \<tpm-extend\> notifications which document all extend operations which have occurred for the requested PCRs since boot will be sent.  Many extend operations to a single PCR index on a single TPM SHOULD be included within a single notification.  

Note that if a Verifier has a partial history of extensions, the \<replay-start-time\> can be adjusted so that known extensions are not forwarded.

The end of this history replay will be indicated with the {{RFC8639}} \<replay-completed\> notification.  For more on this sequence, see Section 2.4.2.1 of {{RFC8639}}.

After the \<replay-complete\> notification is provided, a TPM Quote will be requested and the result passed to the Verifier via a \<tpm12-attestation\> and \<tpm20-attestation\> notification.  If there have been any additional extend operations which have changed a subscribed PCR value in this quote, these MUST be pushed to the Verifier before the \<tpm12-attestation\> and \<tpm20-attestation\> notification. 

At this point, the Verifier has sufficient Evidence to appraise the reported extend operations for each PCR, as well as compare the expected value of the PCR value against that signed by the TPM.


### TPM2 Heartbeat

For TPM2, every requested PCR MUST at least be sent once within a \<tpm20-attestation\> heartbeat interval.  This MAY be done with a single \<tpm20-attestation\> notification that includes all requested PCRs every heartbeat interval.  Alternatively, this MAY be done with several \<tpm20-attestation\> notifications at different times during that heartbeat interval. 

## YANG notifications placed on the \<attestation\> Event Stream

### tpm-extend

This notification documents when a single subscribed PCR is extended within a single TPM cryptoprocessor.  Corresponding notifications SHOULD be emitted no less than a \<marshalling-period\> after the PCR is first extended (the reason for the marshalling is that it is quite possible that multiple extensions to the same PCR have been made in quick succession).  A notification MUST be emitted prior to a \<tpm12-attestation\> or \<tpm20-attestation\> notification which has included and signed the results of any specific PCR extension.

~~~~
    +---n tpm-extend
       +--ro tpm-certificate-name?  string
       +--ro pcr-index-changed      tpm:pcr
       +--ro attested-event* []
          +--ro attested-event
             +--ro extended-with    binary
             +--ro event-type?      identityref
             +--ro event-details?   <anydata>
~~~~

Each \<tpm-extend\> MUST include one or more values being extended into the PCR.   These are conveyed within the \<extended-with\> object.  For each extension, details of the event MAY be provided within the \<event-details\> object.  
The format of any included \<event-details\> is identified by the \<event-type\>.  This document includes two YANG structures which may be inserted into the \<event-details\>.  These two structures are: \<ima-event-log\> and \<bios-event-log\>.  Implementations wanting to provide additional documentation of a type of PCR extension may choose to define additional YANG structures which can be placed into \<event-details\>.

Open question: do we need a notification correlator object to easily allow correlation on which extensions have been embodied within a specific attestation?


### tpm12-attestation

This notification type contains an instance of a TPM1.2 style signed cryptoprocessor measurement. This notification is generated at two points in time:

1. Upon initial subscription
2. Every time at least one subscribed PCR has changed from the directly previous \<tpm12-attestation\>. In this case, the notification SHOULD be emitted within a \<marshalling-period\> since a the first subscribed PCR changed.

This notification MUST NOT include the returned quote digest the results from any PCR extensions not previously reportable by a \<tpm-extend\>.

~~~~
    +---n tpm12-attestation {tpm:TPM12}?
       +--ro certificate-name?            string
       +--ro up-time?                     uint32
       +--ro node-id?                     string
       +--ro node-physical-index?         int32 {ietfhw:entity-mib}?
       +--ro fixed?                       binary
       +--ro external-data?               binary
       +--ro signature-size?              uint32
       +--ro signature?                   binary
       +--ro (tpm12-quote)
          +--:(tpm12-quote1)
          |  +--ro version* []
          |  |  +--ro major?      uint8
          |  |  +--ro minor?      uint8
          |  |  +--ro revMajor?   uint8
          |  |  +--ro revMinor?   uint8
          |  +--ro digest-value?          binary
          |  +--ro TPM_PCR_COMPOSITE* []
          |     +--ro pcr-index*         pcr
          |     +--ro value-size?        uint32
          |     +--ro tpm12-pcr-value*   binary
          +--:(tpm12-quote2)
             +--ro tag?                   uint8
             +--ro pcr-index*             pcr
             +--ro locality-at-release?   uint8
             +--ro digest-at-release?     binary
~~~~

All YANG objects above are defined within {{-rats-yang-tpm}}.  The objects MAY include Attester information such as \<tpm12-pcr-value\> which are not signed. The \<tpm12-attestation\> is not replayable.

### tpm20-attestation

This notification contains an instance of TPM2 style signed cryptoprocessor measurements. This notification is generated at three points in time:

1. Upon initial subscription
2. Every time at least one subscribed PCR has changed from the directly previous \<tpm20-attestation\>. In this case, the notification SHOULD be emitted within a \<marshalling-period\> since a the first subscribed PCR changed.
3. After a minimum heartbeat interval since a previous \<tpm20-attestation\> was sent. 

This notification MUST NOT include the returned \<quote\> the results from any PCR extensions not previously reportable by a \<tpm-extend\>.

~~~~
    +---n tpm20-attestation {tpm:TPM20}?
       +--ro certificate-name?           string
       +--ro up-time?                    uint32
       +--ro node-id?                    string
       +--ro node-physical-index?        int32 {ietfhw:entity-mib}?
       +--ro quote?                      binary
       +--ro quote-signature?            binary
       +--ro pcr-bank-values* []
       |  +--ro (algo-registry-type)
       |  |  +--:(tcg)
       |  |  |  +--ro TPM2_ALG_ID?            enumeration
       |  |  +--:(ietf)
       |  |     +--ro ietf-ni-hash-algo-id?   uint8
       |  +--ro pcr-values* [pcr-index]
       |     +--ro pcr-index    uint16
       |     +--ro pcr-value?   binary
       +--ro pcr-digest-algo-in-quote
          +--ro (algo-registry-type)
             +--:(tcg)
             |  +--ro TPM2_ALG_ID?            enumeration
             +--:(ietf)
                +--ro ietf-ni-hash-algo-id?   uint8

~~~~

All YANG objects above are defined within {{-rats-yang-tpm}}.   The objects MAY include Attester information such as \<pcr-bank-values\> which are not signed.   The \<tpm20-attestation\> is not replayable. 

## Filtering Evidence at the Attester

It can be useful *not* to receive all Evidence related to a PCR.  An example of this is would be a when a Verifier maintains Known Good Values of a PCR.  In this case, it is not necessary to send each extend operation.   

To accomplish this reduction, when an RFC8639 \<establish-subscription\> RPC is sent, a \<stream-filter\> as per RFC8639, Section 2.2 can be set to discard a \<tpm-extend\> notification when the \<pcr-index-changed\> is uninteresting to the verifier.   


## Replaying previous PCR Extend events

To verify the value of a PCR, a Verifier must either know that the value is a Known Good Value {{KGV}} or be able to reconstruct the hash value by viewing all the PCR-Extends since the Attester rebooted. Wherever a hash reconstruction might be needed, the \<remote-attestation\> Event Stream MUST support the RFC8639 \<replay\> feature. Through the \<replay\> feature, it is possible for a Verifier to retrieve and sequentially hash all of the PCR extending events since an Attester booted. And thus, the Verifier has access to all the evidence needed to verify a PCR’s current value.



{: #configuring title="Configuring the Attestation Stream"}
## Configuring the \<attestation\> Event Stream

{{attestationconfig}} is tree diagram which exposes the operator configurable elements of the \<remote-attestation\> Event Stream. This allows an Attester to select what information should be available on the stream. A fetch operation also allows an external device such as a Verifier to understand the current configuration of stream.

Almost all YANG objects below are defined via reference from {{-rats-yang-tpm}}. There is one object which is new with this model however. \<tpm2-heartbeat\> defines the maximum amount of time which should pass before a subscriber to the Event Stream should get a \<tpm20-attestation\> notification from devices which contain a TPM2.

~~~~
  +--rw rats-support-structures
    +--rw rats-support-structures
     +--rw supported-algos*                          uint16
     +--rw tpms* [tpm-name]
     |  +--rw tpm-name                      string
     |  +--rw tras:leafref-to-keystore?     string
     |  +--rw (tras:subscribable)?
     |     +--:(tras:tpm12-stream) {tpm:TPM12}?
     |     |  +--rw tras:tpm12-pcr-index*   tpm:pcr
     |     +--:(tras:tpm20-stream) {tpm:TPM20}?
     |        +--rw tras:tpm20-pcr-index*   tpm:pcr
     +--rw tras:marshalling-period?                  uint8
     +--rw tras:tpm12-subscribed-signature-scheme?
     |       -> ../tpm:supported-algos {tpm:TPM12}?
     +--rw tras:tpm20-subscribed-signature-scheme?
     |       -> ../tpm:supported-algos {tpm:TPM20}?
     +--rw tras:tpm20-subscription-heartbeat?        uint16
             {tpm:TPM20}?

~~~~
{: #attestationconfig title="Configuring the Attestation Stream"}


{: #YANG-Module} 
# YANG Module

This YANG module imports modules from {{-rats-yang-tpm}} and {{RFC8639}}.  It is also work-in-progress.


~~~~ YANG
<CODE BEGINS> ietf-tpm-remote-attestation-stream@2020-06-10.yang
{::include /media/sf_rats/ietf-tpm-remote-attestation-stream.yang}
<CODE ENDS>
~~~~ 

# Security Considerations

To be written.

# IANA Considerations {#IANA}

To be written.

--- back

# Known Issues
{: numbered="no"}

* The hash algorithms need to be changed from strings to enumerations in the base charra YANG model.

# Acknowledgements
{: numbered="no"}

Thanks to ...
