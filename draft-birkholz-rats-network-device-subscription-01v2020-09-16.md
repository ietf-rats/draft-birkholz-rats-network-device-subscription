---
title: Attestation Event Stream Subscription
abbrev: RATS Subscription
docname: draft-birkholz-rats-network-device-subscription-01
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
  I-D.ietf-rats-tpm-based-network-device-attest: device-attestation
  I-D.ietf-rats-yang-tpm-charra: rats-yang-tpm
  I-D.ietf-rats-reference-interaction-models: reference-interactions
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

This document defines how to subscribe to an Event Stream of attestation related Evidence on TPM-based network devices.

--- middle

# Introduction

{{-device-attestation}} and {{-rats-yang-tpm}} define the operational prerequisites and a YANG Model for the acquisition of Evidence from a TPM-based network device.  However, there is a limitation inherent in the challenge-response interaction models upon which these documents are based. This limitation is that it is up to the Verifier to request Evidence.  The result is that the interval between the occurrence of a security event, and the event's visibility within the Relying Party can be unacceptably long.  

This limitation results in two adverse effects:

1. Evidence is not streamed to an interested Verifier as soon as it is generated.

2. If it were to be streamed, the Evidence is not appraisable for freshness.

This specification addresses the first adverse effect by enabling a Verifier to subscribe via {{RFC8639}} to an \<attestation\> Event Stream which exists upon the Attester.  When subscribed, the Attester will continuously stream a requested set of Evidence to the Verifier.  

The second adverse effect results from the challenge-response interaction of {{-rats-yang-tpm}} being nonce-based. In {{-rats-yang-tpm}} an Attester must wait for a new nonce provided by a Verifier before it can generate a new TPM Quote.  To address delays resulting from such a wait, this specification enables evidence freshness to be asserted asynchronously. 

By removing these two adverse effects, it becomes possible for a Verifier to continuously maintain an appraisal of the Attested device without relying on continuous polling. 

# Terminology

The following terms are imported from {{-rats-arch}}: Attester, Evidence, Relying Party, and Verifier.  Also imported are the time definitions time(VG), time(NS), time(EG), time(RG), and time(RA) from that document's Appendix A.  The following terms at imported from {{RFC8639}}: Event Stream, Subscription, Event Stream Filter, Dynamic Subscription.

## Requirements Notation

{::boilerplate bcp14}

# Operational Model

## Sequence Diagram

{{sequence}} below is a sequence diagram which updates Figure 5 of {{-device-attestation}} based on the Streamed Attestation model defined in {{-reference-interactions}}.  This sequence diagram replaces the {{-device-attestation}} challenge-response interaction model with an {{RFC8639}} Dynamic Subscription to an \<attestation\> Event Stream.  The contents of the \<attestation\> Event Stream are defined below within {{attestationstream}}.  

~~~~
.----------.                        .--------------------------.
| Attester |                        | Relying Party / Verifier |
'----------'                        '--------------------------'
   time(VG)                                              |
     |<---------establish-subscription(<attestation>)--time(NS)
     |                                                   |
   time(EG)                                              |
     |--filter(<pcr-extend>)---------------------------->|
     |--<tpm12-attestation> or <tpm20-attestation>------>|
     |                                                   |
     |                      verify time(EG) Evidence @ time(RG,RA)
     |                                                   |
     ~                                                   ~
   time(VG',EG')                                         |
     |--filter(<pcr-extend>)---------------------------->|
     |--<tpm12-attestation> or <tpm20-attestation>------>|
     |                                                   |
     |                     verify time(EG') Evidence @ time(RG',RA')


~~~~
{: #sequence title="YANG Subscription Model for Remote Attestation"}

* time(VG,RG,RA) are identical to the corresponding times from Figure 5 of {{-device-attestation}}.  

* time(RG',RA') are subsequent instances of the corresponding times from Figure 5 of {{-device-attestation}}.  

* time(NS): The Verifier generates a nonce and makes an {{RFC8639}} \<establish-subscription\> request.  This request also includes the augmentations defined in this document's YANG model.  Key subscription RPC parameters include:

  * the nonce

  * a set of PCRs of interest which the Verifier wants to appraise

  * an optional filter which can reduce the logged events on the \<attestation\> stream pushed to the Verifier. 

* time(EG) – An initial response of Evidence is returned to the Verifier.  This includes:

  * A replay of filtered log entries which have extended into a PCR of interest since boot are sent in the \<pcr-extend\> notification.  

  * A signed TPM quote that contains at least the PCRs from the \<establish-subscription\> RPC are included in a \<tpm12-attestation\> or \<tpm20-attestation\>).  This quote must have included the nonce provided at time(NS).

* time(VG',EG') – This occurs when a PCR is extended subsequent to time(EG).  Immediately after the extension, the following information needs to be pushed to the Verifier:   

  * Any values extended into a PCR of interest, and 

  * a signed TPM Quote showing the result the PCR extension.

## Continuously Verifying Freshness 

As there is no new Verifier nonce provided at time(EG'), it is important to validate the freshness of TPM Quotes which are delivered at that time.  The method of doing this verification will vary based on the capabilities of the TPM cryptoprocessor used. 

### TPM 1.2 Quote

The {{RFC8639}} notification format includes the \<eventTime\> object.  This can be used to determine the amount of time subsequent to the initial subscription each notification was sent.  However, this time is not part of the signed results which are returned from the Quote, and therefore is not trustworthy as objects returned in the Quote.  In consequence, a Verifier MUST periodically issue a new nonce, and receive this nonce within a TPM quote response in order to ensure the freshness of the results.  A new nonce is provided to the Verifier using the \<tpm12-challenge-response-attestation\> RPC from {{-rats-yang-tpm}}.

### TPM 2 Quote

When an Attester includes a TPM2 compliant cryptoprocessor, internal time-related counters are included within a signed TPM Quote.  By including an initial nonce in the {{RFC8639}} subscription request, fresh values for these counters are pushed as part of the first TPM Quote returned to the Verifier. As shown by {{-TUDA}}, subsequent TPM Quotes delivered to the Verifier can the be appraised for freshness based on the predictable increments of these time-related counters.

The relevant internal time-related counters defined within {{TPM2.0}} can be seen within \<tpms-clock-info\>.   These counters include the \<clock\>, \<reset-counter\>, and \<restart-counter\> objects.  The rules for appraising these objects are as follows:

* If the \<clock\> has incremented for no more than the same duration as both the \<eventTime\> and the Verifier's internal time since the initial time(EG) and any previous time(EG'), then the TPM Quote may be considered fresh. Note that {{TPM2.0}} allows for +/- 15% clock drift.  However many chips significantly improve on this maximum drift.  If available, chip specific maximum drifts SHOULD be considered during the appraisal process.

* If the \<reset-counter\>, \<restart-counter\> has incremented.  The existing subscription MUST be terminated, and a new \<establish-subscription\> SHOULD be generated.

* If a TPM Quote on any subscribed PCR has not been pushed to the Verifier for a duration of an Attester defined heartbeat interval, then a new TPM Quote notification should be sent to the Verifier.  This may often be the case, as certain PCRs might be infrequently updated.

~~~~
.----------.                        .--------------------------.
| Attester |                        | Relying Party / Verifier |
'----------'                        '--------------------------'
   time(VG',EG')                                         |
     |-<tpm20-attestation>------------------------------>|
     |                                    :              |
     ~                           Heartbeat interval      ~
     |                                    :              |
   time(EG')                              :              |
     |-<tpm20-attestation>------------------------------>|
     |                                                   |
~~~~


{: #attestationstream}
# Remote Attestation Event Stream

The \<attestation\> Event Stream is an {{RFC8639}} complaint Event Stream which is defined within this section and within the YANG Module of {{-rats-yang-tpm}}. This Event Stream contains YANG notifications which carry Evidence which assists a Verifier in appraising the Trustworthiness Level of an Attester. Data Nodes within {{configuring}} allow the configuration of this Event Stream’s contents on an Attester.

This \<attestation\> Event Stream may only be exposed on Attesters supporting {{-device-attestation}}.  As with {{-device-attestation}}, it is up to the Verifier to understand which types of cryptoprocessors and keys are acceptable.

## Subscription to the \<attestation\> Event Stream

To establish a subscription to an Attester in a way which provides provably fresh Evidence, initial randomness must be provided to the Attester. This is done via the augmentation of a \<nonce-value\> into {{RFC8639}} the \<establish-subscription\> RPC.   Additionally, a Verifier must ask for PCRs of interest from a platform.  

~~~~
  augment /sn:establish-subscription/sn:input:
    +---w nonce-value    binary
    +---w pcr-index*     tpm:pcr
~~~~

The result of the subscription will be that passing of the following information:

1. \<tpm12-attestation\> and \<tpm20-attestation\> notifications which include the provided \<nonce-value\>.  These attestation notifications MUST at least include all the \<pcr-indicies\> requested in the RPC.

2. a series of \<pcr-extend\> notifications which reference the requested PCRs on all TPM based cryptoprocessors on the Attester.

3. \<tpm12-attestation\> and \<tpm20-attestation\> notifications generated within a few seconds of the \<pcr-extend\> notifications.  These attestation notifications MUST at least include any PCRs extended.

If the Verifier does not want to see the logged extend operations for all PCRs available from an Attester, an Event Stream Filter should be applied.  This filter will remove Evidence from any PCRs which are not interesting to the Verifier. 


## Replaying a history of previous TPM extend operations

Unless it is relying on Known Good Values, a Verifier will need to acquire a history of PCR extensions since the Attester has been booted.  This history may be requested from the Attester as part of the \<establish-subscription\> RPC.  This request is accomplished by placing a very old \<replay-start-time\> within the original RPC request.  As the very old \<replay-start-time\> will pre-date the time of Attester boot, a \<replay-start-time-revision\> will be returned in the \<establish-subscription\> RPC response, indicating when the Attester booted.  Immediately following the response (and before the notifications above)  one or more \<pcr-extend\> notifications which document all extend operations which have occurred for the requested PCRs since boot will be sent.  Many extend operations to a single PCR index on a single TPM SHOULD be included within a single notification.  

Note that if a Verifier has a partial history of extensions, the \<replay-start-time\> can be adjusted so that known extensions are not forwarded.

The end of this history replay will be indicated with the {{RFC8639}} \<replay-completed\> notification.  For more on this sequence, see Section 2.4.2.1 of {{RFC8639}}.

After the \<replay-complete\> notification is provided, a TPM Quote will be requested and the result passed to the Verifier via a \<tpm12-attestation\> and \<tpm20-attestation\> notification.  If there have been any additional extend operations which have changed a subscribed PCR value in this quote, these MUST be pushed to the Verifier before the \<tpm12-attestation\> and \<tpm20-attestation\> notification. 

At this point the Verifier has sufficient Evidence appraise the reported extend operations for each PCR, as well compare the expected value of the PCR value against that signed by the TPM.


### TPM2 Heartbeat

For TPM2, make sure that every requested PCR is sent within an \<tpm20-attestation\> no less frequently than once per heartbeat interval.   This MAY be done with a single \<tpm20-attestation\> notification that includes all requested PCRs every heartbeat interval.  This MAY be done with several \<tpm20-attestation\> notifications at different times during that heartbeat interval. 

## YANG notifications placed on the \<attestation\> Event Stream

### pcr-extend

This notification documents when a subscribed PCR is extended within a single TPM cryptoprocessor.  It SHOULD be emmitted no less than the \<marshalling-period\> after an the PCR is first extended.  (The reason for the marshalling is that it is quite possible that multiple extensions to the same PCR have been made in quick succession, and these should be reflected in the same notification.)  This notification MUST be emmitted prior to a \<tpm12-attestation\> or \<tpm20-attestation\> notification which has included and signed the results of any specific PCR extension.   If pcr extending events occur during the generation of the \<tpm12-attestation\> or \<tpm20-attestation\> notification, the marshalling period MUST be extended so that a new \<pcr-extend\> is not sent until the corresponding notifications have been sent.

~~~~
    +---n tpm-extend
       +--ro certificate-name?    certificate-name-ref
       +--ro pcr-index-changed*   tpm:pcr
       +--ro attested-event* []
          +--ro attested-event
             +--ro extended-with             binary
             +--ro (event-details)?
                +--:(bios-event-log)
                |  +--ro bios-event-entry* [event-number]
                |     +--ro event-number    uint32
                |     +--ro event-type?     uint32
                |     +--ro pcr-index?      pcr
                |     +--ro digest-list* []
                |     |  +--ro hash-algo?   identityref
                |     |  +--ro digest*      binary
                |     +--ro event-size?     uint32
                |     +--ro event-data*     uint8
                +--:(ima-event-log)
                |  +--ro ima-event-entry* [event-number]
                |     +--ro event-number               uint64
                |     +--ro ima-template?              string
                |     +--ro filename-hint?             string
                |     +--ro filedata-hash?             binary
                |     +--ro filedata-hash-algorithm?   string
                |     +--ro template-hash-algorithm?   string
                |     +--ro template-hash?             binary
                |     +--ro pcr-index?                 pcr
                |     +--ro signature?                 binary
                +--:(netequip-boot)
                   +--ro boot-event-entry* [event-number]
                      +--ro event-number               uint64
                      +--ro filename-hint?             string
                      +--ro filedata-hash?             binary
                      +--ro filedata-hash-algorithm?   string
                      +--ro file-version?              string
                      +--ro file-type?                 string
                      +--ro pcr-index?                 pcr
~~~~

Each \<pcr-extend\> MUST include one or more values being extended into the PCR.   These are passed within the \<extended-with\> object.  For each extension, details of the event SHOULD be provided within the \<event-details\> object.  
The format of any included \<event-details\> is identified by the \<event-type\>.  This document includes two YANG structures which may be inserted into the \<event-details\>.  These two structures are: \<ima-event-log\< and \<bios-event-log\>.  Implementations wanting to provide additional documentation of a type of PCR extension may choose to define additional YANG structures which can be placed into \<event-details\>.


### tpm12-attestation

This notification contains an instance of a TPM1.2 style signed cryptoprocessor measurement. It is supplemented by Attester information which is not signed. This notification is generated and emitted from an Attester when at least one PCR identified within the subscribed \<pcr-indices\> has changed from the previous \<tpm12-attestation\> notification.  This notification MUST NOT include the results of any PCR extensions not previously reported by a \<pcr-extend\>.  This notification SHOULD be emitted as soon as a TPM Quote can extract the latest PCR hashed values.  This notification MUST be emitted prior to a subsequent \<pcr-extend\>.  

~~~~
    +---n tpm12-attestation {taa:TPM12}?
       +--ro certificate-name?            certificate-name-ref
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

All YANG objects above are defined within {{-rats-yang-tpm}}.  The \<tpm12-attestation\> is not replayable. 

### tpm20-attestation

This notification contains an instance of TPM2 style signed cryptoprocessor measurements. It is supplemented by Attester information which is not signed. This notification is generated at two points in time:

* every time at least one PCR has changed from a previous tpm20-attestation. In this case, the notification SHOULD be emitted within 10 seconds of the corresponding \<pcr-extend\> being sent:

* after a locally configurable minimum heartbeat period since a previous tpm20-attestation was sent. 

~~~~
    +---n tpm20-attestation {taa:TPM20}?
       +--ro certificate-name?      certificate-name-ref
       +--ro TPMS_QUOTE_INFO        binary
       +--ro quote-signature?       binary
       +--ro up-time?               uint32
       +--ro node-id?               string
       +--ro node-physical-index?   int32 {ietfhw:entity-mib}?
       +--ro unsigned-pcr-values* []
          +--ro TPM20-hash-algo?   identityref
          +--ro pcr-values* [pcr-index]
             +--ro pcr-index    pcr
             +--ro pcr-value?   binary
~~~~
All YANG objects above are defined within {{-rats-yang-tpm}}.  The \<tpm20-attestation\> is not replayable. 

## Filtering Evidence at the Attester

It can be useful *not* to receive all Evidence related to a PCR.  An example of this is would be a when a Verifier maintains known good values of a PCR.  In this case, it is not necessary to send each extend operation.   

To accomplish this reduction, when an RFC8639 \<establish-subscription\> RPC is sent, a \<stream-filter\> as per RFC8639, Section 2.2 can be set to discard a \<pcr-extend\>  notification when the \<pcr-index-changed\> is uninteresting to the verifier.   


## Replaying previous PCR Extend events

To verify the value of a PCR, a Verifier must either know that the value is a known good value {{KGV}} or be able to reconstruct the hash value by viewing all the PCR-Extends since the Attester rebooted. Wherever a hash reconstruction might be needed, the \<attestation\> Event Stream MUST support the RFC8639 \<replay\> feature. Through the \<replay\> feature, it is possible for a Verifier to retrieve and sequentially hash all of the PCR extending events since an Attester booted. And thus, the Verifier has access to all the evidence needed to verify a PCR’s current value.



{: #configuring title="Configuring the Attestation Stream"}
## Configuring the \<attestation\> Event Stream

{{attestationconfig}} is tree diagram which exposes the operator configurable elements of the \<attestation\> Event Stream. This allows an Attester to select what information should be available on the stream. A fetch operation also allows an external device such as a Verifier to understand the current configuration of stream.

Almost all YANG objects below are defined via reference from {{-rats-yang-tpm}}. There is one object which is new with this model however. \<tpm2-heartbeat\> defines the maximum amount of time which should pass before a subscriber to the Event Stream should get a \<tpm20-attestation\> notification from devices which contain a TPM2.

~~~~
  +--ro rats-support-structures
     +--ro tpms* [tpm-name]
     |  +--ro tpms:leafref-to-keystore?    string
     |  +--ro (tpms:subscribable)?
     |     +--:(tpms:tpm12-stream) {tpm:TPM12}?
     |     |  +--ro tpms:pcr-index*        pcr
     |     +--:(tpms:tpm20-stream) {tpm:TPM20}?
     |        +--ro tpms:pcr-list* []
     |           +--ro tpms:pcr
     |              +--ro tpms:pcr-index*                    pcr
     |              +--ro (tpms:algo-registry-type)
     |                 +--:(tpms:tcg)
     |                 |  +--ro tpms:tcg-hash-algo-id?       uint16
     |                 +--:(tpms:ietf)
     |                    +--ro tpms:ietf-ni-hash-algo-id?   uint8
     +--ro tpms:marshalling-period?           uint8
     +--ro tpms:TPM_SIG_SCHEME-value?         enumeration {tpm:TPM12}?
     +--ro (tpms:signature-identifier-type) {tpm:TPM20}?
     |  +--:(tpms:TPM_ALG_ID)
     |  |  +--ro tpms:TPM_ALG_ID-value?       enumeration
     |  +--:(tpms:COSE_Algorithm)
     |     +--ro tpms:COSE_Algorithm-value?   int32
     +--ro tpms:tpm20-heartbeat?              uint8
~~~~
{: #attestationconfig title="Configuring the \<attestation\> Event Stream"}


{: #YANG-Module} 
# YANG Module

This YANG module imports modules from {{-rats-yang-tpm}} and {{RFC8639}}.  It is also work-in-progress.


~~~~ YANG
<CODE BEGINS> ietf-rats-attestation-stream@2020-09-17.yang
{::include ietf-tpm-remote-attestation-stream@2020-09-17.yang}
<CODE ENDS>
~~~~ 

# Security Considerations

To be written.

# IANA Considerations {#IANA}

To be written.

--- back

# Change Log

v00-v01

* rename notification: pcr-extended, which supports multiple PCRs
* netequip boot added
* YANG structure extension removed
* Matched to structural changes made within charra


# Acknowledgements
{: numbered="no"}

Thanks to ...
