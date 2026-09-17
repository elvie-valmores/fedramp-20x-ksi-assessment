# FedRAMP 20x KSI Catalog Reference
**Source:** `fedramp-consolidated-rules.json`, FedRAMP/rules GitHub repository (machine-readable source of truth).
**Version:** 2026.07.14.01    **Last updated:** 2026-07-14    **Pulled:** 2026-09-05
**Scope of this reference:** Class C (formerly Moderate). Five indicators are optional at Class B and required at Class C; all 46 apply at Class C.
Generated from the canonical dataset. The fedramp.gov website is a human-readable reference only and is not authoritative for implementation.

---

## Clusters (10 themes, 46 indicators)

| Cluster | Name | Indicators |
|---|---|---|
| KSI-CED | Cybersecurity Education | 1 |
| KSI-CMT | Change Management | 4 |
| KSI-CNA | Cloud Native Architecture | 8 |
| KSI-IAM | Identity and Access Management | 6 |
| KSI-INR | Incident Response | 3 |
| KSI-MLA | Monitoring, Logging, and Auditing | 5 |
| KSI-PIY | Policy and Inventory | 5 |
| KSI-RPL | Recovery Planning | 4 |
| KSI-SCR | Supply Chain Risk | 2 |
| KSI-SVC | Service Configuration | 8 |

---

## KSI-CED — Cybersecurity Education

### KSI-CED-RAT — Reviewing All Training

The effectiveness of relevant cybersecurity education and training is persistently reviewed, including at least general training for all employees, role-specific training for employees in high risk roles, training for development and engineering staff on secure software delivery, and training for staff involved with incident response or disaster recovery.

**NIST SP 800-53:** CP-3, IR-2, PS-6, AT-2, AT-2 (2), AT-2 (3), AT-3 (5), AT-4, IR-2 (3), AT-3, SR-11 (1)

**Defined terms in play:** Incident, Persistently, Vulnerability Response


---

## KSI-CMT — Change Management

### KSI-CMT-LMC — Logging Changes

Modifications to the cloud service offering are logged and monitored.

**NIST SP 800-53:** AU-2, CM-3, CM-3 (2), CM-4 (2), CM-6, CM-8 (3), MA-2

**Defined terms in play:** Cloud Service Offering


### KSI-CMT-RMV — Redeploying vs Modifying

Changes to machine-based information resources are executed through the redeployment of version controlled resources rather than direct modification wherever reasonable.

**NIST SP 800-53:** CM-2, CM-3, CM-5, CM-6, CM-7, CM-8 (1), SI-3

**Defined terms in play:** Information Resource, Machine-Based (Information Resources)


### KSI-CMT-RVP — Reviewing Change Procedures

The effectiveness of documented change management procedures is persistently reviewed.

**NIST SP 800-53:** CM-3, CM-3 (2), CM-3 (4), CM-5, CM-7 (1), CM-9

**Defined terms in play:** Persistently


### KSI-CMT-VTD — Validating Throughout Deployment

Persistent testing and validation of changes throughout deployment is automated.

**NIST SP 800-53:** CM-3, CM-3 (2), CM-4 (2), SI-2

**Defined terms in play:** Persistently, Validation


---

## KSI-CNA — Cloud Native Architecture

### KSI-CNA-DFP — Defining Functionality and Privileges

The functionality and privileges for infrastructure and services are strictly defined.

**NIST SP 800-53:** CM-2, SI-3


### KSI-CNA-EIS — Enforcing Intended State

**Varies by class:**

- **Class B:** **Optional:** Automated services are used to persistently assess the security of all machine-based information resources and automatically enforce their intended operational state.
- **Class C:** Automated services are used to persistently assess the security of all machine-based information resources and automatically enforce their intended operational state.

**NIST SP 800-53:** CA-2 (1), CA-7 (1)

**Defined terms in play:** Information Resource, Machine-Based (Information Resources), Persistently


### KSI-CNA-IBP — Implementing Best Practices

The use and configuration of third-party machine-based information resources is persistently compared against the original provider's best practices and guidance.

**NIST SP 800-53:** AC-17 (3), CM-2, PL-10

**Defined terms in play:** Information Resource, Machine-Based (Information Resources), Persistently, Provider


### KSI-CNA-MAT — Minimizing Attack Surface

Machine-based information resources are persistently reviewed to ensure they have a minimal attack surface and that lateral movement is minimized if compromised.

**NIST SP 800-53:** AC-17 (3), AC-18 (1), AC-18 (3), AC-20 (1), CA-9, SC-7 (3), SC-7 (4), SC-7 (5), SC-7 (8), SC-8, SC-10, SI-10, SI-11, SI-16

**Defined terms in play:** Information Resource, Machine-Based (Information Resources), Persistently


### KSI-CNA-OFA — Optimizing for Availability

Machine-based information resources are persistently reviewed to ensure they are appropriately optimized for high availability and rapid recovery.

**Defined terms in play:** Information Resource, Machine-Based (Information Resources), Persistently


### KSI-CNA-RNT — Restricting Network Traffic

Machine-based information resources are persistently reviewed to ensure they are appropriately configured to limit inbound and outbound network traffic.

**NIST SP 800-53:** AC-17 (3), CA-9, CM-7 (1), SC-7 (5), SI-8

**Defined terms in play:** Information Resource, Machine-Based (Information Resources), Persistently


### KSI-CNA-RVP — Reviewing Protections

The effectiveness of protection against denial of service attacks and other unwanted activity for machine-based information resources is persistently reviewed.

**NIST SP 800-53:** SC-5, SI-8, SI-8 (2)

**Defined terms in play:** Information Resource, Machine-Based (Information Resources), Persistently


### KSI-CNA-ULN — Using Logical Networking

Logical networking and related capabilities are used and persistently reviewed to enforce traffic flow controls.

**NIST SP 800-53:** AC-12, AC-17 (3), CA-9, SC-4, SC-7, SC-7 (7), SC-8, SC-10

**Defined terms in play:** Persistently


---

## KSI-IAM — Identity and Access Management

### KSI-IAM-AAM — Automating Account Management

The lifecycle and privileges of all accounts, roles, and groups are securely managed using automation.

**NIST SP 800-53:** AC-2 (2), AC-2 (3), AC-2 (13), AC-6 (7), IA-4 (4), IA-12, IA-12 (2), IA-12 (3), IA-12 (5)


### KSI-IAM-APM — Adopting Passwordless Methods

Secure passwordless methods are used for user authentication and authorization when feasible, otherwise strong passwords with phishing-resistant MFA is used.

**NIST SP 800-53:** AC-3, IA-5 (1), IA-5 (2), IA-5 (6), IA-6, AC-2, IA-2, IA-2 (1), IA-2 (2), IA-2 (8), IA-5, IA-8, SC-23


### KSI-IAM-ELP — Ensuring Least Privilege

Identity and access management measures are used and persistently reviewed to ensure each user or device can only access the resources they need.

**NIST SP 800-53:** AC-2 (5), AC-2 (6), AC-3, AC-4, AC-6, AC-12, AC-14, AC-17, AC-17 (1), AC-17 (2), AC-17 (3), AC-20, AC-20 (1), CM-2 (7), CM-9, IA-2, IA-3, IA-4, IA-4 (4), IA-5 (2), IA-5 (6), IA-11, PS-2, PS-3, PS-4, PS-5, PS-6, SC-4, SC-20, SC-21, SC-22, SC-23, SC-39, SI-3

**Defined terms in play:** Persistently


### KSI-IAM-JIT — Authorizing Just-in-Time

A least-privileged, role and attribute-based, and just-in-time security authorization model is used and persistently reviewed for all user and non-user accounts and services.

**NIST SP 800-53:** AC-2, AC-2 (1), AC-2 (2), AC-2 (3), AC-2 (4), AC-2 (6), AC-3, AC-4, AC-5, AC-6, AC-6 (1), AC-6 (2), AC-6 (5), AC-6 (7), AC-6 (9), AC-6 (10), AC-7, AC-20 (1), AC-17, AU-9 (4), CM-5, CM-7, CM-7 (2), CM-7 (5), CM-9, IA-4, IA-4 (4), IA-7, PS-2, PS-3, PS-4, PS-5, PS-6, PS-9, RA-5 (5), SC-2, SC-23, SC-39

**Defined terms in play:** Persistently


### KSI-IAM-SNU — Securing Non-User Authentication

Appropriately secure authentication methods are used and persistently reviewed for non-user accounts and services.

**NIST SP 800-53:** AC-2, AC-2 (2), AC-4, AC-6 (5), IA-3, IA-5 (2), RA-5 (5)

**Defined terms in play:** Persistently


### KSI-IAM-SUS — Responding to Suspicious Activity

Accounts with privileged access are disabled or otherwise secured in response to suspicious activity.

**NIST SP 800-53:** AC-2, AC-2 (1), AC-2 (3), AC-2 (13), AC-7, PS-4, PS-8

**Defined terms in play:** Vulnerability Response


---

## KSI-INR — Incident Response

### KSI-INR-AAR — Generating After Action Reports

Incident after action reports are generated and lessons learned are persistently incorporated.

**NIST SP 800-53:** IR-3, IR-4, IR-4 (1), IR-8

**Defined terms in play:** Incident, Persistently


### KSI-INR-RIR — Reviewing Incident Response Procedures

The effectiveness of documented incident response procedures is persistently reviewed.

**NIST SP 800-53:** IR-4, IR-4 (1), IR-6, IR-6 (1), IR-6 (3), IR-7, IR-7 (1), IR-8, IR-8 (1), SI-4 (5)

**Defined terms in play:** Incident, Persistently, Vulnerability Response


### KSI-INR-RPI — Reviewing Past Incidents

Past incidents are persistently reviewed for patterns or vulnerabilities that were not previously apparent or identified.

**NIST SP 800-53:** IR-3, IR-4, IR-4 (1), IR-5, IR-8

**Defined terms in play:** Incident, Persistently, Vulnerability


---

## KSI-MLA — Monitoring, Logging, and Auditing

### KSI-MLA-ALA — Authorizing Log Access

**Varies by class:**

- **Class B:** **Optional:** A least-privileged, role and attribute-based, and just-in-time access authorization model is used and persistently reviewed for access to log data based on organizationally defined data sensitivity.
- **Class C:** A least-privileged, role and attribute-based, and just-in-time access authorization model is used and persistently reviewed for access to log data based on organizationally defined data sensitivity.

**NIST SP 800-53:** SI-11

**Defined terms in play:** Persistently


### KSI-MLA-EVC — Evaluating Configurations

The configuration of machine-based information resources, especially infrastructure as code, is persistently evaluated and tested.

**NIST SP 800-53:** CA-7, CM-2, CM-6, SI-7 (7)

**Defined terms in play:** Information Resource, Machine-Based (Information Resources), Persistently


### KSI-MLA-LET — Logging Event Types

A list of information resources and event types that will be logged, monitored, and audited is maintained and persistently reviewed to ensure these activities occur.

**NIST SP 800-53:** AC-2 (4), AC-6 (9), AC-17 (1), AC-20 (1), AU-2, AU-7 (1), AU-12, SI-4 (4), SI-4 (5), SI-7 (7)

**Defined terms in play:** Information Resource, Persistently


### KSI-MLA-OSM — Operating SIEM Capability

A Security Information and Event Management (SIEM) or similar system(s) is used and persistently reviewed for centralized, tamper-resistant logging of events, activities, and changes.

**NIST SP 800-53:** AC-17 (1), AC-20 (1), AU-2, AU-3, AU-3 (1), AU-4, AU-5, AU-6 (1), AU-6 (3), AU-7, AU-7 (1), AU-8, AU-9, AU-11, IR-4 (1), SI-4 (2), SI-4 (4), SI-7 (7)

**Defined terms in play:** Persistently


### KSI-MLA-RVL — Reviewing Logs

Logs are persistently reviewed and audited.

**NIST SP 800-53:** AC-2 (4), AC-6 (9), AU-2, AU-6, AU-6 (1), SI-4, SI-4 (4)

**Defined terms in play:** Persistently


---

## KSI-PIY — Policy and Inventory

### KSI-PIY-GIV — Generating Inventories

Authoritative sources are used to automatically generate real-time inventories of all information resources when needed.

**NIST SP 800-53:** CM-2 (2), CM-7 (5), CM-8, CM-8 (1), CM-12, CM-12 (1), CP-2 (8)

**Defined terms in play:** Information Resource


### KSI-PIY-RES — Reviewing Executive Support

Executive support for achieving the provider's security goals is persistently reviewed and demonstrated.

**Defined terms in play:** Persistently, Provider


### KSI-PIY-RIS — Reviewing Investments in Security

The effectiveness of the provider's investments in achieving security goals is persistently reviewed.

**NIST SP 800-53:** AC-5, CA-2, CP-2 (1), CP-4 (1), IR-3 (2), PM-3, SA-2, SA-3, SR-2 (1)

**Defined terms in play:** Persistently, Provider


### KSI-PIY-RSD — Reviewing Security in the SDLC

The effectiveness of building security and privacy considerations into the Software Development Lifecycle and aligning with CISA Secure By Design principles is persistently reviewed.

**NIST SP 800-53:** AC-5, AU-3 (3), CM-3 (4), PL-8, PM-7, SA-3, SA-8, SC-4, SC-18, SI-10, SI-11, SI-16

**Defined terms in play:** Persistently


### KSI-PIY-RVD — Reviewing Vulnerability Disclosures

The effectiveness of the provider's vulnerability disclosure program is persistently reviewed.

**NIST SP 800-53:** RA-5 (11)

**Defined terms in play:** Persistently, Provider, Vulnerability


---

## KSI-RPL — Recovery Planning

### KSI-RPL-ABO — Aligning Backups with Objectives

The alignment of machine-based information resource backups with defined recovery objectives is persistently reviewed.

**NIST SP 800-53:** CM-2 (3), CP-6, CP-9, CP-10, CP-10 (2), SI-12

**Defined terms in play:** Information Resource, Machine-Based (Information Resources), Persistently


### KSI-RPL-ARP — Aligning Recovery Plan

The alignment of recovery plans with defined recovery objectives is persistently reviewed.

**NIST SP 800-53:** CP-2, CP-2 (1), CP-2 (3), CP-4 (1), CP-6, CP-6 (1), CP-6 (3), CP-7, CP-7 (1), CP-7 (2), CP-7 (3), CP-8, CP-8 (1), CP-8 (2), CP-10, CP-10 (2)

**Defined terms in play:** Persistently


### KSI-RPL-RRO — Reviewing Recovery Objectives

The desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO) are defined and persistently reviewed for alignment with the provider's business needs and capabilities.

**NIST SP 800-53:** CP-2 (3), CP-10

**Defined terms in play:** Persistently, Provider


### KSI-RPL-TRC — Testing Recovery Capabilities

The capability to recover from incidents and contingencies aligned with defined recovery objectives is persistently tested.

**NIST SP 800-53:** CP-2 (1), CP-2 (3), CP-4, CP-4 (1), CP-6, CP-6 (1), CP-9 (1), CP-10, IR-3, IR-3 (2)

**Defined terms in play:** Incident, Persistently


---

## KSI-SCR — Supply Chain Risk

### KSI-SCR-MIT — Mitigating Supply Chain Risk

Persistently identify, review, and mitigate potential supply chain risks.

**NIST SP 800-53:** AC-20, RA-3 (1), SA-9, SA-10, SA-11, SA-15 (3), SA-22, SI-7 (1), SR-5, SR-6, CA-7 (4), SC-18

**Defined terms in play:** Persistently


### KSI-SCR-MON — Monitoring Supply Chain Risk

Third party software information resources are automatically monitored for upstream vulnerabilities using mechanisms that may include contractual notification requirements or active monitoring services.

**NIST SP 800-53:** AC-20, CA-3, IR-6 (3), PS-7, RA-5, SA-9, SI-5, SR-5, SR-6, SR-8

**Defined terms in play:** Information Resource, Vulnerability


---

## KSI-SVC — Service Configuration

### KSI-SVC-ACM — Automating Configuration Management

The configuration of machine-based information resources is managed using automation and persistently reviewed for drift.

**NIST SP 800-53:** AC-2 (4), CM-2, CM-2 (2), CM-2 (3), CM-6, CM-7 (1), PL-9, PL-10, SA-5, SI-5, SR-10

**Defined terms in play:** Drift, Information Resource, Machine-Based (Information Resources), Persistently


### KSI-SVC-ASM — Automating Secret Management

Management, protection, and regular rotation of digital keys, certificates, and other secrets is automated and persistently reviewed.

**NIST SP 800-53:** AC-17 (2), IA-5 (2), IA-5 (6), SC-12, SC-17

**Defined terms in play:** Persistently, Regularly


### KSI-SVC-EIS — Evaluating and Improving Security

Information resources are persistently evaluated for opportunities to improve security and those improvements are persistently made.

**NIST SP 800-53:** CM-7 (1), CM-12 (1), MA-2, PL-8, SC-7, SC-39, SI-2 (2), SI-4, SR-10

**Defined terms in play:** Information Resource, Persistently


### KSI-SVC-PRR — Preventing Residual Risk

**Varies by class:**

- **Class B:** **Optional:** Plans, procedures, and the state of information resources are persistently reviewed after making changes to limit and remove unwanted residual elements that would likely negatively affect the confidentiality, integrity, or availability of federal customer data.
- **Class C:** Plans, procedures, and the state of information resources are persistently reviewed after making changes to limit and remove unwanted residual elements that would likely negatively affect the confidentiality, integrity, or availability of federal customer data.

**NIST SP 800-53:** SC-4

**Defined terms in play:** Federal Customer Data, Information Resource, Likely, Persistently


### KSI-SVC-RUD — Removing Unwanted Data

**Varies by class:**

- **Class B:** **Optional:** Unwanted federal customer data is removed promptly when requested by an agency in alignment with customer agreements, including from backups if appropriate; this typically applies when a customer spills information or when a customer seeks to remove information from a service due to a change in usage.
- **Class C:** Unwanted federal customer data is removed promptly when requested by an agency in alignment with customer agreements, including from backups if appropriate; this typically applies when a customer spills information or when a customer seeks to remove information from a service due to a change in usage.

**NIST SP 800-53:** SI-12 (3), SI-18 (4)

**Defined terms in play:** Agency, Federal Customer Data, Promptly


### KSI-SVC-SIN — Securing Information

Information is encrypted or otherwise secured from unwanted access or modification.

**NIST SP 800-53:** AC-1, AC-17 (2), CP-9 (8), SC-8, SC-8 (1), SC-13, SC-20, SC-21, SC-22, SC-23, SC-28, SC-28 (1)


### KSI-SVC-VCM — Validating Communications

**Varies by class:**

- **Class B:** **Optional:** The authenticity and integrity of communications between machine-based information resources is persistently validated using automation.
- **Class C:** The authenticity and integrity of communications between machine-based information resources is persistently validated using automation.

**NIST SP 800-53:** SC-23, SI-7 (1)

**Defined terms in play:** Information Resource, Machine-Based (Information Resources), Persistently, Validation


### KSI-SVC-VRI — Validating Resource Integrity

Use cryptographic methods to validate the integrity of machine-based information resources.

**NIST SP 800-53:** CM-2 (2), CM-8 (3), SC-13, SC-23, SI-7, SI-7 (1), SR-10

**Defined terms in play:** Information Resource, Machine-Based (Information Resources), Validation


---

## Defined terms that govern interpretation

**Persistently** — Occurring in a firm, steady way that is repeated over a long period of time in spite of obstacles or difficulties. Persistent activities may vary between actors, may occur irregularly, and may include interruptions or waiting periods between cycles. These attributes of persistent activities should be intentional, understood, and documented; the status of persistent activities will always be known.

> The use of persistently indicates a process that may not always occur continuously (without interruption or gaps) or regularly (on a consistent, predictable basis) but will repeat frequently in cycles. It aligns generally with historical misuse of "continuous" in federal information security policies.

**Verification** — Confirmation through objective evidence that specified FedRAMP Practices have been fulfilled for a cloud service offering.

> This adapts the ISO conformity assessment concept of verification to the FedRAMP Certification context.

**Validation** — Confirmation through objective evidence that implemented security capabilities and related certification data are suitable for their intended FedRAMP Certification use and support the expected security outcomes for a cloud service offering.

> This adapts the ISO conformity assessment concept of validation to the FedRAMP Certification context.

**Information Resource** — Has the meaning from 44 USC § 3502 (6): "information and related resources, such as personnel, equipment, funds, and information technology." This includes any aspect of the cloud service offering, both technical and managerial, including everything that makes up the business of the offering from non-machine-based information resources like organizational policies, procedures, employees, etc. to machine-based information resources like hardware, software, cloud services, code, etc.

> Information resources are either machine-based or non-machine-based; any requirement or recommendation that references information resources without specifying a type is inclusive of all information resources.

**Machine-Based (Information Resources)** — Any information technology information resource—including systems, processes, software, hardware, services, cloud-native capabilities, and any other such capability, component, or resource—that relies primarily on mechanical or electronic devices (i.e. computers) for operation.

> All other information resources that do not rely on computers are non-machine-based information resources.

**Security Decision Record (SDR)** — A persistently maintained, verified, and validated record of the security decisions made by a provider over the lifecycle of a cloud service offering. The Security Decision Record replaces the traditional System Security Plan and documents how applicable FedRAMP Practices are addressed, including implementation rationale, resulting customer risk, assessment findings, and supporting artifacts.

**Artifacts** — Security-related materials that supply information regarding or evidence of functions, policies, decisions, procedures, operations, or other such activities, for the purposes of obtaining and maintaining a FedRAMP Certification. All such artifacts are considered FedRAMP Certification Data and are included in the FedRAMP Certification Package.

**Promptly** — Without unnecessary delay.

> The use of promptly in FedRAMP materials frames conveys a need for urgent action where the expected time frame will vary by circumstance but earlier action is more likely to improve security outcomes and increase the security posture of a cloud service offering.

**Likely** — A reasonable degree of probability based on context.

