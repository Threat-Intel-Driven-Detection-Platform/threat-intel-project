# Threat Intelligence Driven Detection Platform

A modular **Threat Intelligence and Detection Platform** designed to collect Indicators of Compromise (IOCs) from multiple threat intelligence sources, normalize and correlate them into a unified dataset, store them in a queryable database, and use the intelligence as a foundation for security monitoring and IOC-based detection.

The platform is designed around a complete intelligence pipeline:

```text
Threat Intelligence Sources
          │
          ▼
      Collectors
          │
          ▼
       Raw Data
          │
          ▼
     Normalization
          │
          ▼
    Global IOC Dataset
          │
          ▼
     SQLite Database
          │
          ▼
   IOC Matching / Detection
          │
          ▼
   Security Monitoring
```

---

## 🎯 Project Goal

The main goal of this project is to build a centralized platform that transforms threat intelligence collected from different sources into structured, normalized, and searchable IOC data that can be used for detection.

Instead of handling each threat intelligence source separately, the platform provides a unified pipeline that:

- Collects threat intelligence from multiple sources.
- Preserves the original/raw intelligence.
- Normalizes different source formats into a common IOC structure.
- Removes duplicate indicators.
- Combines intelligence from multiple sources.
- Stores the resulting intelligence in a structured database.
- Supports efficient IOC lookup and future detection workflows.
- Provides a scalable foundation for integrating additional intelligence sources and detection mechanisms.

---

# 🏗️ Architecture

The project follows a modular pipeline architecture.

```text
                   ┌──────────────────────────┐
                   │ Threat Intelligence      │
                   │ Sources                  │
                   │                          │
                   │ • Feodo Tracker          │
                   │ • Infoblox TI            │
                   │ • CIRCL OSINT            │
                   │ • Other IOC Sources       │
                   └────────────┬─────────────┘
                                │
                                ▼
                   ┌──────────────────────────┐
                   │       Collectors          │
                   │                          │
                   │ Fetch source-specific     │
                   │ threat intelligence       │
                   └────────────┬─────────────┘
                                │
                                ▼
                   ┌──────────────────────────┐
                   │        Raw Data           │
                   │                          │
                   │ Original source data     │
                   │ before transformation     │
                   └────────────┬─────────────┘
                                │
                                ▼
                   ┌──────────────────────────┐
                   │      Normalization        │
                   │                          │
                   │ • Common IOC schema       │
                   │ • Type normalization      │
                   │ • Field normalization     │
                   │ • Deduplication           │
                   └────────────┬─────────────┘
                                │
                                ▼
                   ┌──────────────────────────┐
                   │    Global IOC Dataset     │
                   │                          │
                   │ Unified intelligence      │
                   │ from multiple sources     │
                   └────────────┬─────────────┘
                                │
                                ▼
                   ┌──────────────────────────┐
                   │    SQLite Database        │
                   │                          │
                   │ • IOCs                    │
                   │ • Sources                 │
                   │ • Relationships           │
                   │ • Observations            │
                   └────────────┬─────────────┘
                                │
                                ▼
                   ┌──────────────────────────┐
                   │ Detection & Monitoring    │
                   │                          │
                   │ IOC matching against      │
                   │ security/network data     │
                   └──────────────────────────┘
```

---

# 🔍 What is an IOC?

An **Indicator of Compromise (IOC)** is a piece of information that can indicate malicious or suspicious activity.

This project is designed to work with different IOC types, including:

- IPv4 addresses
- Domains
- URLs
- File hashes
- Other indicator types supported by the intelligence sources

Each IOC is associated with information such as its source, type, timestamps, tags, and other available threat intelligence metadata.

---

# 🌐 Threat Intelligence Sources

The platform is designed to ingest intelligence from multiple external sources.

Examples currently integrated into the project include:

### Feodo Tracker

Provides information related to malicious infrastructure and botnet Command & Control (C2) activity.

The collected intelligence can contain information such as:

- IP address
- Port
- Malware family
- First seen
- Last seen
- Status
- Tags
- Source information

---

### Infoblox Threat Intelligence

Provides threat intelligence that can be transformed into standardized IOC records and correlated with intelligence from other sources.

The project also performs source-name normalization so that logically identical sources are not represented as separate sources due to differences in naming or capitalization.

---

### CIRCL OSINT

Provides open-source threat intelligence that can contribute additional IOC observations to the unified dataset.

---

### Extensible Source Architecture

The collector/normalization architecture is designed so additional threat intelligence sources can be added without redesigning the entire platform.

Each source can have its own:

```text
Source
  ↓
Collector
  ↓
Raw Format
  ↓
Normalizer
  ↓
Common IOC Format
```

---

# 📥 Collection Layer

The **Collectors** are responsible for acquiring threat intelligence from external sources.

Collectors are source-specific because different intelligence providers expose their data in different formats.

For example:

```text
Feodo Tracker
      ↓
Feodo Collector
      ↓
Raw Feodo Data
```

The collector layer focuses on **acquisition**, not on forcing every source into the same schema.

This separation makes the system easier to maintain when a source changes its format.

---

# 🔄 Normalization Layer

Different threat intelligence sources represent the same concepts differently.

For example, one source may use:

```text
ip_address
```

while another may use:

```text
indicator
```

The normalization layer converts these source-specific representations into a common structure.

A normalized IOC can conceptually contain:

```text
value
type
source
first_seen
last_seen
status
tags
threat_type
metadata
```

For example:

```text
Source Field:
ip_address = 1.2.3.4

        ↓

Normalized IOC:

value = 1.2.3.4
type = ipv4
threat_type = botnet_c2
source = Feodo Tracker
```

This allows indicators from completely different sources to be processed consistently.

---

# ♻️ Deduplication

The platform performs deduplication during normalization and data integration.

The same indicator may appear:

- multiple times in the same source,
- in different source feeds,
- or with slightly different representations.

The platform therefore uses normalized IOC values and types to identify duplicate indicators while preserving source and observation information.

This is important because:

```text
Multiple observations
        ↓
      Same IOC
        ↓
   One normalized IOC
        +
   Multiple relationships
```

This preserves intelligence provenance instead of simply deleting duplicate information.

---

# 🌍 Global IOC Dataset

After source-specific normalization, the platform combines the normalized intelligence into a global IOC dataset.

Conceptually:

```text
Feodo Normalized
        │
Infoblox Normalized
        │
CIRCL Normalized
        │
Other Sources
        │
        ▼
   Global IOC Dataset
```

The global dataset acts as the bridge between the source-processing pipeline and the database layer.

---

# 🗄️ SQLite Database

The project uses **SQLite** as the local threat intelligence database.

The database provides structured storage for:

- IOC records
- Threat intelligence sources
- IOC-to-source relationships
- IOC observations
- Associated metadata

The database separates the concept of:

```text
IOC
```

from:

```text
Source
```

and:

```text
Observation
```

This is important because one IOC can be associated with multiple intelligence sources or observations.

---

## Database Population

The database is populated from the unified IOC dataset using the database-building pipeline.

The database builder uses streaming JSON processing so that the large IOC dataset does not need to be loaded completely into memory at once.

Conceptually:

```text
global_iocs.json
       │
       ▼
Database Builder
       │
       ▼
SQLite
       │
       ├── IOCs
       ├── Sources
       ├── Relationships
       └── Observations
```

The resulting database can then be queried directly for IOC lookups.

---

# 🔎 IOC Querying

The project includes database querying functionality for looking up indicators.

Example:

```bash
python database/query_database.py 0-0x.xyz
```

This allows analysts or future detection components to quickly determine whether an indicator exists in the threat intelligence database and retrieve associated intelligence.

---

# 🛡️ Detection Layer

The ultimate purpose of centralizing the threat intelligence is to support **IOC-driven detection**.

The database can act as the intelligence layer against which security data can be checked.

A future detection workflow can follow:

```text
Network / Security Logs
          │
          ▼
      Extract IOCs
          │
          ▼
    Query Threat DB
          │
          ▼
   IOC Match Found?
       /       \
     YES        NO
      │          │
      ▼          ▼
    Alert      Continue
```

For example, a network log containing:

```text
Source IP = 185.x.x.x
```

can be checked against the IOC database.

If the indicator exists and has relevant threat intelligence associated with it, the detection layer can use that information to support alert generation and investigation.

---

# 📁 Project Structure

```text
threat-intel-project/
│
├── collectors/
│   ├── ...
│   └── Source-specific collectors
│
├── normalization/
│   ├── ...
│   └── Source-specific normalizers
│
├── pipeline/
│   ├── global_merge.py
│   └── ...
│
├── database/
│   ├── build_database.py
│   └── query_database.py
│
├── data/
│   ├── raw/
│   │   └── Source-specific raw data
│   │
│   ├── normalized/
│   │   └── Normalized IOC data
│   │
│   └── database/
│       ├── global_iocs.json
│       └── threat_intel.db
│
└── README.md
```

The exact set of source-specific files may evolve as additional intelligence feeds are integrated.

---

# 🔐 Data Flow

The complete data lifecycle is:

```text
1. Collect
      ↓
2. Store Raw Data
      ↓
3. Normalize
      ↓
4. Deduplicate
      ↓
5. Merge
      ↓
6. Store in SQLite
      ↓
7. Query
      ↓
8. Match Against Security Data
      ↓
9. Detect / Alert
```

Each stage has a separate responsibility.

This separation makes the platform easier to debug, test, extend, and maintain.

---

# 🧪 Validation & Quality Checks

The project includes validation at different stages of the pipeline.

Examples include:

### Python Syntax Validation

Collectors, normalization, and pipeline modules are checked for Python syntax errors before integration.

### Database Integrity

The SQLite database is checked for:

- valid foreign-key relationships
- expected IOC counts
- expected observation counts
- valid source relationships

### Duplicate Handling

IOC and source-level duplication is checked during the normalization and database integration process.

### Merge Safety

The global merge process contains a safety check to prevent an empty normalized dataset from accidentally overwriting an existing global IOC dataset.

---

# 📊 Current Dataset

The current integrated threat intelligence database contains approximately:

```text
508,267 unique IOCs
510,889 observations
10 intelligence sources
0 foreign-key integrity errors
```

These numbers represent the current integrated dataset and may change as new intelligence feeds are collected.

---

# 🚀 Getting Started

## Requirements

- Python 3.x
- Git
- Git LFS
- SQLite

Clone the repository:

```bash
git clone https://github.com/Threat-Intel-Driven-Detection-Platform/threat-intel-project.git
cd threat-intel-project
```

Install the required Python dependencies if a project requirements file is provided:

```bash
pip install -r requirements.txt
```

---

## Build the Database

After the global IOC dataset has been generated:

```bash
python database/build_database.py data/database/global_iocs.json
```

This creates:

```text
data/database/threat_intel.db
```

---

## Query an IOC

Example:

```bash
python database/query_database.py 0-0x.xyz
```

---

# 🌱 Development Workflow

Development is organized using Git branches so individual contributors can work independently without modifying another contributor's branch.

Example:

```text
Ganna_week1
     │
     ├── Kenzy_week1
     │
     └── Other development branches
```

Changes are developed, tested, committed, and pushed to the appropriate branch before integration.

---

# 📦 Large Dataset Management

The project contains large threat intelligence datasets and database files.

**Git LFS (Large File Storage)** is used to manage large files such as:

```text
data/database/global_iocs.json
data/database/threat_intel.db
```

This avoids storing very large binary/data objects directly inside normal Git history.

After cloning the repository, Git LFS should be installed and initialized:

```bash
git lfs install
```

Then:

```bash
git lfs pull
```

---

# 🧩 Design Principles

The platform is built around several design principles:

### Modularity

Collectors, normalizers, pipelines, and database components are separated.

### Extensibility

New threat intelligence sources should be addable without rewriting the entire pipeline.

### Normalization

Different source formats are converted into a common representation.

### Data Provenance

The system preserves information about where an IOC came from instead of treating all indicators as anonymous data.

### Scalability

Large datasets are processed using streaming techniques where appropriate.

### Safety

Pipeline operations include validation and safeguards against destructive empty-data merges.

### Detection-Oriented Design

The final intelligence database is designed to support real security monitoring and IOC-based detection.

---

# 🛣️ Roadmap

The platform is being developed incrementally.

### Phase 1 — Threat Intelligence Foundation

- [x] Threat intelligence source integration
- [x] Source-specific collectors
- [x] IOC normalization
- [x] IOC deduplication
- [x] Global IOC dataset
- [x] SQLite threat intelligence database
- [x] Database querying
- [x] Data integrity validation
- [x] Large-file management using Git LFS

### Future Development

- [ ] Expand threat intelligence source coverage
- [ ] Automated collection and update scheduling
- [ ] Continuous IOC database updates
- [ ] Network/security log ingestion
- [ ] Automated IOC extraction
- [ ] IOC matching engine
- [ ] Detection and alerting
- [ ] Threat intelligence correlation
- [ ] Analyst-facing investigation capabilities
- [ ] Monitoring and reporting
- [ ] Production-oriented deployment

---

# 🔭 Long-Term Vision

The long-term goal is to evolve the project from a threat intelligence ingestion pipeline into an integrated **Threat Intelligence Driven Detection Platform**.

The intended workflow is:

```text
External Threat Intelligence
            │
            ▼
     Intelligence Pipeline
            │
            ▼
      Central IOC Store
            │
            ▼
     Detection Engine
            │
            ▼
      Security Events
            │
            ▼
       IOC Matching
            │
            ▼
       Alert / Context
            │
            ▼
      Analyst Investigation
```

This architecture allows threat intelligence to become an active part of the detection process rather than simply a collection of static IOC feeds.

---

# 👥 Project Team

This project is developed collaboratively as a cybersecurity/threat intelligence engineering project.

Each contributor works on dedicated development branches before changes are integrated into the main project workflow.

---

# 📄 Project Status

**Status:** Active Development 🚧

The threat intelligence collection, normalization, global dataset, and database foundation are implemented. The platform is being extended toward automated IOC matching, detection, alerting, and broader security monitoring capabilities.

---

## Disclaimer

The threat intelligence data used by this project is intended for **security research, threat intelligence analysis, and defensive cybersecurity purposes**.

Indicators should be validated and investigated within the appropriate security context before taking defensive or operational actions.
