# 🚀 SSM -> HPC Standards & Specification
> **The Vision:** A comprehensive blueprint setting out the ecosystem, middleware, and toolchain an Indian High-Performance Computing (HPC) operating system must standardise, layer by layer. 
> *Let's dive in, understand the standards, and build the future of indigenous computing!*

---

## 🎯 The Brief: What We Are Setting Out to Do

### What It Covers 
* **Three Focus Areas:** The software ecosystem, the middleware, and the toolchain.
* **One Machine Class:** High-Performance Computing (HPC).
* **Testable Standards:** Written as strict standards outlining what an implementer *must*, *should*, and *may* do, rather than a loose description.
* **Architectural Organization:** Organized by the four layers of an operating system (because standards are written per layer, not per product).
* **International Baselining:** Every requirement is checked against current global baselines, ensuring our standards are world-class.

### What It Leaves to Others
* **Out of Scope for this specific standard:** Kernel, security, artificial intelligence, hardware and firmware, networking and storage, and post-quantum cryptography.
* *Note:* These belong to other technical groups. However, we explicitly name what we assume from them and provide a clean handover list to prevent integration blind spots.

---

## 🗺️ Where We Start From
*What our own two documents already settle.*

| Source | What it already decides | What it leaves open |
| :--- | :--- | :--- |
| **Feasibility Study — ecosystem chapter** | Package management, national repositories/mirrors, and software signing apply to HPC. Repositories/signing are marked for indigenous development. | No repository design and no package format are named. |
| **Feasibility Study — middleware and toolchain chapter** | 15 components with a machine-class matrix; 12 apply to HPC. Distributed computing middleware is the one line that is HPC-only. | No version, no obligation level, and no test is attached to any of them. |
| **Feasibility Study — HPC chapter** | A complete requirement table for HPC across all 8 technology areas, plus deployment settings, gaps, and indigenous opportunities. | Written as descriptive prose, not as testable obligations. |
| **Feasibility Study — build strategy** | Three tiers: reuse commodity software, extend platform software, build strategic software ourselves. | Which tier each HPC component belongs to. |
| **Specification Template** | The four-layer architecture, and the empty chapters we have been asked to fill. | Its ecosystem and middleware chapters contain no HPC content at all today. |

### ⚠️ Decision Needed Before Drafting
**The two documents do not agree on what HPC is:**
1. The *Specification Template* treats HPC as a tuned configuration of the Server OS.
2. The *Feasibility Study* treats HPC as an OS in its own right alongside Desktop, Server, Mobile, and Embedded. It then divides it again into cluster, supercomputing, grid, cloud, and strategic/secure HPC.

> **Why this matters:** This decides whether our output is a subsection, a new chapter, or a family of chapters. It dictates how requirements are numbered and traced—the one thing that cannot be corrected cheaply later.

---

## 🥞 The Layer View
An operating system is built in four horizontal layers. Our three areas cut across all four layers, and differently in each. 

| Layer | What it does, in plain terms | What our three areas must specify here |
| :--- | :--- | :--- |
| **1. Hardware enablement** | Makes processors, accelerators, and network cards usable. | Which processor families and accelerator programming models the compiler must produce working code for. (Drivers belong to the hardware group). |
| **2. Kernel and core services** | Decides which job gets which processor, memory, and device—and keeps jobs apart. | Nothing of ours is written here. But we must publish the list of kernel features we assume and formally hand it to the kernel group. |
| **3. Platform and middleware** | The layer researchers actually work on: compilers, parallel runtimes, containers, schedulers, storage clients. | The bulk of the work, and the layer where an HPC operating system genuinely differs from an ordinary server. |
| **4. Ecosystem** | How software is packaged, signed, delivered, certified, and supported. | The national repository and mirror network, package format, developer kit, and scientific application certification. |

---

## 🛠️ Layer 1: Hardware Enablement
*What the compiler must be able to target.*

* **MUST:** Name a specific capability level for each processor family.
  * *Intel/AMD:* A defined instruction-set level (not just "64-bit x86").
  * *ARM:* Vector extensions named.
  * *RISC-V:* The **RVA23 profile** (ratified Oct 2024, making vector and virtualization support compulsory). This is critical for defending an HPC claim against "RISC-V support" vagueness.
* **MUST:** Name one portable way to program accelerators. **OpenMP** is the only candidate that is a published standard rather than a vendor product (vendor stacks like CUDA, ROCm, oneAPI should be supported but not be the *only* route).
* **MUST:** Cross-building for RISC-V is specified until India has native RISC-V build capacity.

---

## 🧠 Layer 2: Kernel and Core Services
*What we depend on but do not own. If the kernel fails to provide these, our specifications break.*

| What we assume the kernel provides | What breaks in our chapters without it |
| :--- | :--- |
| Awareness of memory-to-processor mapping & ability to pin work | Placement of parallel jobs, and every performance figure we publish. |
| Large memory page support, controllable per job | Performance of memory-heavy scientific codes. |
| Modern resource-control groups (delegable to a scheduler) | Job resource limits, and running containers without admin rights. |
| Controls keeping background system activity off compute processors | Efficiency at large node counts. |
| Direct application access to high-speed network hardware | The whole of distributed computing middleware. |
| Kernel-level performance measurement and tracing | The profiling and debugging tools we are asked to provide. |

---

## ⚙️ Layer 3: Platform and Middleware
*Where an HPC system stops resembling a standard server.*

### The HPC Runtime
* **MUST:** Conform to **MPI version 5.0** (approved June 2025). This establishes a common binary interface—compile once, run anywhere. This is the cheapest and most effective sovereignty available.
* **MUST:** Adopt **PMIx** (the published interface between the job scheduler and parallel runtime). This provides a measurable definition for "Slurm-compatible".
* **MUST:** Name a standard network abstraction layer so Indian interconnects can be added as plug-ins.
* **MUST:** Use open container standards to package applications so they can run without admin privileges.

### Toolchain (Build & Provenance)
* **MUST:** Support major compiler families with fixed minimum versions and named language standards, explicitly including **Fortran**.
* **MUST:** Specify math libraries by published interface, not by product name.
* **MUST:** Provide a build system holding many versions of the same library side by side (e.g., **Spack 1.0**, July 2025).
* **MUST:** Require every delivered artefact to carry a **Software Bill of Materials (SBOM)** and a signed record binding it to the source.

---

## 🌐 Layer 4: Ecosystem
*Delivery, Trust, and Support.*

* **MUST:** Establish a national repository and mirror network, including disconnected/offline routes for defense clusters.
* **MUST:** Define certification in testable terms (builds from a published recipe, passes tests, ships an SBOM, declares parallel runtime versions).
* **SHOULD:** Curate a national scientific software collection (like Europe's EESSI project which distributes 600+ projects).
* **MUST:** Guarantee (in years) that compiled applications will keep working across supported releases.

---

## 📊 Benchmark: Where the World Actually Is (2026)

| Capability | Where the world is (2026) | What our standard must state |
| :--- | :--- | :--- |
| **Parallel communication** | MPI 5.0 (June 2025) - first common binary interface. | MUST conform (anti-lock-in clause). |
| **Multi-core programming** | OpenMP 6.0 (Nov 2024). | MUST conform (portable accelerator route). |
| **Scheduler interface** | PMIx standard v5.0 (May 2023). | MUST conform (defines "Slurm-compatible"). |
| **Reference cluster OS** | OpenHPC 4.x targets Enterprise Linux 10. | SHOULD align to a named public baseline. |
| **Scientific software stack** | Spack 1.0 (July 2025). | MUST specify a scientific stack manager. |
| **National stack delivery** | EESSI - 600+ projects (production March 2026). | SHOULD be the working model for our stack. |
| **Software supply chain** | SPDX 3.0.1 (ISO) / CycloneDX 1.6. | MUST name one as authoritative. |
| **RISC-V for HPC** | RVA23 profile (Oct 2024). | MUST target the ratified profile, not just "RISC-V". |

> **The Strategic Read:** Every sovereign OS program keeps the Linux base and spends its budget on the ecosystem, supply chain, and hardware enablement. Require conformance to open standards first, and only fund the gaps.

---

## 🏗️ Reuse Versus Build
*Where our indigenous effort and focus actually belong.*

| Component | Position |
| :--- | :--- |
| Parallel runtime, compilers, mathematical libraries, parallel filesystem | **REUSE** |
| Container runtime, package management, build & release pipeline, monitoring | **EXTEND** |
| Drivers and plug-ins for Indian high-speed interconnects | **BUILD** |
| Allocation/priority policy for Indian HPC on a standards-compatible scheduler | **BUILD** |
| National repository, mirror network, and code-signing infrastructure | **BUILD** |
| Provenance and attestation across the scientific software stack | **BUILD** |
| Hardened library variants for classified and defense deployment | **BUILD** |

---

## 📋 What Makes This a Standard?
* Every requirement is marked **mandatory, recommended, or optional**.
* Every requirement carries an identifier and a **traceable link to a verification test**.
* Every performance figure names the **hardware measured on and the method used** (no invented placeholders).
* Every external standard cited carries its **exact version and date**.

---

## 🚦 For Direction: Decisions Blocking the Start

| Question | What it blocks |
| :--- | :--- |
| Is HPC a Server config, a distinct OS, or a family of five? | Document structure, compliance matrix, and requirement numbering. |
| Does "Slurm-compatible" mean conforming to the interface, forking, or upstreaming? | Scheduler effort/cost and whether it counts as strategic work. |
| Is the sovereign package format new, and does it cover the scientific stack? | The whole ecosystem chapter (an order of magnitude in effort difference). |
| Which bill-of-materials format is authoritative (SPDX or CycloneDX)? | Toolchain output and compliance tests built on it. |
| Which facility do we measure performance on, and when can it be booked? | Every performance requirement in the HPC chapter. |
| Which Indian interconnect are we writing plug-in support for? | The one strategic item that is genuinely HPC-only and ours. |

---
*End of Document. Let's start building!* 🇮🇳💻
