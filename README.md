sudo modprobe -r kvm_intel
sudo modprobe -r kvm_amd
sudo modprobe -r kvm


### Phase 1: Database Management (pgAdmin 4 Setup)

This phase configures the official repository for Debian 11 (Bullseye) to ensure the correct dependencies are fetched, and installs the pgAdmin 4 desktop client.

**Step 1: Configure the Official Repository**
Open the terminal and run the following command to add the pgAdmin repository specifically tailored for Debian 11:

```bash
sudo sh -c 'echo "deb [signed-by=/usr/share/keyrings/packages-pgadmin-org.gpg] https://ftp.postgresql.org/pub/pgadmin/pgadmin4/apt/bullseye pgadmin4 main" > /etc/apt/sources.list.d/pgadmin4.list'
```

**Step 2: Update Package Lists**
Refresh the system's package manager to recognize the newly added repository:

```bash
sudo apt update
```

**Step 3: Install pgAdmin 4**
Install the full desktop application package:

```bash
sudo apt install pgadmin4
```

**Step 4: Launch pgAdmin 4**
The installation does not create a standard terminal command. To open the application, use one of the following methods:

* **Desktop Interface:** Open the system's **Applications Menu**, search for **pgAdmin 4**, and click to launch.
* **Terminal Interface:** Run the absolute path to the executable:
```bash
/usr/pgadmin4/bin/pgadmin4
```

### Phase 2: Spring Boot Development Environment

This phase installs the required Java Development Kit (JDK), the Maven build tool, and a professional Integrated Development Environment (IDE).

**Step 1: Install Java and Maven**
Spring Boot requires Java and a build tool to compile code and manage dependencies. Run the following command to install Java 21 and Maven natively:

```bash
sudo apt install openjdk-21-jdk maven -y
```

**Step 3: Initialize a Spring Boot Project**
To begin developing:

1. Navigate to **start.spring.io** in a web browser.
2. Configure the project parameters (Maven, Java, Spring Boot 3.x.x, Java 21).
3. Add required dependencies (e.g., Spring Web, Spring Data JPA, PostgreSQL Driver).
4. Click **Generate** to download the project blueprint.
5. Extract the downloaded `.zip` file.
