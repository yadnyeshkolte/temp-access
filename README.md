Unlike Windows, where the PostgreSQL installer usually comes with pgAdmin bundled together, **Linux packages them separately**. If you just installed PostgreSQL via your terminal using `apt`, you likely still need to install pgAdmin itself.

Here is how to check if you have it, open it, or install it from scratch.

### 1. How to open it (if it's already installed)

If you suspect you already installed it, you can launch it two ways:

* **Via your App Menu:** Press your Super (Windows) key and search for **pgAdmin 4**.
* **Via Terminal:** Open your terminal and type:
```bash
pgadmin4

```



### 2. How to install pgAdmin 4 (if you don't have it)

If the above steps didn't work, you'll need to install it. It's best to use the official pgAdmin repository to ensure you get the latest version, as the default Debian/Ubuntu repositories are often outdated.

Open your terminal and run these commands one by one:

**Step A: Add the public key for the repository**

```bash
curl -fsS https://www.pgadmin.org/static/packages_pgadmin_org.pub | sudo gpg --dearmor -o /usr/share/keyrings/packages-pgadmin-org.gpg

```

*(Note: If it says `curl: command not found`, run `sudo apt install curl` first).*

**Step B: Create the repository configuration file**

```bash
sudo sh -c 'echo "deb [signed-by=/usr/share/keyrings/packages-pgadmin-org.gpg] https://ftp.postgresql.org/pub/pgadmin/pgadmin4/apt/$(lsb_release -cs) pgadmin4 main" > /etc/apt/sources.list.d/pgadmin4.list && apt update'

```

**Step C: Install pgAdmin 4**
This command installs both the desktop application and the web-based version:

```bash
sudo apt install pgadmin4

```

### 3. Launching and Connecting

Once installed, search for **pgAdmin 4** in your applications menu and open it.

When it opens for the first time:

1. It will ask you to set a **Master Password**. This is just a password to secure the pgAdmin app itself on your computer.
2. To connect to your newly installed database, right-click on **Servers** in the left sidebar > **Register** > **Server**.
3. Under the **General** tab, name it something like "Local Postgres".
4. Under the **Connection** tab, set the Host name/address to `localhost`. The default username is usually `postgres`. Add the password you configured for your PostgreSQL database, and click **Save**.
