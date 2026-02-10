# ColumnLynx

## What is it?

ColumnLynx is a VPN protocol designed to be as lightweight and simple to understand as possible.

### Origin

The original goal of this project was for me to learn about the inner-workings of VPN protocols, but overtime, it has transformed into the goal seen above.

### Design Philosophy

A VPN (Virtual Private Network), in the most basic terms, is a protocol that tunnels network traffic from a client to a server over an encrypted tunnel and having the server send that traffic on its behalf. It can be catagorized into sitting somewhere in-between the 3rd and 4th layers of the ISO/OSI model.

This project aims to be just that, an encrypted tunneling protocol that works on the 3rd and 4th layers of the ISO/OSI model, nothing more, nothing less. We leave complex functions like compression, to the higher layers (though it could be argued that making an encrypted tunnel already pushes us up to Layer 6).

This simplicity-focused design approach allows us to make an efficient, low-overhead VPN protocol and minimize any potential attack surface.

## Configuration

Configurating the server and client are are relatively easy. Currently (since the project is in alpha), the configuration files **must be in your system-specific config location** (which can be overriden via a CLI argument or the **COLUMNLYNX_CONFIG_DIR** Environment Variable).

The defaults depends on your system.

For the server:
- Linux: **/etc/columnlynx**
- macOS: **/etc/columnlynx**
- Windows: **C:\ProgramData\ColumnLynx**

For the client:
- Linux: **~/.config/columnlynx**
- macOS: **~/Library/Application Support/columnlynx**
- Windows: **C:\Users\USERNAME\AppData\Local\ColumnLynx**

### Getting a keypair

Release builds of the software force you to specify your own keypairs. That's why you need to generate a keypair with some other software that you can use.

This guide will show a generation example with openssl:

#### Generate a keypair:
```bash
openssl genpkey -algorithm ED25519 -out key.pem
```

#### Extract the **Private Key Seed**:
```bash
openssl pkey -in key.pem -outform DER | tail -c 32 | xxd -p -c 32
# Output example: 9f3a2b6c0f8e4d1a7c3e9a4b5d2f8c6e1a9d0b7e3f4c2a8e6d5b1f0a3c4e
```

#### Extract the **Raw Public Key**:
```bash
openssl pkey -in key.pem -pubout -outform DER | tail -c 32 | xxd -p -c 32
# Output example: 1c9d4f7a3b2e8a6d0f5c9b1e4d8a7f3c6e2b1a9d5f4c8e0a7b3d6c9f2e
```

You can then set these keys accordingly in the **server_config** and **client_config** files.

### Server Setup (Linux Server ONLY)

#### Creating the Tun Interface

In order for the VPN server to work, you need to create the Tun interface that the VPN will use.

This is the set of commands to create one on Linux. Replace the example 10.10.0.1/24 IPv4 address with the FIRST IPv4 in the Network and Subnet Mask that you set in server_config.
```bash
sudo ip tuntap add dev lynx0 mode tun
sudo ip addr add 10.10.0.1/24 dev lynx0
sudo ip link set dev lynx0 mtu 1420
sudo ip link set dev lynx0 up
```

#### Creating the systemd service

It is highly recommended to **run the server as a systemd service**, as systemd is the primary service manager on Linux.

**1. Create a file for the service**
```bash
sudo touch /etc/systemd/system/columnlynx.service
```

**2. Open the file in your editor of choice**
```bash
sudo nano /etc/systemd/system/columnlynx.service
# OR
sudo vim /etc/systemd/system/columnlynx.service
# OR any other editor of your choice...
```

**3. Configure the service**

**Replace** the **ExecStart** and **WorkingDirectory** paths with the paths where your binaries are stored.

If you configured your tun interface to belong to a custom user, you may also replace the **User** and **Group** with that user, however you must ensure that that user owns the **tun interface**, **config directory in /etc/columnlynx** and the **working directory**.

This is a **simple example** for the **root user** and the executable in **/opt/columnlynx**:

```
[Unit]
Description=ColumnLynx Server Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/columnlynx/columnlynx_server
WorkingDirectory=/opt/columnlynx
User=root
Group=root
Restart=on-failure
StandardOutput=append:/var/log/columnlynx.log
StandardError=append:/var/log/columnlynx.err

[Install]
WantedBy=multi-user.target
```

**4. Reload systemd and enable the service**

```bash
sudo systemctl daemon-reload
sudo systemctl enable columnlynx.service
sudo systemctl start columnlynx.service
```

#### Set firewall rules

This part greatly depends on your firewall of choice. Generally you just need to **allow port 48042 on both TCP and UDP** (Both IPv4 and IPv6).

This example is for **UFW**:

```bash
sudo ufw allow 48042
sudo ufw reload
```


#### IPTables rules for forwarding (Optional)

In addition to creating the interface, you'll also need to make some **iptables** rules if you want to be able to **send traffic to foreign networks** (more like a *commercial VPN*).

You can do these as such (example with NFT IPTABLES):

- Enable the **generic IPv4 forwarding**:
```bash
sudo sysctl net.ipv4.ip_forward=1
```
- Create the masquerade (**Replace the IP subnet** with your own that you set in the config and **replace the interface** with your server's main (NOT *lynx0*) interface):
```bash
sudo nft add table nat
sudo nft add chain nat postroute { type nat hook postrouting priority 100 \; }
sudo nft add rule nat postroute ip saddr 10.10.0.0/24 oifname "eth0" masquerade
```


### Server
 
"**server_config**" is a file that contains the server configuration, **one variable per line**. These are the current configuration available variables:

- **SERVER_PUBLIC_KEY** (Hex String): The public key to be used - Used for verification
- **SERVER_PRIVATE_KEY** (Hex String): The private key seed to be used
- **NETWORK** (IPv4 Format): The network IPv4 to be used (Server Interface still needs to be configured manually)
- **SUBNET_MASK** (Integer): The subnet mask to be used (ensure proper length, it will not be checked)

**Example:**

```
SERVER_PUBLIC_KEY=1c9d4f7a3b2e8a6d0f5c9b1e4d8a7f3c6e2b1a9d5f4c8e0a7b3d6c9f2e
SERVER_PRIVATE_KEY=9f3a2b6c0f8e4d1a7c3e9a4b5d2f8c6e1a9d0b7e3f4c2a8e6d5b1f0a3c4e
NETWORK=10.10.0.0
SUBNET_MASK=24
```

<hr></hr>

"**whitelisted_keys**" is a file that **public keys of clients that are allowed to connect to the server, one key per line**.

**Example:**

```
8CC8BE1A9D24639D0492EF143E84E2BD4C757C9B3B687E7035173EBFCA8FEDDA
338592767CE50DB84674494704E1363C6E43948F722D70DD812F455FCA295792
```

### Client
 
"**client_config**" is a file that contains the client configuration, **one variable per line**. These are the current configuration available variables:

- **CLIENT_PUBLIC_KEY** (Hex String): The public key to be used - Used for verification
- **CLIENT_PRIVATE_KEY** (Hex String): The private key seed to be used

**Example:**

```
CLIENT_PUBLIC_KEY=1c9d4f7a3b2e8a6d0f5c9b1e4d8a7f3c6e2b1a9d5f4c8e0a7b3d6c9f2e
CLIENT_PRIVATE_KEY=9f3a2b6c0f8e4d1a7c3e9a4b5d2f8c6e1a9d0b7e3f4c2a8e6d5b1f0a3c4e
```

<hr></hr>

"**whitelisted_keys**" is a file that **public keys of servers that are allowed to communicate with your client, one key per line**.

**Example:**

```
787B648046F10DDD0B77A6303BE42D859AA65C52F5708CC3C58EB5691F217C7B
8CC8BE1A9D24639D0492EF143E84E2BD4C757C9B3B687E7035173EBFCA8FEDDA
```

## How does it work

ColumnLynx makes use of both **TCP** and **UDP**. **TCP** is used for the initial handshake and commands, which **UDP** is used for actual packet transmission.

It operates on port **48042** for both TCP and UDP.

Current protocol version is **2**.

Generally, all transmission is done in **little-endian byte order**, since pretty much every single modern architecture uses it by default. The only exemption to this is the **transmission of IP addresses** (for the **Virtual Interface**), which is **big-endian**.

### Handshake Procedure

The handshake between the client and server is done over **TCP**. This is to ensure delivery without much hassle.

The procedure will be described packet per packet (line per line) with a **C** or **S** prefix for the client and server, respectfully. After the prefix will be the **Packet ID** and then the data in **<>** tags. Lines without a prefix describe the use / reasoning of the above packet.

```
C: HANDSHAKE_INIT <Client Identity Public Key>
S: HANDSHAKE_IDENTIFY <Server Identity Public Key>
C: HANDSHAKE_CHALLENGE <Random Nonce (32 bytes)>
S: HANDSHAKE_CHALLENGE_RESPONSE <Signed Nonce (Gotten from Previous Packet)>

The Client now generates a random aesKey (32 bytes long)

C: HANDSHAKE_EXCHANGE_KEY <aesKey Encrypted with Server Public Key>

The Server now assigns a local 4 byte session ID in the Session Registry.

S: HANDSHAKE_EXCHANGE_KEY_CONFIRM <Assigned SessionID>
```

The **Client** and **Server** have now securely exchanged a symmetric **AES Key** that they'll use to **encrypt all traffic** sent further out.

### Packet Exchange

Packet exchange and the general data tunneling is done via **Standard UDP** (*see the **UDP Packet** in **Data***).

The **header** of the sent packet always includes a **12 byte nonce** derived from a random **4 byte base nonce** and the **send count** to ensure a unique nonce, used to obscure the **encrypted payload / data** and the **Session ID** assigned by the server to the client (4 bytes). This makes the header **16 bytes long**.

The **payload / data** of the sent packet is **always encrypted** using the exchanged **AES Key** and obscured using the **random nonce**.

*The AES key used is according to the **ChaCha20-Poly1305** algorithm.*

### Connection Termination

The lifetime of a connection is determined based on the lifetime of the **TCP connection** and **Heartbeat packets**.

As soon as the TCP connection terminates, either due to a lost connection, **TCP RST**, **GRACEFUL_DISCONNECT** or **KILL_CONNECTION** packet, etc., the client and server will **stop sending UDP data**. The server will also remove the terminated client from its **Session Registry**.

Additionally, if either party misses **3 of the sent heartbeat packets**, the other party will treat them as dead and remove them.

## Packet Structure

These are the general packet structures for both the TCP and UDP sides of the protocol. Generally **headers** are **plain-text (unencrypted)** and do not contain any sensitive data. 


The **data / payload** section is:
- For **TCP**: **encrypted** or **plain-text** depending on the **packet type** (packets with **sensitive data** are **encrypted**)
- For **UDP**: **encrypted**, as they're transfering the actual data

### TCP Packets

TCP Packets generally follow the structure **Packet ID + Data**. They're only used for the **inital handshake** and **commands sent between the client and server**.

#### Packet ID

The **Packet ID** is an **8 bit unsigned integer** that is predefined from either the **Client to Server** or **Server to Client** enum set, however they are uniquely numbered as to not collide with each other.

**Server to Client** IDs are always below **0xA0** (exclusive) and **Client to Server** IDs are always above **0xA0** (exclusive). **0xF0**, **0xF1**, **0xFE** and **OxFF** are shared for **HEARTBEAT**, **HEARTBEAT_ACK**, **GRACEFUL_DISCONNECT** and **KILL_CONNECTION** respectively.

#### Data

The data section is unspecified. It may change depending on the **Packet ID**. It is encoded as a **raw byte array**

#### Final General Structure

| Type | Length | Name | Description |
|:-----|:-------|:-----|:------------|
| uint8_t | 1 byte | **Header** - Protocol Version | Supported protocol version |
| uint8_t | 1 byte | **Header** - Packet Type | General type of packet |
| uint8_t/byte array | variable | Data | General packet data - changes for packet to packet |

### UDP Packets

**UDP Packets** follow the same general structure of **Packet ID + Data**, however, they are **encrypted in full** with the exchanged AES key. This is done to prevent any metadata leakage by either the client or the server.

The **Data** is generally just the **raw underlying packet** forwarded to the server/client.

#### Final General Structure

| Type | Length | Name | Description |
|:-----|:-------|:-----|:------------|
| uint8_t | 12 bytes | **Header** - Nonce | Random nonce to obfuscate encrypted contents |
| uint32_t | 4 bytes | **Header** - Session ID | The unique and random session identifier for the client |
| uint8_t | variable | Data | General data / payload |

## Misc.
Building the binary for Windows requires the Wintun DLL. The include header is pre-packaged.

## Legal

### Copyright ownership:
Unless explicitly stated otherwise, all source code and material contained in this project
is the copyright of their respective authors, as identified in (but not limited to)
the project's version control history (e.g., Git commit authorship).

Each contribution is provided under the terms of the GNU General Public License,
version 2 or (at your option) any later version, as published by the Free Software Foundation,
unless an individual file or component specifies a different license.

No contributor or maintainer claims exclusive ownership of the entire project.
All rights are retained by their respective authors.

By submitting a contribution, you agree that it will be licensed under the
same dual GPL terms as the project as a whole.

### Licensing:

This project is **dual-licensed** under the GNU General Public License (GPL):

- **GPL version 2 only**, *or*
- **GPL version 3**.

You may choose **either license**, whichever better suits your project or compliance requirements.

Copies of both licenses are provided in the [`LICENSES/`](LICENSES) directory:
- [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt)
- [GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.txt)

Unless you explicitly state otherwise, any contributions you submit will be considered
dual-licensed under the same terms.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

This project includes the [ASIO C++ Library](https://think-async.com/Asio/),
distributed under the [Boost Software License, Version 1.0](https://www.boost.org/LICENSE_1_0.txt).

This project includes the CXXOPTS Library
distributed under the MIT License

This project includes the [Wintun Library](https://www.wintun.net/), distributed under the MIT License or the GPL-2.0 License. This project utilizes it under the MIT license.

*See **ATTRIBUTIONS.md** for details.*
