# ColumnLynx

## What is it?

ColumnLynx is a VPN protocol designed to be as lightweight and simple to understand as possible.

### Origin

The original goal of this project was for me to learn about the inner-workings of VPN protocols, but overtime, it has transformed into the goal seen above.

### Design Philosophy

A VPN (Virtual Private Network), in the most basic terms, is a protocol that tunnels network traffic from a client to a server over an encrypted tunnel and having the server send that traffic on its behalf. It can be catagorized into sitting somewhere in-between the 3rd and 4th layers of the ISO/OSI model.

This project aims to be just that, an encrypted tunneling protocol that works on the 3rd and 4th layers of the ISO/OSI model, nothing more, nothing less. We leave complex functions like compression, to the higher layers (though it could be argued that making an encrypted tunnel already pushes us up to Layer 6).

This simplicity-focused design approach allows us to make an efficient, low-overhead VPN protocol and minimize any potential attack surface.

## How does it work

ColumnLynx makes use of both **TCP** and **UDP**. **TCP** is used for the initial handshake and commands, which **UDP** is used for actual packet transmission.

It operates on port **48042** for both TCP and UDP.

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

The Server now assigns a local 8 byte session ID in the Session Registry.

S: HANDSHAKE_EXCHANGE_KEY_CONFIRM <Assigned SessionID>
```

The **Client** and **Server** have now securely exchanged a symmetric **AES Key** that they'll use to **encrypt all traffic** sent further out.

### Packet Exchange

Packet exchange and the general data tunneling is done via **Standard UDP** (*see the **UDP Packet** in **Data***).

The **header** of the sent packet always includes a **random 12 byte nonce** used to obscure the **encrypted payload / data** and the **Session ID** assigned by the server to the client (8 bytes). This makes the header **20 bytes long**.

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
| uint64_t | 8 bytes | **Header** - Session ID | The unique and random session identifier for the client |
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

This project includes the [Wintun Library](https://www.wintun.net/), distributed under the MIT License or the GPL-2.0 License.

*See **ATTRIBUTIONS.md** for details.*