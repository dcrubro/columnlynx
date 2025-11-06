# ColumnLynx

ColumnLynx is a VPN protocol designed to be as lightweight as possible.

## How does it work

ColumnLynx makes use of both **TCP** and **UDP**. **TCP** is used for the initial handshake and commands, which **UDP** is used for actual packet transmission.

It operates on port **48042** for both TCP and UDP.

## Packet Structure

### TCP Packets

TCP Packets generally follow the structure **Packet ID + Data**

#### Packet ID

The **Packet ID** is an **8 bit unsigned integer** that is predefined from either the **Client to Server** or **Server to Client** enum set, however they are uniquely numbered as to not collide with each other.

**Server to Client** IDs are always below **0xA0** (exclusive) and **Client to Server** IDs are always above **0xA0** (exclusive). **0xFE** and **OxFF** are shared for **GRACEFUL_DISCONNECT** and **KILL_CONNECTION** respectively.


#### Data

The data section is unspecified. It may change depending on the **Packet ID**. It is encoded as a **raw byte array**

### UDP Packets

*WIP, fill in later*

## Legal

Copyright (C) 2025 Jonas Korene Novak

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

DcruBro is the online pseudonym of Jonas Korene Novak. Both refer to the same individual and may be used interchangeably for copyright attribution purposes.

### Licensing

This project includes the [ASIO C++ Library](https://think-async.com/Asio/),
distributed under the [Boost Software License, Version 1.0](https://www.boost.org/LICENSE_1_0.txt).