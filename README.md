
# File Sharing System

This project implements a simple file-sharing system with a tracker server and client communication using sockets in C++. The server can manage multiple clients and handle user commands such as creating users, joining groups, and more.

## Prerequisites

- A C++ compiler (like g++)
- OpenSSL development libraries (for hashing)
- Basic knowledge of C++ and networking concepts

## File Structure

- `tracker/tracker.cpp`: Source code for the tracker server.
- `client/client.cpp`: Source code for the client application.
- `info.txt`: A file containing server IPs and ports. [In both folders]

## Instructions

### 1. Prepare `info.txt`

Create a file named `info.txt` in the same directory with the following format:

```
127.0.0.1:8080
127.0.0.1:8081
```

Replace the IP addresses and ports with the appropriate values for your setup.

### 2. Build and Run the Tracker

Open your terminal and execute the following commands:

```bash
# Compile the tracker code
g++ tracker.cpp -o tracker

# Run the tracker, specifying the info file and tracker number
./tracker info.txt 0
```

### 3. Build and Run the Client

In a separate terminal, execute the following commands:

```bash
# Compile the client code with OpenSSL libraries
g++ client.cpp -o client -lcrypto -lssl

# Run the client, specifying the tracker address and info file
./client 0
```

### 4. Client Commands

Once connected to the tracker, you can enter the following commands:
__Press Enter after each keyword__ *Input via getLine*

- `create_user`: Create a new user.
- `login`: Log in as an existing user.
- `create_group`: Create a new group.
- `join_group`: Join an existing group.
- `leave_group`: Leave a group.
- `list_requests`: List pending friend requests.
- `accept_request`: Accept a pending friend request.
- `list_groups`: List all available groups.
- `quit`: Disconnect from the tracker.
