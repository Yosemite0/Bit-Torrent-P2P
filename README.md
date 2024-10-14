
# File Sharing System [P2P Network]

## Name : Yash Chordia

## Overview

This project implements a simple file-sharing system with two tracker server and client communication using sockets in C++. The server can manage multiple clients and handle user commands such as creating users, joining groups, and more. The clients can upload and download files from the groups they are a part of. The trackers can sync files between them and load balance the clients.

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
./tracker info.txt <tracker_no.>
```

### 3. Build and Run the Client

In a separate terminal, execute the following commands:

```bash
# Compile the client code with OpenSSL libraries
g++ client.cpp -o client -lcrypto -lssl


# Run the client, specifying the client address and tracker number
./client <ip>:<port> <tracker_no.>
```

### 4. Client Commands

Once connected to the tracker, you can enter the following commands:
__Press Enter after each keyword__ *Input via getLine*

=> User/Session management:
- `create_user`: Create a new user.
- `login`: Log in as an existing user.
- `logout`: Log out from the current session.

=> Group management:
- `create_group`: Create a new group.
- `join_group`: Join an existing group.
- `leave_group`: Leave a group.
- `list_requests`: List pending friend requests.
- `accept_request`: Accept a pending friend request.
- `list_groups`: List all available groups.

=> File management:
- `list_files`: List all files in a group.
- `upload_file`: Upload a file to a group.
- `download_file`: Download a file from a group.

=>  File sharing controls:
- `stop_share`: Stop sharing a file.
- `show_downloads`: Show all downloads.
- `quit`: Disconnect from the tracker.

### 5. Syncing Files and Load Balancing

The trackers are able to sync files and load balance the clients. The clients can upload and download files from any tracker, and the trackers will sync the files between them. It enables the clients to connect to any tracker and access the files shared by other clients from any group.

### 6. Additional Notes
- The client can only upload/download files from groups they are a part of.
- Each user must have a unique username.
- Each group must have a unique group name.
- Each file must have a unique name.
- A file can exist in only one group.
