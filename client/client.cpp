#include <iostream>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <bits/stdc++.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <signal.h>
#include <dirent.h>
#include <thread>
#include <vector>
#include <mutex>


using namespace std;


int tracker_sock;
int client_sock;
int tracker_port;
int client_port;
int CHUNK_SIZE = 512 * 1024;


struct File_info {
    string file_name;
    // string file_hash;
    int file_size;
    unordered_map<int,pair<int,string>> chunks_hash;
};

struct download_file_info {
    string status = "Pending";
    string file_name;
    int total_chunks;
    unordered_map<int, string> chunks_hash;
};

struct Chunk {
    int chunk_num;
    int size;
    string hash;
    vector<int> sockets;
};

struct File_info_tracker {
    string file_name;
    int file_size;
    unordered_set<string> group_ids;
    unordered_map<int, Chunk> chunks;
};;

void sigHandler(int sigNum) {
    cout << "SigInt received. Closing sockets..." << endl;
    close(tracker_sock);
    close(client_sock);
    exit(EXIT_SUCCESS);
}


vector<string> split(const string &str, char delim = ' ')
{
    vector<string> tokens;
    stringstream ss(str);
    string token;
    while (getline(ss, token, delim))
    {
        tokens.push_back(token);
    }
    return tokens;
}

string sha1_hash(const string &input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);

    string hashed;
    char buf[3];
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        snprintf(buf, sizeof(buf), "%02x", hash[i]);
        hashed += buf;
    }
    return hashed.substr(24);
}

string send_command(int sock, const string &command) {
    send(sock, command.c_str(), command.size(), 0);
    char buffer[16*1024];
    memset(buffer, 0, sizeof(buffer));
    int bytes_read = read(sock, buffer, sizeof(buffer));
    return string(buffer);
}

void write_chunks_to_files(const string &file_name, int chunk_size = CHUNK_SIZE) {
    string client_folder = "./" + to_string(client_port);
    string chunk_folder = client_folder + "/0_" + file_name;

    struct stat st;
    if (stat(chunk_folder.c_str(), &st) == -1) {
        mkdir(chunk_folder.c_str(), 0700);
    }

    FILE *file = fopen((client_folder + "/" + file_name).c_str(), "rb");
    if (file == NULL) {
        cerr << "Failed to open file: " << strerror(errno) << endl;
        exit(EXIT_FAILURE);
    }

    char buffer[chunk_size];
    int bytes_read;
    int chunk_num = 0;
    while ((bytes_read = fread(buffer, 1, chunk_size, file)) > 0) {
        // Write the chunk to a file in the chunk folder
        string chunk_file_name = chunk_folder + "/" + to_string(chunk_num);
        FILE *chunk_file = fopen(chunk_file_name.c_str(), "wb");
        if (chunk_file == NULL) {
            cerr << "Failed to create chunk file: " << strerror(errno) << endl;
            fclose(file);
            exit(EXIT_FAILURE);
        }
        fwrite(buffer, 1, bytes_read, chunk_file);
        fclose(chunk_file);
        chunk_num++;
    }
    fclose(file);
}

File_info create_file_info(const string &file_name, int chunk_size = CHUNK_SIZE) {
    string client_folder = "./" + to_string(client_port);
    string chunk_folder = client_folder + "/0_" + file_name;

    File_info info;
    info.file_name = file_name;

    struct dirent *entry;
    DIR *dp = opendir(chunk_folder.c_str());
    if (dp == NULL) {
        cerr << "Failed to open chunk folder: " << strerror(errno) << endl;
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dp))) {
        if (entry->d_type == DT_REG) {
            string chunk_file_name = chunk_folder + "/" + entry->d_name;
            FILE *chunk_file = fopen(chunk_file_name.c_str(), "rb");
            if (chunk_file == NULL) {
                cerr << "Failed to open chunk file: " << strerror(errno) << endl;
                closedir(dp);
                exit(EXIT_FAILURE);
            }

            fseek(chunk_file, 0, SEEK_END);
            int chunk_size = ftell(chunk_file);
            fseek(chunk_file, 0, SEEK_SET);

            char *buffer = new char[chunk_size];
            fread(buffer, 1, chunk_size, chunk_file);
            fclose(chunk_file);

            string chunk(buffer, chunk_size);
            info.chunks_hash[stoi(entry->d_name)] = {chunk_size, sha1_hash(chunk)};
            delete[] buffer;
        }
    }
    closedir(dp);

    // Calculate total file size
    info.file_size = 0;
    for (const auto &chunk : info.chunks_hash) {
        info.file_size += chunk.second.first;
    }


    return info;
}

string upload_file_info(const File_info &info, const string &group_id) {
    string file_info = info.file_name + " " + to_string(info.file_size) + " " + group_id + " " + to_string(info.chunks_hash.size());
    for (auto &chunk : info.chunks_hash) {
        file_info += " " + to_string(chunk.first) + " " +to_string(chunk.second.first) + " " + chunk.second.second;
    }
    return send_command(tracker_sock, "upload_file " + file_info);
}

File_info_tracker deserialize_file_tracker(const string &response) {
    vector<string> tokens = split(response);
    File_info_tracker file;
    
    // Read file name
    size_t idx = 1;
    file.file_name = tokens[idx++];    
    file.file_size = stoi(tokens[idx++]);    
    int num_chunks = stoi(tokens[idx++]);
    
    for (int i = 0; i < num_chunks; ++i) {
        Chunk chunk;
        
        int chunk_num = stoi(tokens[idx++]);
        chunk.chunk_num = chunk_num;
        chunk.size = stoi(tokens[idx++]);
        chunk.hash = tokens[idx++];        
        int num_sockets = stoi(tokens[idx++]);
        for (int j = 0; j < num_sockets; ++j) {
            int socket = stoi(tokens[idx++]);
            chunk.sockets.push_back(socket);
        }
        file.chunks[chunk_num] = chunk;
    }
    
    return file;
}

File_info_tracker get_response_file_info(string &response){
    File_info_tracker file_tracker = deserialize_file_tracker(response);
    cout << "Received response from tracker" << endl;
    for(auto i : file_tracker.chunks){
        cout << i.first << " " << i.second.chunk_num << " " << i.second.size << " " << i.second.hash << endl;
    }
    cout << "File Name: " << file_tracker.file_name << endl;
    return file_tracker;
}

bool getChunk(int peer_fd, const string& file_name, int chunk_num, int chunk_size, const string& chunk_hash) {
    string client_folder = "./" + to_string(client_port);
    string chunk_folder = client_folder + "/0_" + file_name;
    string chunk_file_name = chunk_folder + "/" + to_string(chunk_num);
    
    vector<char> chunk_data(chunk_size);
    
    string command_str = "get_chunk " + file_name + " " + to_string(chunk_num);
    cout << "Requesting chunk " << chunk_num << " for file " << file_name << " from peer." << endl;
    if (send(peer_fd, command_str.c_str(), command_str.size(), 0) == -1) {
        cerr << "Failed to send chunk request: " << strerror(errno) << endl;
        return false;
    }
    
    int total_bytes_read = 0;
    while (total_bytes_read < chunk_size) {
        int bytes_read = recv(peer_fd, chunk_data.data() + total_bytes_read, chunk_size - total_bytes_read, 0);
        if (bytes_read <= 0) {
            if (bytes_read == 0) {
                cerr << "Connection closed by peer before receiving full chunk" << endl;
            } else {
                cerr << "Failed to read chunk data from peer: " << strerror(errno) << endl;
            }
            return false;
        }
        total_bytes_read += bytes_read;
    }
    
    string calculated_hash = sha1_hash(string(chunk_data.begin(), chunk_data.end()));
    cout << "Received chunk " << chunk_num << " with hash: " << calculated_hash << endl;
    if (calculated_hash != chunk_hash) {
        cerr << "Chunk hash mismatch. Expected: " << chunk_hash << ", Got: " << calculated_hash << endl;
        return false;
    }
    
    FILE *chunk_file = fopen(chunk_file_name.c_str(), "wb");
    if (chunk_file == NULL) {
        cerr << "Failed to open chunk file for writing: " << strerror(errno) << endl;
        return false;
    }
    size_t bytes_written = fwrite(chunk_data.data(), 1, chunk_size, chunk_file);
    fclose(chunk_file);
    
    if (bytes_written != static_cast<size_t>(chunk_size)) {
        cerr << "Failed to write full chunk to file" << endl;
        return false;
    }
    
    cout << "Successfully wrote chunk " << chunk_num << " to file." << endl;
    return true;
}

void downloadChunk(const File_info_tracker& file_tracker, int chunk_num, int peer_socket, std::mutex& mtx, download_file_info& downloads) {
    const Chunk& chunk = file_tracker.chunks.at(chunk_num);
    
    bool success = false;
    int retry_count = 0;

    // Try to download the chunk up to 3 times
    // while (!success && retry_count < 3) {
        // cout << "Attempt " << (retry_count + 1) << " to download chunk " << chunk_num << "." << endl; // Debug statement
        success = getChunk(peer_socket, file_tracker.file_name, chunk_num, chunk.size, chunk.hash);
        retry_count++;
    // }

    // Lock the mutex to safely update shared resources
    std::lock_guard<std::mutex> lock(mtx);
    if (success) {
        downloads.chunks_hash[chunk_num] = chunk.hash;
        // cout << "Successfully downloaded chunk " << chunk_num << "." << endl; // Debug statement
    } else {
        downloads.status = "Error";
        // cerr << "Failed to download chunk " << chunk_num << " after 3 attempts." << endl;
    }
}

bool mergeChunks(const string& file_name, int total_chunks , string dest_file_path) {
    // Create the final output file
    string output_file_name = dest_file_path;
    FILE *output_file = fopen(output_file_name.c_str(), "wb");
    if (output_file == NULL) {
        cerr << "Failed to open output file for merging: " << strerror(errno) << endl;
        return false;
    }
    
    // Iterate through all chunks and write them to the output file
    for (int chunk_num = 0; chunk_num < total_chunks; ++chunk_num) {
        string chunk_file_name = "./" + to_string(client_port) + "/0_" + file_name + "/" + to_string(chunk_num);
        FILE *chunk_file = fopen(chunk_file_name.c_str(), "rb");
        if (chunk_file == NULL) {
            cerr << "Failed to open chunk file: " << strerror(errno) << endl;
            fclose(output_file);
            return false;
        }
        
        // Read chunk data and write it to the output file
        char buffer[1024]; // Buffer to hold data temporarily
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), chunk_file)) > 0) {
            fwrite(buffer, 1, bytes_read, output_file);
        }
        
        fclose(chunk_file);
    }
    
    fclose(output_file);
    // cout << "All chunks merged into: " << output_file_name << endl;
    return true;
}

void download(File_info_tracker &file_tracker,string dest_file_path) {
    string client_folder = "./" + to_string(client_port);
    string file_folder = client_folder + "/0_" + file_tracker.file_name;

    // Create directory for downloading chunks
    struct stat st;
    if (stat(file_folder.c_str(), &st) == -1) {
        mkdir(file_folder.c_str(), 0700);
        cout << "Created folder: " << file_folder << endl; // Debug statement
    }

    // Initialize download status
    download_file_info downloads;
    downloads.status = "Downloading";
    downloads.total_chunks = file_tracker.chunks.size();
    downloads.file_name = file_tracker.file_name;

    std::mutex mtx; // Mutex for thread-safe updates
    std::vector<std::thread> threads; // Vector to hold threads

    // Iterate through each chunk and download it
    for (const auto &chunk_pair : file_tracker.chunks) {
        int chunk_num = chunk_pair.first;
        const Chunk& chunk = chunk_pair.second;

        // Create a peer socket for each chunk
        int peer_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (peer_fd < 0) {
            cerr << "Failed to create peer socket" << endl;
            exit(EXIT_FAILURE);
        }

        sockaddr_in peer_addr;
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Assuming localhost for now
        peer_addr.sin_port = htons(chunk.sockets[0]); // Use first available socket

        // Try to connect to the peer
        if (connect(peer_fd, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
            cerr << "Failed to connect to peer: " << strerror(errno) << endl;
            close(peer_fd);
            continue; // Continue to the next chunk
        }

        // Download the chunk synchronously
        downloadChunk(file_tracker, chunk_num, peer_fd, mtx, downloads);
        close(peer_fd); // Close peer socket after downloading the chunk
    }

    // Check download status
    if (downloads.status != "Error") {
        bool status = mergeChunks(file_tracker.file_name, downloads.total_chunks, dest_file_path);
        if(status)
        downloads.status = "Completed";
        else {
            downloads.status = "Error while merging chuunks";
        }
    }
}

void give_chunk(int peer_sock, const string &file_name, int chunk_num) {
    string client_folder = "./" + to_string(client_port);
    string chunk_folder = client_folder + "/0_" + file_name;
    string chunk_file_name = chunk_folder + "/" + to_string(chunk_num);

    FILE *chunk_file = fopen(chunk_file_name.c_str(), "rb");
    if (chunk_file == NULL) {
        cerr << "Failed to open chunk file: " << strerror(errno) << endl;
        return;
    }

    fseek(chunk_file, 0, SEEK_END);
    long chunk_size = ftell(chunk_file);
    fseek(chunk_file, 0, SEEK_SET);

    vector<char> buffer(chunk_size);
    size_t bytes_read = fread(buffer.data(), 1, chunk_size, chunk_file);
    fclose(chunk_file);
    
    if (bytes_read != static_cast<size_t>(chunk_size)) {
        cerr << "Failed to read entire chunk from file" << endl;
        return;
    }

    size_t total_sent = 0;
    while (total_sent < bytes_read) {
        ssize_t sent = send(peer_sock, buffer.data() + total_sent, bytes_read - total_sent, 0);
        if (sent == -1) {
            cerr << "Error sending chunk data: " << strerror(errno) << endl;
            return;
        }
        total_sent += sent;
    }

    cout << "Sent chunk " << chunk_num << " of file " << file_name << " to peer." << endl;
}

void handleCommand(string command) {
    if (command == "create_user") {
        string username, password;
        cout << "Enter username: ";
        getline(cin, username);
        cout << "Enter password: ";
        getline(cin, password);
        string hashed_credentials = sha1_hash(username + password);

        string response = send_command(tracker_sock, "create_user " + username + " " + hashed_credentials);
        cout << "Response: " << response << endl;
    } else if (command == "login") {
        string username, password;
        cout << "Enter username: ";
        getline(cin, username);
        cout << "Enter password: ";
        getline(cin, password);
        string hashed_credentials = sha1_hash(username + password);

        string response = send_command(tracker_sock, "login " + username + " " + hashed_credentials + " " + to_string(client_port));
        cout << "Response: " << response << endl;
    } else if (command == "create_group") {
        string group_id;
        cout << "Enter group ID: ";
        getline(cin, group_id);

        string response = send_command(tracker_sock, "create_group " + group_id);
        cout << "Response: " << response << endl;
    } else if (command == "join_group") {
        string group_id;
        cout << "Enter group ID: ";
        getline(cin, group_id);

        string response = send_command(tracker_sock, "join_group " + group_id);
        cout << "Response: " << response << endl;
    } else if (command == "leave_group") {
        string group_id;
        cout << "Enter group ID: ";
        getline(cin, group_id);

        string response = send_command(tracker_sock, "leave_group " + group_id);        
        cout << "Response: " << response << endl;
    } else if (command == "list_requests") {
        string group_id;
        cout << "Enter group ID: ";
        getline(cin, group_id);

        string response = send_command(tracker_sock, "list_requests " + group_id);
        cout << "Response: " << response << endl;

    } else if (command == "accept_request") {
        string group_id;
        cout << "Enter group ID: ";
        getline(cin, group_id);
        string username;
        cout << "Enter username to accept: ";
        getline(cin, username);

        string response = send_command(tracker_sock, "accept_request " + group_id + " " + username);        
        cout << "Response: " << response << endl;

    } else if (command == "list_groups") {
        string group_id;
        cout << "Enter group ID: ";
        getline(cin, group_id);        

        string response = send_command(tracker_sock, "list_groups " + group_id);        
        cout << "Response: " << response << endl;

    } else if(command == "upload_file"){
        cout << "Enter file name: ";
        string file_name; 
        getline(cin, file_name);
        cout << "Enter group ID: ";
        string group_id; 
        getline(cin, group_id);
        write_chunks_to_files(file_name);
        File_info upload_file = create_file_info(file_name);
        string response = upload_file_info(upload_file, group_id);
        
        cout << "Response: " << response << endl;

    } else if(command == "upload_chunks"){
        cout << "Enter file name: ";
        string file_name; 
        getline(cin, file_name);
        cout << "Enter group ID: ";
        string group_id; 
        getline(cin, group_id);
        File_info upload_file = create_file_info(file_name);

        string response =  upload_file_info(upload_file, group_id);        
        cout << "Response: " << response << endl; 

    } else if(command == "list_files"){
        string group_id;
        cout << "Enter group ID: ";
        getline(cin, group_id);

        string response = send_command(tracker_sock, "list_files " + group_id);           
        cout << "Response: " << response << endl; 

    } else if (command == "download_file"){
        string group_id;
        cout << "Enter group ID: ";
        getline(cin, group_id);
        string file_name;
        cout << "Enter file name: ";
        getline(cin, file_name);
        string dest_file_path;
        cout << "Enter Destination address ";
        getline(cin , dest_file_path);


        string response = send_command(tracker_sock, "download_file " + group_id + " " + file_name);
        if(response.find("success") == 0){
            File_info_tracker file_tracker =  get_response_file_info(response);
            cout << "Downloading: " << file_tracker.file_name << endl;   
            download(file_tracker, dest_file_path);
            cout << "Download completed" << endl;
        }
        else {
            cout << "Response: " << response << endl;
        }
    } else {
        cout << "Unknown command." << endl;
    }
}

void process_peer_request(int peer_sock) {
    char buffer[256] = {0};
    int bytes_received = recv(peer_sock, buffer, sizeof(buffer), 0);
    if (bytes_received > 0) {
        stringstream ss(buffer);
        string command, file_name;
        int chunk_num;

        ss >> command >> file_name >> chunk_num;
        cout << "Parsed request: command = " << command << ", file_name = " << file_name << ", chunk_num = " << chunk_num << endl;

        if (command == "get_chunk") {
            cout << "Handling get_chunk request for file: " << file_name << ", chunk: " << chunk_num << endl;
            give_chunk(peer_sock, file_name, chunk_num);
            close(peer_sock);
            cout << "Closed connection with peer after processing request." << endl;
        } else {
            cerr << "Unknown command received: " << command << endl;
            close(peer_sock);
        }
    } else {
        cerr << "Failed to receive data from peer: " << strerror(errno) << endl;
        close(peer_sock);
    }
}

void accept_peer_connections(int client_sock) {
    while (true) {
        int peer_sock = accept(client_sock, NULL, NULL);
        if (peer_sock < 0) {
            cerr << "Failed to accept peer connection: " << strerror(errno) << endl;
            continue;
        }

        cout << "Accepted a new connection from peer." << endl;
        thread(process_peer_request, peer_sock).detach();
    }
}

void handle_request(int client_sock) {
    accept_peer_connections(client_sock);
}

void open_client_port(int port) {
    client_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sock < 0) {
        cerr << "Failed to create client socket" << endl;
        exit(EXIT_FAILURE);
    }

    sockaddr_in client_addr;
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(port);

    if (bind(client_sock, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0) {
        cerr << "Failed to bind client socket: " << strerror(errno) << endl;
        close(client_sock);
        client_sock = -1;
        exit(EXIT_FAILURE);
    }

    listen(client_sock, SOMAXCONN); 
    cout << "Opened client port: " << port << endl;
}

void connect_to_tracker(const string &ip, int port) {
    tracker_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tracker_sock < 0) {
        cerr << "Failed to create tracker socket" << endl;
        exit(EXIT_FAILURE);
    }

    sockaddr_in tracker_addr;
    tracker_addr.sin_family = AF_INET;
    tracker_addr.sin_addr.s_addr = inet_addr(ip.c_str());
    tracker_addr.sin_port = htons(port);

    if (connect(tracker_sock, (struct sockaddr*)&tracker_addr, sizeof(tracker_addr)) < 0) {
        cerr << "Connection to tracker failed: " << strerror(errno) << endl;
        close(tracker_sock);
        exit(EXIT_FAILURE);
    }

    cout << "Connected to tracker at " << ip << ":" << port << endl;
}

void start_client(const string &tracker_ip, int tracker_port, int client_port) {
    open_client_port(client_port);
    connect_to_tracker(tracker_ip, tracker_port);
    thread(handle_request, client_sock).detach();

    signal(SIGINT, sigHandler);

    string command;
    while (true) {
        cout << "\nEnter command (create_user, login, create_group, join_group, leave_group, list_requests, accept_request, list_groups, quit): ";
        getline(cin, command);

        if (command == "quit") {
            break;
        }
        handleCommand(command);
    }

    close(tracker_sock);
    close(client_sock);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <ip>:<client_port> <tracker_number>" << endl;
        return EXIT_FAILURE;
    }
    string ip_port = argv[1];
    client_port = stoi(ip_port.substr(ip_port.find_last_of(':')));
    int tracker_number = stoi(argv[2]);

    FILE *info_file = fopen("info.txt", "r");
    if (info_file == NULL) {
        cerr << "Failed to open info.txt" << endl;
        return EXIT_FAILURE;
    }

    char line[256];
    int current_tracker = 0;
    string tracker_ip;
    while (fgets(line, sizeof(line), info_file)) {
        if (current_tracker == tracker_number) {
            istringstream iss(line);
            iss >> tracker_ip >> tracker_port;
            break;
        }
        current_tracker++;
    }

    fclose(info_file);

    if (tracker_ip.empty() || tracker_port <= 0) {
        cerr << "Invalid tracker number or details not found." << endl;
        return EXIT_FAILURE;
    }

    string client_folder = "./" + to_string(client_port);
    struct stat st;
    if (stat(client_folder.c_str(), &st) == -1) {
        mkdir(client_folder.c_str(), 0700);
    }

    start_client(tracker_ip, tracker_port, client_port);

    return 0;
}