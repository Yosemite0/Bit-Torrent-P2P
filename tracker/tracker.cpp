#include <iostream>
#include <unordered_map>
#include <map>
#include <set>
#include <unordered_set>
#include <vector>
#include <thread>
#include <mutex>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <cstring>
#include <sstream>
#include <fcntl.h>
#include <errno.h>

using namespace std;

mutex tracker_mutex;

int server_socket;

struct User;
struct Group;

struct User
{
    string user_id;
    string hashed_passwd;
    bool isActive;
    unordered_set<string> files;
    unordered_map<string, bool> group_owned;
    unordered_map<string, bool> groups;
};

struct Group
{
    string group_id;
    string owner_id;
    unordered_set<string> files;
    unordered_map<string, bool> members;
    unordered_map<string, bool> requests; // Track join requests
};

struct Chunk {
    int chunk_num;
    int size;
    string hash;
    unordered_set<int> sockets;
};

struct File_info {
    string file_name;
    int file_size;
    unordered_set<string> group_ids;
    unordered_map<int, Chunk> chunks;
};;

unordered_map <string,File_info> files;
unordered_map <int, string> session;
unordered_map <string, pair<int,int>> logged_in;
unordered_map <string, User> users;
unordered_map <string, Group> groups;

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

vector<string> parse_command(const string &command)
{
    return split(command, ' ');
}

void signalHandler(int sig_num)
{
    cout << "Signal received, shutting down server.\n";
    close(server_socket);
    exit(EXIT_SUCCESS);
}

void send_response(int client_socket, const string &response)
{
    send(client_socket, response.c_str(), response.size(), 0);
}

bool validate_logged_in(int client_socket)
{
    lock_guard<mutex> lock(tracker_mutex);
    if (session.find(client_socket) == session.end())
    {
        send_response(client_socket, "User not logged in\n");
        return false;
    }
    return true;
}

bool validate_group(int client_socket, string group_id){
    lock_guard<mutex> lock(tracker_mutex);
    auto it = groups.find(group_id);
    string user_id = session[client_socket];
    if (it == groups.end() || it->second.members.find(user_id) == it->second.members.end())
    {
        send_response(client_socket,"User not present in group\n");
        return false;
    }
    return true;
}

void create_user(int client_socket, const string &command)
{
    vector<string> tokens = parse_command(command);
    if (tokens.size() != 3)
    {
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    string user_id = tokens[1];
    string hashed_passwd = tokens[2];

    lock_guard<mutex> lock(tracker_mutex);
    if (users.find(user_id) != users.end())
    {
        send_response(client_socket, "User already exists\n");
        return;
    }
    users[user_id] = User{user_id, hashed_passwd, false, unordered_set<string>(), unordered_map<string, bool>(), unordered_map<string, bool>()};
    send_response(client_socket, "User registered successfully\n");
}

void login_user(int client_socket, const string &command)
{
    vector<string> tokens = parse_command(command);
    if (tokens.size() != 4)
    {
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    string user_id = tokens[1];
    string hashed_passwd = tokens[2];
    int port = stoi(tokens[3]);

    lock_guard<mutex> lock(tracker_mutex);
    if (session.find(client_socket) != session.end())
    {
        send_response(client_socket, (session[client_socket] + " is already logged in\n"));
        return;
    }
    if (logged_in.find(user_id) != logged_in.end())
    {
        send_response(client_socket, (user_id + " is already logged in\n"));
        return;
    }
    auto it = users.find(user_id);
    if (it != users.end() && it->second.hashed_passwd == hashed_passwd)
    {
        session[client_socket] = user_id;
        logged_in[user_id] = {client_socket, port};
        users[user_id].isActive = true;
        send_response(client_socket, "Login success\n");
    }
    else
    {
        send_response(client_socket, "Login failed\n");
    }
}

void create_group(int client_socket, const string &command)
{
    if (!validate_logged_in(client_socket))
        return;

    vector<string> tokens = parse_command(command);
    if (tokens.size() != 2)
    {
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    string group_id = tokens[1];

    lock_guard<mutex> lock(tracker_mutex);
    if (groups.find(group_id) != groups.end())
    {
        send_response(client_socket, "Group already exists\n");
        return;
    }

    string user_id = session[client_socket];
    Group new_group = {group_id, user_id};
    groups[group_id] = new_group;
    users[user_id].group_owned[group_id] = true;
    groups[group_id].members[user_id] = true;

    send_response(client_socket, "Group created\n");
}

void join_group(int client_socket, const string &command)
{
    if (!validate_logged_in(client_socket))
        return;

    vector<string> tokens = parse_command(command);
    if (tokens.size() != 2)
    {
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    string group_id = tokens[1];
    string user_id = session[client_socket];

    lock_guard<mutex> lock(tracker_mutex);
    auto it = groups.find(group_id);
    if (it == groups.end())
    {
        send_response(client_socket, "Group does not exist\n");
        return;
    }

    Group &group = it->second;
    if (group.members.find(user_id) != group.members.end())
    {
        send_response(client_socket, "You are already a member of this group\n");
        return;
    }

    if (group.requests.find(user_id) != group.requests.end())
    {
        send_response(client_socket, "Join request already sent\n");
        return;
    }

    group.requests[user_id] = true;
    send_response(client_socket, "Join request sent successfully\n");
}

void leave_group(int client_socket, const string &command)
{
    if (!validate_logged_in(client_socket))
        return;

    vector<string> tokens = parse_command(command);
    if (tokens.size() != 2)
    {
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    string group_id = tokens[1];
    string user_id = session[client_socket];

    lock_guard<mutex> lock(tracker_mutex);
    auto it = groups.find(group_id);
    if (it != groups.end())
    {
        Group &group = it->second;
        if (group.owner_id == user_id)
        {
            if (group.members.size() > 1)
            {
                for (auto &member : group.members)
                {
                    if (member.first != user_id)
                    {
                        group.owner_id = member.first;
                        send_response(client_socket, "You left the group. New owner is " + member.first + "\n");
                        break;
                    }
                }
            }
            else
            {
                groups.erase(group_id);
                send_response(client_socket, "Group was removed since no members remain\n");
                return;
            }
        }
        group.members.erase(user_id);   // Remove user from members
        users[user_id].groups.erase(group_id); // Remove from user's groups
        send_response(client_socket, "Left group successfully\n");
    }
    else
    {
        send_response(client_socket, "You are not a member of this group\n");
    }
}

void list_groups(int client_socket, const string &command){
    lock_guard<mutex> lock(tracker_mutex);

    string response = "Available groups:\n";
    for (const auto &group : groups)
    {
        response += group.first + "\n";
    }

    if (groups.empty())
    {
        response = "No groups available\n";
    }

    send_response(client_socket, response);
}

void list_requests(int client_socket, const string &command) {
    if (!validate_logged_in(client_socket))
        return;

    vector<string> tokens = parse_command(command);
    if (tokens.size() != 2)
    {
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    string group_id = tokens[1];
    string user_id = session[client_socket];

    lock_guard<mutex> lock(tracker_mutex);
    auto it = groups.find(group_id);
    if (it == groups.end() || it->second.owner_id != user_id)
    {
        send_response(client_socket, "You are not owner of this group\n");
        return;
    }
    string response = "Join requests:\n";
    for (const auto &request : it->second.requests)
    {
        response += request.first + "\n";
    }
    if (it->second.requests.empty())
    {
        response = "No join requests\n";
    }
    send_response(client_socket, response);
}

void accept_request(int client_socket, const string &command)
{
    if (!validate_logged_in(client_socket))
        return;

    vector<string> tokens = parse_command(command);
    if (tokens.size() != 3)
    {
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    string group_id = tokens[1];
    string user_id = tokens[2];

    string owner_id = session[client_socket];

    lock_guard<mutex> lock(tracker_mutex);
    auto it = groups.find(group_id);
    if (it == groups.end() || it->second.owner_id != owner_id)
    {
        send_response(client_socket, "You are not the owner of this group or the group does not exist\n");
        return;
    }

    Group &group = it->second;
    if (users.find(user_id) != users.end() && group.requests.find(user_id) != group.requests.end())
    {
        group.members[user_id] = true;
        group.requests.erase(user_id); // Remove from requests
        send_response(client_socket, "Request accepted\n");
    }
    else
    {
        send_response(client_socket, "Request does not exist or user not found\n");
    }
}

void upload_file(int client_socket, const string &command)
{
    if (!validate_logged_in(client_socket))
        return;

    vector<string> tokens = parse_command(command);
    if (tokens.size() < 6)
    {
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    string file_name = tokens[1];
    int file_size = stoi(tokens[2]);
    string group_id = tokens[3];
    int chunk_number = stoi(tokens[4]);

    if(tokens.size() != 5 + 3*chunk_number){
        send_response(client_socket, "Insufficent Information\n");
        return;
    }
    if(!validate_group(client_socket,group_id)){
        return;
    }

    string user_id = session[client_socket];
    int port = logged_in[user_id].second;


    File_info new_file;
    new_file.file_name = file_name;
    new_file.file_size = file_size;
    new_file.group_ids = unordered_set<string>{group_id};

    for (int i = 5; i < tokens.size() - 2; i += 3) {
        int chunk_num = stoi(tokens[i]);
        int sz = stoi(tokens[i + 1]);
        string hash = tokens[i + 2];

        Chunk chunk;
        chunk.chunk_num = chunk_num;
        chunk.size = sz;
        chunk.hash = hash;
        chunk.sockets.insert(port);

        new_file.chunks[chunk_num] = chunk;
    }

    lock_guard<mutex> lock(tracker_mutex);
    auto it = groups.find(group_id);

    // HANDLE IF FILE ALREADY EXISTS
    if (files.find(file_name) != files.end()) {
        File_info &existing_file = files[file_name];
        existing_file.group_ids.insert(group_id);
        users[user_id].files.insert(file_name);
        for (auto &chunk : existing_file.chunks) {
            chunk.second.sockets.insert(port);
        }
        send_response(client_socket, "File already exists\n");
        return;
    }

    files[file_name] = new_file;
    users[user_id].files.insert(file_name);
    groups[group_id].files.insert(file_name);
    send_response(client_socket, "File uploaded successfully\n");
    return;
}

void list_files(int client_socket, const string &command)
{
    if (!validate_logged_in(client_socket))
        return;

    vector<string> tokens = parse_command(command);
    if (tokens.size() != 2)
    {
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    string group_id = tokens[1];
    string user_id = session[client_socket];

    lock_guard<mutex> lock(tracker_mutex);
    auto it = groups.find(group_id);
    if (it == groups.end() || it->second.members.find(user_id) == it->second.members.end())
    {
        send_response(client_socket, "You are not a member of this group\n");
        return;
    }
    string response = "Available files:\n";
    for (const auto &file : files)
    {
        if (file.second.group_ids.find(group_id) != file.second.group_ids.end())
        {
            response += file.first + "\n";
        }
    }
    send_response(client_socket, response);
}

string serialize_file_info(File_info &file){
    string serialized = file.file_name + " " + to_string(file.file_size);
    serialized += " " + to_string(file.chunks.size());
    for (const auto &chunk : file.chunks)
    {
        serialized += " " + to_string(chunk.first) + " " + to_string(chunk.second.size) + " " + chunk.second.hash + " " + to_string(chunk.second.sockets.size());
        for(const auto &socket : chunk.second.sockets){
            serialized += " " + to_string(socket);
        }
    }
    return serialized;
}
// Download File: download_file <group_id> <file_name>
void download_file(int client_socket, const string &command){
    vector<string> tokens = parse_command(command);
    if (tokens.size() != 3)
    {
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    if (!validate_logged_in(client_socket)){
        return;
    }
    string group_id = tokens[1];
    if(!validate_group(client_socket,group_id));
    string user_id = session[client_socket];

    lock_guard<mutex> lock(tracker_mutex);
    // send Fileinfo [filename filesize chunks] from files to client
    string file_name = tokens[2];

    auto file_it = files.find(file_name);
    if (file_it == files.end())
    {
        send_response(client_socket, "File not found\n");
        return;
    }
    File_info file = file_it->second;

    string serialized = "success " + serialize_file_info(file);
    send(client_socket, serialized.c_str(), serialized.size(), 0); 
    
}

// Update Chunk: update_chunk <file_name> <chunk_num>
void update_chunk(int client_socket, const string &command){
    vector<string> tokens = parse_command(command);
    if (tokens.size() != 3)
    {
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    if (!validate_logged_in(client_socket)){
        return;
    }
    string user_id = session[client_socket];

    lock_guard<mutex> lock(tracker_mutex);
    // send Fileinfo [filename filesize chunks] from files to client
    string file_name = tokens[1];
    int chunk_num = stoi(tokens[2]);

    auto file_it = files.find(file_name);
    if (file_it == files.end())
    {
        send_response(client_socket, "File not found\n");
        return;
    }
    File_info file = file_it->second;

    auto chunk_it = file.chunks.find(chunk_num);
    if (chunk_it == file.chunks.end())
    {
        send_response(client_socket, "Chunk not found\n");
        return;
    }
    Chunk &chunk = chunk_it->second;
    chunk.sockets.insert(logged_in[user_id].second);
    send_response(client_socket, "Socket updated " + file_name + " " + to_string(chunk_num) + "\n");
}

void handle_client(int client_socket)
{
    char buffer[1024 * 8];
    while (true)
    {
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = read(client_socket, buffer, sizeof(buffer) - 1);
        if (bytes_read <= 0)
        {
            lock_guard<mutex> lock(tracker_mutex);
            if (session.find(client_socket) != session.end())
            {
                string user_id = session[client_socket];
                session.erase(client_socket);
                logged_in.erase(user_id);
            }
            close(client_socket);
            break;
        }
        string command(buffer);
        cout << "Received Command : " << buffer << endl;
        if (command.find("create_user") == 0)
        {
            create_user(client_socket, command);
        }
        else if (command.find("login") == 0)
        {
            login_user(client_socket, command);
        }
        else if (command.find("create_group") == 0)
        {
            create_group(client_socket, command);
        }
        else if (command.find("join_group") == 0)
        {
            join_group(client_socket, command);
        }
        else if (command.find("leave_group") == 0)
        {
            leave_group(client_socket, command);
        }
        else if (command.find("list_groups") == 0)
        {
            list_groups(client_socket,command);
        }
        else if (command.find("list_requests") == 0)
        {
            list_requests(client_socket, command);
        }
        else if (command.find("accept_request") == 0)
        {
            accept_request(client_socket, command);
        }
        else if(command.find("upload_file") == 0)
        {
            upload_file(client_socket, command);
        }
        else if(command.find("list_files") == 0)
        {
            list_files(client_socket, command);
        }
        else if(command.find("download_file") == 0)
        {
            download_file(client_socket, command);
        }
        else if(command.find("update_chunk") == 0)
        {
            update_chunk(client_socket, command);
        }
        else
        {
            send_response(client_socket, "Invalid command\n");
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        cerr << "Usage: " << argv[0] << " <info.txt> <tracker no.>\n";
        return 1;
    }

    vector<pair<string, int>> server_addresses;
    string line;
    int tracker_no = stoi(argv[2]);

    FILE *file = fopen(argv[1], "r");
    if (!file){
        cerr << "Failed to open " << argv[1] << ": " << strerror(errno) << endl;
        return 1;
    }

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), file)){
        line = buffer;
        stringstream ss(line);
        string ip;
        int port;
        ss >> ip >> port;
        server_addresses.emplace_back(ip, port);
    }

    fclose(file);

    if (tracker_no < 0 || tracker_no >= server_addresses.size())
    {
        cerr << "Invalid tracker number\n";
        return 1;
    }

    signal(SIGINT, signalHandler);

    string ip_address = server_addresses[tracker_no].first;
    int port = server_addresses[tracker_no].second;

    struct sockaddr_in server_addr;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        cerr << "Failed to create socket\n";
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip_address.c_str());
    server_addr.sin_port = htons(port);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        cerr << "Bind failed\n";
        close(server_socket);
        return 1;
    }

    if (listen(server_socket, 10) < 0)
    {
        cerr << "Listen failed\n";
        close(server_socket);
        return 1;
    }

    cout << "Server started on " << ip_address << " and port " << port << "\n";

    while (true)
    {
        socklen_t server_addr_len = sizeof(server_addr);
        int client_socket = accept(server_socket, (struct sockaddr *)&server_addr, &server_addr_len);
        if (client_socket < 0)
        {
            cerr << "Failed to accept connection\n";
            continue;
        }
        cout << "Connection opened on socket: " << client_socket << endl;
        thread(handle_client, client_socket).detach();
    }

    close(server_socket);
    return 0;
}
