// Standard Libraries
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <sstream>
#include <cstring>

// Threading and Synchronization
#include <thread>
#include <mutex>

// Networking
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

// File Handling
#include <fcntl.h>
#include <errno.h>

using namespace std;

mutex tracker_mutex;

int server_socket;

struct User;
struct Group;

int track_no = -1;
string log_file;
string other_log_file;
int log_line = 0;


struct address{
    string ip = "127.0.0.1";
    int port;
    bool operator==(const address &a) const {
        return ip == a.ip && port == a.port;
    }
};
namespace std
{
    template <>
    struct hash<address>
    {
        size_t operator()(const address &a) const
        {
            return hash<string>()(a.ip + to_string(a.port));
        }
    };
}
string to_string(const address &a){
    return a.ip + " " + to_string(a.port);
}

address to_address(string &a){
    stringstream ss(a);
    string ip; ss >> ip;
    int port; ss >> port;
    return address{ip,port};
}
struct User
{
    string user_id;
    string hashed_passwd;
    bool isActive;
    unordered_set<string> files;
    unordered_map<string, bool> group_owned;
    unordered_map<string, bool> groups;
    address addr;
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
    unordered_set<address> sockets;
};

struct File_info {
    string file_name;
    int file_size;
    string file_hash;
    // unordered_set<string> group_ids;
    unordered_map<int, Chunk> chunks;
};;

unordered_map <string,File_info> files;
// socket -> user_id
unordered_map <int, string> session;
// user_id -> (socket)
unordered_map <string, int> logged_in;
unordered_map <string, User> users;
unordered_map <string, Group> groups;

void handle_client(int client_socket);
void write_log(string &command, string _user_id, int log_user = -1);

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

vector<string> parse_command(string &command)
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

bool validate_group(int client_socket, string group_id, string user_id = "-"){
    lock_guard<mutex> lock(tracker_mutex);
    auto it = groups.find(group_id);
    ;
    if (it == groups.end() || it->second.members.find(user_id) == it->second.members.end())
    {
        send_response(client_socket,"User not present in group\n");
        return false;
    }
    return true;
}

void create_user(int client_socket, string &command, bool to_send = true, string _user_id = "-")
{
    vector<string> tokens = parse_command(command);
    if (tokens.size() != 3)
    {
        if(to_send)
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    string user_id = tokens[1];
    string hashed_passwd = tokens[2];

    lock_guard<mutex> lock(tracker_mutex);
    if (users.find(user_id) != users.end())
    {
        if(to_send)
        send_response(client_socket, "User already exists\n");
        return;
    }
    users[user_id] = User{user_id, hashed_passwd, false, unordered_set<string>(), unordered_map<string, bool>(), unordered_map<string, bool>()};
    
    if(to_send)
    send_response(client_socket, "User registered successfully\n");
    if(to_send)
    write_log(command, _user_id, track_no);
}

void login_user(int client_socket, string &command, bool to_send = true, string _user_id = "-")
{
    vector<string> tokens = parse_command(command);
    if (tokens.size() != 5)
    {
        if(to_send)
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    string user_id = tokens[1];
    string hashed_passwd = tokens[2];
    string ip = tokens[3];
    int port = stoi(tokens[4]);

    lock_guard<mutex> lock(tracker_mutex);
    if (_user_id != "-")
    {
        if(to_send)
        send_response(client_socket, (_user_id + " is already logged in\n"));
        return;
    }
    if(to_send)
    if (logged_in.find(user_id) != logged_in.end())
    {
        if(to_send)
        send_response(client_socket, (user_id + " is already logged in\n"));
        return;
    }
    auto it = users.find(user_id);
    if (it != users.end() && it->second.hashed_passwd == hashed_passwd)
    {
        if(to_send)
        session[client_socket] = user_id;
        if(to_send)
        logged_in[user_id] = {client_socket};
        users[user_id].isActive = true;
        users[user_id].addr.ip = ip;
        users[user_id].addr.port = port;
        if(to_send)
        send_response(client_socket, "Login success\n");
        if(to_send)
        write_log(command, _user_id, track_no);
    }
    else
    {
        send_response(client_socket, "Login failed\n");
    }
}

void create_group(int client_socket, string &command, bool to_send = true, string _user_id = "-")
{
    if(to_send)
    if (!validate_logged_in(client_socket))
        return;

    vector<string> tokens = parse_command(command);
    if (tokens.size() != 2)
    {
        if(to_send)
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    string group_id = tokens[1];

    lock_guard<mutex> lock(tracker_mutex);
    if (groups.find(group_id) != groups.end())
    {
        if(to_send)
        send_response(client_socket, "Group already exists\n");
        return;
    }

    string user_id = _user_id;
    Group new_group = {group_id, user_id};
    groups[group_id] = new_group;
    users[user_id].group_owned[group_id] = true;
    groups[group_id].members[user_id] = true;
    if(to_send)
    send_response(client_socket, "Group created\n");
    if(to_send)
    write_log(command, _user_id, track_no);
}
void join_group(int client_socket, string &command, bool to_send = true, string _user_id = "-")
{
    if (to_send && !validate_logged_in(client_socket))
        return;

    vector<string> tokens = parse_command(command);
    if (tokens.size() != 2)
    {
        if (to_send) send_response(client_socket, "Invalid command format\n");
        return;
    }

    string group_id = tokens[1];
    string user_id = _user_id;

    lock_guard<mutex> lock(tracker_mutex);
    auto it = groups.find(group_id);
    if (it == groups.end())
    {
        if (to_send) send_response(client_socket, "Group does not exist\n");
        return;
    }

    Group &group = it->second;
    if (group.members.find(user_id) != group.members.end())
    {
        if (to_send) send_response(client_socket, "You are already a member of this group\n");
        return;
    }

    if (group.requests.find(user_id) != group.requests.end())
    {
        if (to_send) send_response(client_socket, "Join request already sent\n");
        return;
    }

    group.requests[user_id] = true;
    if (to_send) send_response(client_socket, "Join request sent successfully\n");
    if (to_send) write_log(command, _user_id, track_no);
}

void list_groups(int client_socket, string &command, bool to_send = true, string _user_id = "-"){
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

void list_requests(int client_socket, string &command, bool to_send = true, string _user_id = "-") {
    if (!validate_logged_in(client_socket))
        return;

    vector<string> tokens = parse_command(command);
    if (tokens.size() != 2)
    {
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    string group_id = tokens[1];
    string user_id = _user_id;

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

void accept_request(int client_socket, string &command, bool to_send = true, string _user_id = "-")
{
    if(to_send)
    if (!validate_logged_in(client_socket))
        return;

    vector<string> tokens = parse_command(command);
    if (tokens.size() != 3)
    {
        if(to_send)
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    string group_id = tokens[1];
    string user_id = tokens[2];

    string owner_id = _user_id;

    lock_guard<mutex> lock(tracker_mutex);
    auto it = groups.find(group_id);
    if (it == groups.end() || it->second.owner_id != owner_id)
    {
        if(to_send)
        send_response(client_socket, "You are not the owner of this group or the group does not exist\n");
        return;
    }

    Group &group = it->second;
    if (users.find(user_id) != users.end() && group.requests.find(user_id) != group.requests.end())
    {
        group.members[user_id] = true;
        group.requests.erase(user_id); // Remove from requests
        users[user_id].groups[group_id] = true;
        if(to_send)
        send_response(client_socket, "Request accepted\n");
        if(to_send)
        write_log(command, _user_id, track_no);
    }
    else
    {
        if(to_send)
        send_response(client_socket, "Request does not exist or user not found\n");
    }
}
string serialize_file_info(File_info &file);
void upload_file(int client_socket, string &command, bool to_send = true, string _user_id = "-")
{
    if(to_send)
    if (!validate_logged_in(client_socket))
        return;

    vector<string> tokens = parse_command(command);
    if (tokens.size() < 6)
    {
        if(to_send)
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    string file_name = tokens[1];
    int file_size = stoi(tokens[2]);
    string group_id = tokens[3];
    int chunk_number = stoi(tokens[4]);

    if(tokens.size() != 5 + 3*chunk_number + 1){
        if(to_send)
        send_response(client_socket, "Invalid Information\n");
        return;
    }
    if(to_send)
    if(!validate_group(client_socket,group_id,_user_id)){
        return;
    }

    string user_id = _user_id;
    address addr = users[user_id].addr;

    File_info new_file;
    new_file.file_name = file_name;
    new_file.file_size = file_size;
    new_file.file_hash = tokens[tokens.size() - 1];

    for (int i = 5; i < tokens.size() - 3; i += 3) {
        int chunk_num = stoi(tokens[i]);
        int sz = stoi(tokens[i + 1]);
        string hash = tokens[i + 2];

        Chunk chunk;
        chunk.chunk_num = chunk_num;
        chunk.size = sz;
        chunk.hash = hash;
        chunk.sockets.insert(addr);

        new_file.chunks[chunk_num] = chunk;
    }

    cout << "Serializing file info\n" << serialize_file_info(new_file) << endl;


    lock_guard<mutex> lock(tracker_mutex);
    auto it = groups.find(group_id);

    // HANDLE IF FILE ALREADY EXISTS
    if(to_send) write_log(command, _user_id, track_no);

    if (files.find(file_name) != files.end()) {
        if(groups[group_id].files.find(file_name) == groups[group_id].files.end()){
            send_response(client_socket, "File exists in different group\n");
            return;
        }
        File_info &existing_file = files[file_name];
        if (existing_file.file_hash == new_file.file_hash) {
            users[user_id].files.insert(file_name);
            for (auto &chunk : existing_file.chunks) {
                chunk.second.sockets.insert(addr);
            }
            if(to_send)
            send_response(client_socket, "File already exists\n");
            return;
        } else {
            if(to_send)
            send_response(client_socket, "File with the same name but different hash already exists\n");
            return;
        }
    }

    files[file_name] = new_file;
    users[user_id].files.insert(file_name);
    groups[group_id].files.insert(file_name);
    if(to_send)
    send_response(client_socket, "File uploaded successfully\n");
    return;
}

void list_files(int client_socket, string &command, bool to_send = true, string _user_id = "-")
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
    string user_id = _user_id;

    lock_guard<mutex> lock(tracker_mutex);
    auto it = groups.find(group_id);
    if (it == groups.end() || it->second.members.find(user_id) == it->second.members.end())
    {
        send_response(client_socket, "You are not a member of this group\n");
        return;
    }
    string response = "Available files:\n";
    for (const auto &file : it->second.files)
    {
        response += file + "\n";
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
void download_file(int client_socket, string &command, bool to_send = true, string _user_id = "-"){
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
    if(!validate_group(client_socket,group_id,_user_id)){
        return;
    }
    string user_id = _user_id;

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
    cerr << "Serialized :: " << serialized << endl ;
    send(client_socket, serialized.c_str(), serialized.size(), 0); 
    
}

// Update Chunk: update_chunk <file_name> <chunk_num>
void update_chunk(int client_socket, string &command, bool to_send = true, string _user_id = "-"){
    vector<string> tokens = parse_command(command);
    if (tokens.size() != 3)
    {
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    if (!validate_logged_in(client_socket)){
        return;
    }
    string user_id = _user_id;

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
    chunk.sockets.insert(users[user_id].addr);
    send_response(client_socket, "Socket updated " + file_name + " " + to_string(chunk_num) + "\n");
}

// filename chunk_no.
void add_chunk(int client_socket, string &command, bool to_send = true, string _user_id = "-") {
    vector<string> token = parse_command(command);
    string file_name = token[1];
    int chunk_no = stoi(token[2]);
    lock_guard<mutex> lock(tracker_mutex);
    string user_id = _user_id;
    auto file_it = files.find(file_name);
    if (file_it == files.end()) {
        return;
    }
    File_info &file = file_it->second;
    file.chunks[chunk_no].sockets.insert(users[user_id].addr);
    if(to_send)
    send_response(client_socket, "Chunk added\n");
    if(to_send)
    write_log(command, _user_id, track_no);
}

// Stop Share: stop_share <file_name> <group_id>
void stop_share(int client_socket, string command, bool to_send = true, string _user_id = "-"){
    if(to_send){
        if (!validate_logged_in(client_socket))
        return;
    }
    vector<string> tokens = parse_command(command);
    if (tokens.size() != 3)
    {
        if (to_send) send_response(client_socket, "Invalid command format\n");
        return;
    }

    string file_name = tokens[1];
    string group_id = tokens[2];
    string user_id = _user_id;

    lock_guard<mutex> lock(tracker_mutex);
    auto file_it = files.find(file_name);
    if (file_it == files.end())
    {
        if (to_send) send_response(client_socket, "File not found\n");
        return;
    }
    File_info &file = file_it->second;
    groups[group_id].files.erase(file_name);
    users[user_id].files.erase(file_name);
    bool to_remove = true;
    for(auto &chunk : file.chunks){
        chunk.second.sockets.erase(users[user_id].addr);
        if(chunk.second.sockets.size() > 0){
            to_remove = false;
        }
    }
    if(to_remove){
        files.erase(file_name);
        groups[group_id].files.erase(file_name);
    }

    if (to_send) send_response(client_socket, "File unshared successfully\n");
    if(to_send) write_log(command, _user_id, track_no);
}

// Leave Group: leave_group <group_id>
void leave_group(int client_socket, string command, bool to_send = true, string _user_id = "-")
{
    if(to_send){
        if (!validate_logged_in(client_socket))
            return;
    }

    vector<string> tokens = parse_command(command);
    if (tokens.size() != 2)
    {
        if(to_send)
        send_response(client_socket, "Invalid command format\n");
        return;
    }

    string group_id = tokens[1];
    string user_id = _user_id;

    lock_guard<mutex> lock(tracker_mutex);
    auto it = groups.find(group_id);
    string response;
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
                        response = "New owner: " + member.first + "\n";
                        break;
                    }
                }
            }
            else
            {
                groups.erase(group_id);
                response = "Group deleted\n";
                return;
            }
        }
        group.members.erase(user_id);   // Remove user from members
        users[user_id].groups.erase(group_id); // Remove from user's groups

        // Stop sharing files when leaving group
        for (const auto &file_name : group.files)
        {
            stop_share(client_socket, "stop_share " + file_name + " " + group_id,false,_user_id);
        }
        if(to_send) write_log(command, _user_id, track_no);
        if(to_send) send_response(client_socket, response + "Left group successfully\n");
    }
    else
    {
        if(to_send) send_response(client_socket, "You are not a member of this group\n");
    }
}

void logout(int client_socket, string &command, bool to_send = true, string _user_id = "-"){
    if (!validate_logged_in(client_socket))
        return;

    string user_id = _user_id;
    lock_guard<mutex> lock(tracker_mutex);
    if(to_send){
    session.erase(client_socket);
    logged_in.erase(user_id);
    }
    users[user_id].isActive = false;
    auto groups = users[user_id].groups;
    for(auto i : groups){
        leave_group(client_socket,"leave_group " + i.first,false, _user_id);
        cerr << "Leaving group " << i.first << endl;
    }
    if(to_send)
    send_response(client_socket, "Logout success\n");
    if(to_send) write_log(command, _user_id, track_no);
}

// write log to log file
void write_log(string &command, string _user_id, int log_user){
    // lock_guard<mutex> lock(tracker_mutex);
    int log_fd = open(log_file.c_str(), O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (log_fd == -1) {
        cerr << "Failed to open log file\n";
        return;
    }
    string log_entry = to_string(log_user) + " " + _user_id + " " + command + "\n";
    write(log_fd, log_entry.c_str(), log_entry.size());
    close(log_fd);
    log_line++;
}

void execute_log(string &command , string _user_id){
    cerr << "Executing log: " << command << endl;
    if (command.find("create_user") == 0)
    {
        create_user(-1, command, false, _user_id);
    }
    else if (command.find("login") == 0)
    {
        login_user(-1, command, false, _user_id);
    }
    else if (command.find("create_group") == 0)
    {
        create_group(-1, command, false, _user_id);
    }
    else if (command.find("join_group") == 0)
    {
        join_group(-1, command, false, _user_id);
    }
    else if (command.find("leave_group") == 0)
    {
        leave_group(-1, command, false, _user_id);
    }
    else if (command.find("list_groups") == 0)
    {
        list_groups(-1, command, false, _user_id);
    }
    else if (command.find("list_requests") == 0)
    {
        list_requests(-1, command, false, _user_id);
    }
    else if (command.find("accept_request") == 0)
    {
        accept_request(-1, command, false, _user_id);
    }
    else if(command.find("upload_file") == 0)
    {
        upload_file(-1, command, false, _user_id);
    }
    else if(command.find("list_files") == 0)
    {
        list_files(-1, command, false, _user_id);
    }
    else if(command.find("download_file") == 0)
    {
        download_file(-1, command, false, _user_id);
    }
    else if(command.find("update_chunk") == 0)
    {
        update_chunk(-1, command, false, _user_id);
    }
    else if (command.find("add_chunk") == 0){
        add_chunk(-1, command, false, _user_id);
    }
    else if(command.find("stop_share") == 0)
    {
        stop_share(-1, command, false, _user_id);
    }
    else if(command.find("logout") == 0)
    {
        logout(-1, command, false, _user_id);
    }
    else
    {
        cerr << "Invalid command\n";
    }
    write_log(command,_user_id);

}

void execute_log_line(string &command){
    vector<string> tokens = split(command);
    int log_user = stoi(tokens[0]);
    string _user_id = tokens[1];
    string _command = tokens[2];
    for(int i = 3; i < tokens.size(); i++){
        _command = _command + " " + tokens[i];
    }
    execute_log(_command,_user_id);
}

string read_line(int &fd){
    string line;
    char c;
    while(read(fd, &c, 1) > 0){
        if(c == '\n'){
            break;
        }
        line += c;
    }
    return line;
}

void sync(){
    int log_fd = open(other_log_file.c_str(), O_RDONLY);
    if (log_fd == -1) {
        // cerr << "Failed to open log file\n";
        return;
    }
    lseek(log_fd, 0, SEEK_SET);
    for(int i = 0; i < log_line; i++){
        string log_entry = read_line(log_fd);
    }
    vector<string> logs;
    while(true){
        string log_entry = read_line(log_fd);
        if(log_entry.empty()){
            break;
        }
        logs.push_back(log_entry);
    }
    close(log_fd);
    if(log_line == 0){
        for(auto i : logs){
            execute_log_line(i);
        }
    } else {
        for(auto i : logs){
            if(track_no == 0){
                if(i[0] == '1'){
                    execute_log_line(i);
                }
            } else {
                if(i[0] == '0'){
                    execute_log_line(i);
                }
            }
        }
    }
}

void handle_client(int client_socket)
{
    char buffer[1024 * 16];
    while (true)
    {
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = read(client_socket, buffer, sizeof(buffer) - 1);
        if (bytes_read <= 0)
        {
            lock_guard<mutex> lock(tracker_mutex);
            if (session.find(client_socket) != session.end())
            {
                cerr << "User " << session[client_socket] << " disconnected\n";
                string user_id = session[client_socket];
                session.erase(client_socket);
                logged_in.erase(user_id);
            }
            close(client_socket);
            break;
        }
        string command(buffer);
        cout << "Received Command : " << buffer << endl;
        string _user_id = "-";
        if(session.find(client_socket) != session.end()){
            _user_id = session[client_socket];
        }            
        sync();
        if (command.find("create_user") == 0)
        {
            create_user(client_socket, command, true, _user_id);
        }
        else if (command.find("login") == 0)
        {
            login_user(client_socket, command, true, _user_id);
        }
        else if (command.find("create_group") == 0)
        {
            create_group(client_socket, command, true, _user_id);
        }
        else if (command.find("join_group") == 0)
        {
            join_group(client_socket, command, true, _user_id);
        }
        else if (command.find("leave_group") == 0)
        {
            leave_group(client_socket, command, true, _user_id);
        }
        else if (command.find("list_groups") == 0)
        {
            list_groups(client_socket, command, true, _user_id);
        }
        else if (command.find("list_requests") == 0)
        {
            list_requests(client_socket, command, true, _user_id);
        }
        else if (command.find("accept_request") == 0)
        {
            accept_request(client_socket, command, true, _user_id);
        }
        else if(command.find("upload_file") == 0)
        {
            upload_file(client_socket, command, true, _user_id);
        }
        else if(command.find("list_files") == 0)
        {
            list_files(client_socket, command, true, _user_id);
        }
        else if(command.find("download_file") == 0)
        {
            download_file(client_socket, command, true, _user_id);
        }
        else if(command.find("update_chunk") == 0)
        {
            update_chunk(client_socket, command, true, _user_id);
        }
        else if (command.find("add_chunk") == 0){
            add_chunk(client_socket, command, true, _user_id);
        }
        else if(command.find("stop_share") == 0)
        {
            stop_share(client_socket, command, true, _user_id);
        }
        else if(command.find("logout") == 0)
        {
            logout(client_socket, command, true, _user_id);
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
    if(tracker_no == 0){
        log_file = "log0.txt";
        other_log_file = "log1.txt";
    } else if(tracker_no == 1){
        log_file = "log1.txt";
        other_log_file = "log0.txt";
    } else {
        cerr << "Invalid tracker number\n";
        return 1;
    }
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
    cout << "Tracker " << tracker_no << " is Syncing" << endl; 
    sync();
    cout << "Syncing Done" << endl;
    track_no = tracker_no;
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
