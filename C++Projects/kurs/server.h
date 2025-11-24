#ifndef SERVER_H
#define SERVER_H

#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>

struct ServerParams {
    std::string authFile = "./vcalc.conf";
    std::string logFile = "./log/vcalc.log";
    uint16_t port = 33333;
};

class AuthDatabase {
private:
    std::unordered_map<std::string, std::string> users;
    
public:
    bool loadFromFile(const std::string& filename);
    bool authenticate(const std::string& login, const std::string& password, 
                     const std::string& salt, const std::string& hash);
};

class Logger {
private:
    std::string logFile;
    bool createLogDirectory(const std::string& filepath);
    
public:
    Logger(const std::string& filename);
    bool initialize();
    void logError(const std::string& message, bool critical = false);
    void logInfo(const std::string& message);
};

class Calculator {
public:
    uint16_t calculateVectorSum(const std::vector<uint16_t>& vector);
};

class Server {
private:
    ServerParams params;
    AuthDatabase authDB;
    Logger logger;
    Calculator calculator;
    int serverSocket;
    
    bool parseCommandLine(int argc, char** argv);
    bool initializeSocket();
    void handleClient(int clientSocket);
    bool authenticateClient(int clientSocket, std::string& clientLogin);
    std::vector<uint16_t> processVectors(int clientSocket);
    
public:
    Server();
    int run(int argc, char** argv);
};

#endif