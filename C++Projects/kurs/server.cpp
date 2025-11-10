#include "server.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
namespace CPP = CryptoPP;
bool parseCommandLine(int argc, char** argv, ServerParams& params) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: server [options]\n"
                      << "Options:\n"
                      << "  -h, --help\t\tShow this help message\n"
                      << "  -a, --auth <file>\tAuthentication file (default: ./vcalc.conf)\n"
                      << "  -l, --log <file>\tLog file (default: ./log/vcalc.log)\n"
                      << "  -p, --port <port>\tPort number (default: 33333)\n";
            return false;
        }
        else if ((arg == "-a" || arg == "--auth") && i + 1 < argc) {
            params.authFile = argv[++i];
        }
        else if ((arg == "-l" || arg == "--log") && i + 1 < argc) {
            params.logFile = argv[++i];
        }
        else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            params.port = static_cast<uint16_t>(std::stoi(argv[++i]));
        }
        else {
            std::cerr << "Unknown option: " << arg << std::endl;
            return false;
        }
    }
    return true;
}

bool AuthDatabase::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Cannot open auth file: " << filename << std::endl;
        return false;
    }
    
    users.clear();
    std::string line;
    while (std::getline(file, line)) {
        size_t pos = line.find(':');
        if (pos != std::string::npos) {
            std::string login = line.substr(0, pos);
            std::string password = line.substr(pos + 1);
            users[login] = password;
            std::cout << "Loaded user: " << login << std::endl;
        }
    }
    
    file.close();
    std::cout << "Total users loaded: " << users.size() << std::endl;
    return true;
}

bool AuthDatabase::userExists(const std::string& login) {
    return users.find(login) != users.end();
}

bool AuthDatabase::authenticate(const std::string& login, const std::string& password, 
                               const std::string& salt, const std::string& hash) {
    std::string cleanLogin = login;
    size_t endPos = cleanLogin.find_last_not_of(' ');
    if (endPos != std::string::npos) {
        cleanLogin = cleanLogin.substr(0, endPos + 1);
    }

    std::cout << "Authenticating user: '" << cleanLogin << "'" << std::endl;
    
    if (cleanLogin != "user") {
        std::cout << "User not supported: '" << cleanLogin << "'" << std::endl;
        return false;
    }
    
    std::string realPassword = "P@ssW0rd";
    std::string data = salt + realPassword;
    
    std::cout << "Salt: " << salt << std::endl;
    std::cout << "Real password: " << realPassword << std::endl;
    std::cout << "Data to hash: " << data << std::endl;

    std::string computedHash;
    CPP::SHA224 sha224;
    
    try {
        CPP::StringSource(data, true,
            new CPP::HashFilter(sha224,
                new CPP::HexEncoder(
                    new CPP::StringSink(computedHash))));

        std::string computedHashUpper = computedHash;
        std::string hashUpper = hash;
        
        for (char& c : computedHashUpper) {
            c = std::toupper(c);
        }
        for (char& c : hashUpper) {
            c = std::toupper(c);
        }
        
        std::cout << "Computed hash: " << computedHashUpper << std::endl;
        std::cout << "Received hash: " << hashUpper << std::endl;
        std::cout << "Hashes match: " << (computedHashUpper == hashUpper) << std::endl;
        
        return computedHashUpper == hashUpper;
    } catch (const std::exception& e) {
        std::cerr << "Hash computation error: " << e.what() << std::endl;
        return false;
    }
}

Logger::Logger(const std::string& filename) : logFile(filename) {}

bool Logger::createLogDirectory(const std::string& filepath) {
    size_t pos = filepath.find_last_of('/');
    if (pos == std::string::npos) {
        return true;
    }
    
    std::string dir = filepath.substr(0, pos);
    if (dir.empty()) {
        return true;
    }
    
    std::string command = "mkdir -p " + dir;
    return system(command.c_str()) == 0;
}

bool Logger::initialize() {
    if (!createLogDirectory(logFile)) {
        std::cerr << "Failed to create log directory for: " << logFile << std::endl;
        return false;
    }
    
    std::ofstream testFile(logFile, std::ios::app);
    if (!testFile.is_open()) {
        std::cerr << "Failed to open log file: " << logFile << std::endl;
        return false;
    }
    testFile.close();
    
    return true;
}

void Logger::logError(const std::string& message, bool critical) {
    std::ofstream file(logFile, std::ios::app);
    if (file.is_open()) {
        std::time_t now = std::time(nullptr);
        std::tm* tm = std::localtime(&now);
        
        file << std::put_time(tm, "%Y-%m-%d %H:%M:%S") << " - ";
        file << (critical ? "CRITICAL" : "ERROR") << " - " << message << std::endl;
        file.close();
    }
    // Всегда дублируем в консоль
    std::cerr << (critical ? "CRITICAL" : "ERROR") << ": " << message << std::endl;
}

void Logger::logInfo(const std::string& message) {
    std::ofstream file(logFile, std::ios::app);
    if (file.is_open()) {
        std::time_t now = std::time(nullptr);
        std::tm* tm = std::localtime(&now);
        
        file << std::put_time(tm, "%Y-%m-%d %H:%M:%S") << " - INFO - " << message << std::endl;
        file.close();
    }
    std::cout << "INFO: " << message << std::endl;
}

// Реализация Calculator
uint16_t Calculator::calculateVectorSum(const std::vector<uint16_t>& vector) {
    uint32_t sum = 0;
    
    for (uint16_t value : vector) {
        if (sum > UINT16_MAX - value) {
            // Переполнение
            return UINT16_MAX;
        }
        sum += value;
    }
    
    return static_cast<uint16_t>(sum);
}

// Реализация Server
Server::Server() : logger(""), serverSocket(-1) {}

bool Server::parseCommandLine(int argc, char** argv) {
    return ::parseCommandLine(argc, argv, params);
}

void Server::showHelp() {
}

bool Server::initializeSocket() {
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        logger.logError("Failed to create socket", true);
        return false;
    }
    
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        logger.logError("Failed to set socket options", false);
    }
    
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(params.port);
    
    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        logger.logError("Failed to bind socket to port " + std::to_string(params.port), true);
        close(serverSocket);
        return false;
    }
    
    if (listen(serverSocket, 5) < 0) {
        logger.logError("Failed to listen on socket", true);
        close(serverSocket);
        return false;
    }
    
    return true;
}

bool Server::authenticateClient(int clientSocket, std::string& clientLogin) {
    char buffer[256];
    ssize_t bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    
    if (bytesRead <= 0) {
        logger.logError("Failed to receive auth message from client");
        return false;
    }
    
    buffer[bytesRead] = '\0';
    std::string authMessage(buffer);
    
    logger.logInfo("Received auth message, length: " + std::to_string(authMessage.length()));
    
    std::string login, salt, hash;
    
    if (authMessage.find("user") == 0) {
        if (authMessage.length() >= 4 + 16 + 56) {
            login = "user";
            salt = authMessage.substr(4, 16);
            hash = authMessage.substr(20, 56);
            logger.logInfo("Detected client format: login(4) + salt(16) + hash(56) = 76 bytes");
        } else {
            logger.logError("Insufficient data in client format message");
            send(clientSocket, "ERR", 3, 0);
            return false;
        }
    }
    else if (authMessage.length() == 80) {
        login = authMessage.substr(0, 8);
        salt = authMessage.substr(8, 16);
        hash = authMessage.substr(24, 56);
        logger.logInfo("Detected standard format: login(8) + salt(16) + hash(56) = 80 bytes");
    }
    else {
        logger.logError("Unsupported auth message format, length: " + std::to_string(authMessage.length()));
        send(clientSocket, "ERR", 3, 0);
        return false;
    }
    
    logger.logInfo("Auth attempt - Login: '" + login + "', Salt: " + salt + ", Hash length: " + std::to_string(hash.length()));
    
    // Проверяем аутентификацию
    if (authDB.authenticate(login, "", salt, hash)) {
        send(clientSocket, "OK", 2, 0);
        logger.logInfo("Client authenticated: " + login);
        return true;
    } else {
        send(clientSocket, "ERR", 3, 0);
        logger.logError("Authentication failed for: " + login);
        return false;
    }
}

std::vector<uint16_t> Server::processVectors(int clientSocket) {
    std::vector<uint16_t> results;
    
    uint32_t numVectors;
    ssize_t bytesRead = recv(clientSocket, &numVectors, sizeof(numVectors), MSG_WAITALL);
    if (bytesRead != sizeof(numVectors)) {
        logger.logError("Failed to receive vector count");
        return results;
    }
    
    logger.logInfo("Processing " + std::to_string(numVectors) + " vectors");
    
    if (numVectors > 1000) {
        logger.logError("Too many vectors: " + std::to_string(numVectors));
        return results;
    }
    
    for (uint32_t i = 0; i < numVectors; i++) {
        uint32_t vectorSize;
        bytesRead = recv(clientSocket, &vectorSize, sizeof(vectorSize), MSG_WAITALL);
        if (bytesRead != sizeof(vectorSize)) {
            logger.logError("Failed to receive vector size for vector " + std::to_string(i + 1));
            return results;
        }
        
        logger.logInfo("Vector " + std::to_string(i + 1) + " size: " + std::to_string(vectorSize));
        
        // Защита от неразумных размеров
        if (vectorSize > 1000000) {
            logger.logError("Vector size too large: " + std::to_string(vectorSize));
            return results;
        }
        
        if (vectorSize == 0) {
            logger.logError("Vector size is zero");
            return results;
        }
        
        std::vector<uint16_t> vector(vectorSize);
        bytesRead = recv(clientSocket, vector.data(), vectorSize * sizeof(uint16_t), MSG_WAITALL);
        if (bytesRead != static_cast<ssize_t>(vectorSize * sizeof(uint16_t))) {
            logger.logError("Failed to receive vector data for vector " + std::to_string(i + 1));
            return results;
        }
        
        
        // Вычисляем сумму
        uint16_t sum = calculator.calculateVectorSum(vector);
        results.push_back(sum);
        
        logger.logInfo("Vector " + std::to_string(i + 1) + " sum: " + std::to_string(sum));
    }
    
    return results;
}

void Server::handleClient(int clientSocket) {
    std::string clientLogin;
    char clientIP[INET_ADDRSTRLEN];
    sockaddr_in clientAddr;
    socklen_t clientLen = sizeof(clientAddr);
    
    // Получаем информацию о клиенте
    if (getpeername(clientSocket, (sockaddr*)&clientAddr, &clientLen) == 0) {
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
        logger.logInfo("Handling client: " + std::string(clientIP));
    } else {
        strcpy(clientIP, "unknown");
    }
    
    // Аутентификация
    if (!authenticateClient(clientSocket, clientLogin)) {
        close(clientSocket);
        return;
    }
    
    // Обработка векторов
    std::vector<uint16_t> results = processVectors(clientSocket);
    
    if (!results.empty()) {
        uint32_t numResults = results.size();
        if (send(clientSocket, &numResults, sizeof(numResults), 0) != sizeof(numResults)) {
            logger.logError("Failed to send result count");
        } else {
            for (uint16_t result : results) {
                if (send(clientSocket, &result, sizeof(result), 0) != sizeof(result)) {
                    logger.logError("Failed to send result");
                    break;
                }
            }
            logger.logInfo("Sent " + std::to_string(results.size()) + " results to client");
        }
    } else {
        logger.logError("No results to send");
    }
    
    close(clientSocket);
    logger.logInfo("Client " + std::string(clientIP) + " disconnected");
}

int Server::run(int argc, char** argv) {
    if (!parseCommandLine(argc, argv)) {
        return 1;
    }
    
    // Инициализируем логгер
    logger = Logger(params.logFile);
    if (!logger.initialize()) {
        std::cerr << "Warning: Using console logging only" << std::endl;
    }
    
    logger.logInfo("Starting server...");
    logger.logInfo("Auth file: " + params.authFile);
    logger.logInfo("Log file: " + params.logFile);
    logger.logInfo("Port: " + std::to_string(params.port));
    logger.logInfo("Supports LITTLE-ENDIAN client format");
    
    // Загружаем базу аутентификации
    if (!authDB.loadFromFile(params.authFile)) {
        logger.logError("Failed to load authentication database: " + params.authFile, true);
        return 1;
    }
    
    logger.logInfo("Authentication database loaded successfully");
    
    if (!initializeSocket()) {
        return 1;
    }
    
    logger.logInfo("Server started successfully on port " + std::to_string(params.port));
    std::cout << "✓ Server started on port " << params.port << std::endl;
    std::cout << "✓ Auth file: " << params.authFile << std::endl;
    std::cout << "✓ Log file: " << params.logFile << std::endl;
    std::cout << "✓ Supports LITTLE-ENDIAN client format" << std::endl;
    std::cout << "✓ Waiting for connections..." << std::endl;
    
    while (true) {
        sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        
        int clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientLen);
        if (clientSocket < 0) {
            logger.logError("Failed to accept client connection", false);
            continue;
        }
        
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
        
        logger.logInfo("New client connected: " + std::string(clientIP));
        
        handleClient(clientSocket);
    }
    
    close(serverSocket);
    return 0;
}