/**
 * @file server.h
 * @brief Заголовочный файл сервера для вычисления суммы векторов
 * 
 * Определяет классы и структуры для работы сервера:
 * - ServerParams: параметры конфигурации
 * - AuthDatabase: управление аутентификацией
 * - Logger: система логирования
 * - Calculator: вычисление сумм векторов
 * - Server: основной класс сервера
 * @author Ruslan Barabanov
 * @date 16.12.2025
 * @version 1.0
 */

#ifndef SERVER_H
#define SERVER_H

#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>

/**
 * @struct ServerParams
 * @brief Параметры конфигурации сервера
 * 
 * Хранит настройки сервера, загружаемые из командной строки.
 */
struct ServerParams {
    std::string authFile = "./vcalc.conf";  ///< Файл аутентификации
    std::string logFile = "./log/vcalc.log"; ///< Файл логов
    uint16_t port = 33333;                   ///< Порт сервера
};

/**
 * @class AuthDatabase
 * @brief База данных аутентификации пользователей
 * 
 * Загружает и проверяет учетные данные пользователей из файла.
 */
class AuthDatabase {
private:
    std::unordered_map<std::string, std::string> users; ///< Хранилище пользователей
    
public:
    bool loadFromFile(const std::string& filename);
    bool authenticate(const std::string& login, const std::string& password, 
                     const std::string& salt, const std::string& hash);
};

/**
 * @class Logger
 * @brief Система логирования сервера
 * 
 * Обеспечивает запись логов в файл с временными метками.
 */
class Logger {
private:
    std::string logFile; ///< Имя файла логов
    bool createLogDirectory(const std::string& filepath);
    
public:
    Logger(const std::string& filename);
    bool initialize();
    void logError(const std::string& message, bool critical = false);
    void logInfo(const std::string& message);
};

/**
 * @class Calculator
 * @brief Калькулятор для вычисления сумм векторов
 * 
 * Вычисляет сумму элементов вектора с обработкой переполнения.
 */
class Calculator {
public:
    uint16_t calculateVectorSum(const std::vector<uint16_t>& vector);
};

/**
 * @class Server
 * @brief Основной класс сервера
 * 
 * Управляет сетевыми подключениями, аутентификацией клиентов
 * и обработкой запросов на вычисление сумм векторов.
 */
class Server {
private:
    ServerParams params;      ///< Параметры сервера
    AuthDatabase authDB;      ///< База данных аутентификации
    Logger logger;            ///< Логгер
    Calculator calculator;    ///< Калькулятор
    int serverSocket;         ///< Сокет сервера
    
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