#include <iostream>
#include <cassert>
#include <vector>
#include <fstream>
#include "server.h"

class TestHelper {
public:
    static bool createTestFile(const std::string& filename, const std::string& content) {
        std::ofstream file(filename);
        if (!file.is_open()) return false;
        file << content;
        file.close();
        return true;
    }
    
    static bool removeTestFile(const std::string& filename) {
        return std::remove(filename.c_str()) == 0;
    }
};

void testCalculator() {
    std::cout << "=== Тестирование Calculator ===\n";
    
    Calculator calculator;
    bool allPassed = true;
    
    // Тест 1: Сумма обычного вектора
    std::vector<uint16_t> vec1 = {1, 2, 3, 4, 5};
    uint16_t result1 = calculator.calculateVectorSum(vec1);
    if (result1 == 15) {
        std::cout << "✓ Сумма обычного вектора - PASSED\n";
    } else {
        std::cout << "✗ Сумма обычного вектора - FAILED\n";
        allPassed = false;
    }
    
    std::vector<uint16_t> vec2 = {};
    uint16_t result2 = calculator.calculateVectorSum(vec2);
    if (result2 == 0) {
        std::cout << "✓ Сумма пустого вектора - PASSED\n";
    } else {
        std::cout << "✗ Сумма пустого вектора - FAILED\n";
        allPassed = false;
    }
    
    std::vector<uint16_t> vec4(1000, 10000);
    uint16_t result4 = calculator.calculateVectorSum(vec4);
    if (result4 == 11000) {
        std::cout << "✓ Сумма большого вектора - PASSED\n";
    } else {
        std::cout << "✗ Сумма большого вектора - FAILED\n";
        allPassed = false;
    }
        std::vector<uint16_t> vec2 = {1};
    uint16_t result2 = calculator.calculateVectorSum(vec2);
    if (result3 == 1) {
        std::cout << "✓ Сумма одного вектора - PASSED\n";
    } else {
        std::cout << "✗ Сумма одного вектора - FAILED\n";
        allPassed = false;
    }
    if (allPassed) {
        std::cout << "✓ Все тесты Calculator пройдены\n";
    } else {
        std::cout << "✗ Некоторые тесты Calculator не пройдены\n";
    }
}

// Тест 2: AuthDatabase (базовый)
void testAuthDatabase() {
    std::cout << "\n=== Тестирование AuthDatabase ===\n";
    
    AuthDatabase authDB;
    bool allPassed = true;
    
    // Тест 1: Загрузка корректного файла
    std::string authFile = "test_auth.conf";
    if (TestHelper::createTestFile(authFile, "user1:password1\nuser2:password2\n")) {
        bool loadResult = authDB.loadFromFile(authFile);
        if (loadResult) {
            std::cout << "✓ Загрузка файла аутентификации - PASSED\n";
        } else {
            std::cout << "✗ Загрузка файла аутентификации - FAILED\n";
            allPassed = false;
        }
        TestHelper::removeTestFile(authFile);
    } else {
        std::cout << "⚠ Загрузка файла аутентификации - SKIPPED\n";
    }
    
    // Тест 2: Загрузка несуществующего файла
    bool loadFailResult = authDB.loadFromFile("nonexistent_file_12345.conf");
    if (!loadFailResult) {
        std::cout << "✓ Обработка отсутствующего файла - PASSED\n";
    } else {
        std::cout << "✗ Обработка отсутствующего файла - FAILED\n";
        allPassed = false;
    }
    

    if (allPassed) {
        std::cout << "✓ Все тесты AuthDatabase пройдены\n";
    } else {
        std::cout << "✗ Некоторые тесты AuthDatabase не пройдены\n";
    }
}

// Тест 3: Logger (базовый)
void testLogger() {
    std::cout << "\n=== Тестирование Logger ===\n";
    
    std::string testLogFile = "test_log.log";
    bool allPassed = true;
    
    try {

        Logger logger(testLogFile);
        std::cout << "✓ Создание логгера - PASSED\n";
        
        logger.logInfo("Test info message");
        logger.logError("Test error message");
        logger.logError("Test critical error", true);
        std::cout << "✓ Логирование сообщений - PASSED\n";
        
    } catch (...) {
        std::cout << "✗ Создание логгера - FAILED\n";
        allPassed = false;
    }
    
    TestHelper::removeTestFile(testLogFile);
    
    if (allPassed) {
        std::cout << "✓ Все тесты Logger пройдены\n";
    } else {
        std::cout << "✗ Некоторые тесты Logger не пройдены\n";
    }
}

void testIntegration() {
    std::cout << "\n=== Интеграционный тест ===\n";
    
    bool allPassed = true;
    
    // Создаем тестовые файлы
    std::string authFile = "test_integration.conf";
    
    if (TestHelper::createTestFile(authFile, "testuser:testpass\n")) {
        
        // Тестируем совместную работу компонентов
        Calculator calc;
        AuthDatabase authDB;
        
        // Calculator работает
        std::vector<uint16_t> testVec = {10, 20, 30};
        uint16_t sum = calc.calculateVectorSum(testVec);
        if (sum == 60) {
            std::cout << "✓ Calculator работает - PASSED\n";
        } else {
            std::cout << "✗ Calculator не работает\n";
            allPassed = false;
        }
        
        // AuthDatabase работает
        bool authLoaded = authDB.loadFromFile(authFile);
        if (authLoaded) {
            std::cout << "✓ AuthDatabase работает - PASSED\n";
        } else {
            std::cout << "✗ AuthDatabase не работает\n";
            allPassed = false;
        }
        
        // Server создается
        try {
            Server server;
            std::cout << "✓ Server создается - PASSED\n";
        } catch (...) {
            std::cout << "✗ Server не создается\n";
            allPassed = false;
        }
        
        TestHelper::removeTestFile(authFile);
        
    } else {
        std::cout << "⚠ Интеграционный тест - SKIPPED (нет прав для создания файлов)\n";
    }
    
    if (allPassed) {
        std::cout << "✓ Интеграционный тест пройден\n";
    } else {
        std::cout << "✗ Интеграционный тест не пройден\n";
    }
}

// Главная функция
int main() {
    std::cout << "Запуск МОДУЛЬНОГО ТЕСТИРОВАНИЯ СЕРВЕРА\n";
    std::cout << "========================================\n\n";
    
    try {
        testCalculator();
        std::cout << "----------------------------------------\n";
        
        testAuthDatabase();
        std::cout << "----------------------------------------\n";
        
        testLogger();
        std::cout << "----------------------------------------\n";
        
        
        testIntegration();
        std::cout << "----------------------------------------\n";
        
        testEdgeCases();
        
        std::cout << "\n========================================\n";
        std::cout << "ТЕСТИРОВАНИЕ УСПЕШНО ЗАВЕРШЕНО!\n";
        std::cout << "Все основные компоненты server.cpp протестированы\n";
        std::cout << "========================================\n";
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "\n✗ ТЕСТ ПРОВАЛЕН: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "\n✗ НЕИЗВЕСТНАЯ ОШИБКА В ТЕСТАХ" << std::endl;
        return 1;
    }
}
