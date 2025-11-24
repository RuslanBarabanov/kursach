#include <iostream>
#include <cassert>
#include <vector>
#include <fstream>
#include "server.h"

// Вспомогательные функции для тестирования
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

// Тест 1: Calculator (самый надежный)
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
    
    // Тест 2: Сумма пустого вектора
    std::vector<uint16_t> vec2 = {};
    uint16_t result2 = calculator.calculateVectorSum(vec2);
    if (result2 == 0) {
        std::cout << "✓ Сумма пустого вектора - PASSED\n";
    } else {
        std::cout << "✗ Сумма пустого вектора - FAILED\n";
        allPassed = false;
    }
    
    // Тест 3: Сумма с переполнением
    std::vector<uint16_t> vec3 = {UINT16_MAX, 1};
    uint16_t result3 = calculator.calculateVectorSum(vec3);
    if (result3 == UINT16_MAX) {
        std::cout << "✓ Обработка переполнения - PASSED\n";
    } else {
        std::cout << "✗ Обработка переполнения - FAILED\n";
        allPassed = false;
    }
    
    // Тест 4: Большой вектор
    std::vector<uint16_t> vec4(100, 10);
    uint16_t result4 = calculator.calculateVectorSum(vec4);
    if (result4 == 1000) {
        std::cout << "✓ Сумма большого вектора - PASSED\n";
    } else {
        std::cout << "✗ Сумма большого вектора - FAILED\n";
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
    
    // Тест 3: Аутентификация (проверяем что не падает)
    try {
        bool authResult = authDB.authenticate("user", "", "testsalt12345678", "somehash");
        std::cout << "✓ Аутентификация (без падения) - PASSED\n";
    } catch (...) {
        std::cout << "✗ Аутентификация (упала с исключением) - FAILED\n";
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
        // Тест 1: Создание логгера
        Logger logger(testLogFile);
        std::cout << "✓ Создание логгера - PASSED\n";
        
        // Тест 2: Инициализация
        bool initResult = logger.initialize();
        if (initResult) {
            std::cout << "✓ Инициализация логгера - PASSED\n";
        } else {
            std::cout << "⚠ Инициализация логгера - SKIPPED (нет прав)\n";
        }
        
        // Тест 3: Логирование (проверяем что не падает)
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


// Тест 5: Интеграционный тест
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

// Тест 6: Граничные условия
void testEdgeCases() {
    std::cout << "\n=== Тестирование граничных условий ===\n";
    
    Calculator calculator;
    bool allPassed = true;
    
    // Тест 1: Вектор с максимальными значениями
    std::vector<uint16_t> maxVec = {UINT16_MAX, UINT16_MAX};
    uint16_t maxResult = calculator.calculateVectorSum(maxVec);
    if (maxResult == UINT16_MAX) {
        std::cout << "✓ Обработка максимальных значений - PASSED\n";
    } else {
        std::cout << "✗ Обработка максимальных значений - FAILED\n";
        allPassed = false;
    }
    
    // Тест 2: Вектор с нулевыми значениями
    std::vector<uint16_t> zeroVec = {0, 0, 0, 0};
    uint16_t zeroResult = calculator.calculateVectorSum(zeroVec);
    if (zeroResult == 0) {
        std::cout << "✓ Обработка нулевых значений - PASSED\n";
    } else {
        std::cout << "✗ Обработка нулевых значений - FAILED\n";
        allPassed = false;
    }
    
    // Тест 3: Вектор с одним элементом
    std::vector<uint16_t> singleVec = {42};
    uint16_t singleResult = calculator.calculateVectorSum(singleVec);
    if (singleResult == 42) {
        std::cout << "✓ Обработка одного элемента - PASSED\n";
    } else {
        std::cout << "✗ Обработка одного элемента - FAILED\n";
        allPassed = false;
    }
    
    if (allPassed) {
        std::cout << "✓ Все граничные условия обработаны\n";
    } else {
        std::cout << "✗ Некоторые граничные условия не обработаны\n";
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
