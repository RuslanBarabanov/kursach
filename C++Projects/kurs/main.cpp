#include "server.h"
#include <iostream>
#include <cstdlib>

int main(int argc, char** argv) {
    try {
        Server server;
        return server.run(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown fatal error occurred" << std::endl;
        return 1;
    }
}