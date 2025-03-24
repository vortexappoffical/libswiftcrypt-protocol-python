#include <iostream>
#include <fstream>
#include <json/json.h>

int main() {
    // Vytvoření objektu pro JSON
    Json::Value root;
    std::ifstream file("data.json"); // Otevření souboru s JSON

    // Načítání JSON do objektu
    file >> root;

    // Příklad zpracování JSON dat
    std::cout << "Jméno: " << root["jmeno"].asString() << std::endl;
    std::cout << "Věk: " << root["vek"].asInt() << std::endl;

    return 0;
}
