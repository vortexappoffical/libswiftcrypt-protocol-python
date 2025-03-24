#include <iostream>
#include <sqlite3.h>

int main() {
    sqlite3 *db;
    char *errMessage = 0;

    // Open SQLite database (will create if not exist)
    int rc = sqlite3_open("test.db", &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return 0;
    } else {
        std::cout << "Opened database successfully" << std::endl;
    }

    // Create SQL table
    const char* createTableSQL = "CREATE TABLE IF NOT EXISTS COMPANY("  \
                                 "ID INT PRIMARY KEY NOT NULL," \
                                 "NAME TEXT NOT NULL," \
                                 "AGE INT NOT NULL," \
                                 "ADDRESS CHAR(50));";

    rc = sqlite3_exec(db, createTableSQL, 0, 0, &errMessage);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMessage << std::endl;
        sqlite3_free(errMessage);
    } else {
        std::cout << "Table created successfully" << std::endl;
    }

    // Insert data into the table
    const char* insertSQL = "INSERT INTO COMPANY (ID, NAME, AGE, ADDRESS) VALUES (1, 'John Doe', 30, '123 Main St');";
    rc = sqlite3_exec(db, insertSQL, 0, 0, &errMessage);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMessage << std::endl;
        sqlite3_free(errMessage);
    } else {
        std::cout << "Records created successfully" << std::endl;
    }

    // Close the database connection
    sqlite3_close(db);

    return 0;
}
