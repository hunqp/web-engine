#ifndef UTILS_H
#define UTILS_H

#include "json.hpp"
#include <string>

extern std::string readBin(const std::string& filename);
extern std::string readFile(const std::string& filename);
extern bool wrteFile(const std::string& filename, const std::string& content);
extern int runCommands(const char *fmt, ...);
extern std::string runShellCommands(const char *fmt, ...);

template<typename T>
bool assignJSValue(const nlohmann::json& js, const std::string& key, T& value) {
    if (js.contains(key)) {
        value = js[key].get<T>();
        return true;
    }
    return false;
}

extern std::string MD5Sum(const std::string& filename);

extern int runFormatExitDisks(void);

extern int setMachineTimezone(const std::string timezone);

#endif /* UTILS_H */
