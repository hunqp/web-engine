#include <cstring>
#include <fstream>
#include <sstream>
#include <stdarg.h>
#include <sys/stat.h>

#include "utils.h"
#include "driver/param/rk_param.h"

std::string readFile(const std::string& filename) {
    std::ifstream file(filename.c_str());
    if (!file.is_open()) {
        return "";
    }
    std::stringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

bool wrteFile(const std::string& filename, const std::string& content) {
    std::ofstream file(filename.c_str());
    if (!file.is_open()) {
        return false;
    }
    file << content;
	system("sync");
    return true;
}

std::string readBin(const std::string& filename) {
    std::ifstream file(filename.c_str(), std::ios::binary);
    if (!file.is_open()) {
        return "";
    }

    std::stringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

int runCommands(const char *fmt, ...) {
	char cmd[256] = {0};
    va_list args;
    va_start(args, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, args);
    va_end(args);
    return system(cmd);
}

std::string runShellCommands(const char *fmt, ...) {
	char cmd[256] = {0};
	std::string result;
	std::array<char, 128> buffer {};
	
	va_list args;
	va_start(args, fmt);
	vsprintf(cmd, fmt, args);
	va_end(args);
	std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);

	if (!pipe) {
		return std::string("UNKNOWN");
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
	result.erase(result.find_last_not_of("\n") + 1);
	return result;
}

std::string MD5Sum(const std::string& filename) {
    return runShellCommands("md5sum %s | awk '{print $1}'", filename.c_str());
}

int setMachineTimezone(const std::string timezone) {
    if (timezone.empty() ||
        timezone.find("..") != std::string::npos ||
        timezone.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_+-.") != std::string::npos) {
            return -1;
        }

    std::string filename = "/oem/usr/share/zoneinfo/" + timezone;
    if (access(filename.c_str(), F_OK) != 0) {
        return -1;
    }

    wrteFile("/userdata/TZ", timezone);
    int rc = runCommands("ln -sf /oem/usr/share/zoneinfo/%s /etc/localtime", timezone.c_str());
    if (rc == 0) {
        tzset();
    }
    return rc;
}

int runFormatExitDisks(void) {
    int rc = -1;
    char hdd[32] = {0};
    char mountpoint[32] = {0};

    FILE *fp = fopen("/proc/mounts", "r");
    if (fp) {
        while (fscanf(fp, "%31s %31s %*s %*s %*d %*d", hdd, mountpoint) == 2) {
            if (strcmp(mountpoint, (const char*)"/mnt/sdcard") == 0) {
                rc = runCommands("killall -9 p2p_client && umount -l %s && mkfs.vfat %s > /dev/null 2>&1", mountpoint, hdd);
                break;
            }
        }
        fclose(fp);
    }
    return rc;
}