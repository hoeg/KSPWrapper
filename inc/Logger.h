#ifndef __LOGGER_CSP_H__
#define __LOGGER_CSP_H__

#include <string>
#include <fstream>

class Logger {
public:
	Logger();
	~Logger();

	int logString(std::string message);

private:
	std::ofstream logFile;
};
#endif