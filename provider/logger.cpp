#include "../inc/Logger.h"

Logger::Logger() {
	logFile = std::ofstream("D:/log_file.txt", std::ios_base::out | std::ios_base::app);
}

Logger::~Logger() {
	logFile.close();
}

int Logger::logString(std::string message)
{
	logFile << message << std::endl;
	return 0;
}
