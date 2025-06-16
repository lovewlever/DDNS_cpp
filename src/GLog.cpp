//
// Created by catog on 2025/6/16.
//

#include "../include/GLog.h"

const int32_t GLog::LogLevelInfo{0};
const int32_t GLog::LogLevelError{1};
bool GLog::enable{true};
bool GLog::writeLogToFile{false};

GLog::GLog()
{

}

GLog::~GLog()
{

}

void GLog::setEnable(const bool enable)
{
    GLog::enable = enable;
}

void GLog::setWriteLogToFile(bool writeLogToFile)
{
    GLog::writeLogToFile = writeLogToFile;
}

std::ostream & GLog::log(const int32_t level)
{
    if (level == LogLevelError)
    {
        return std::cerr;
    }
    if (!enable)
    {
        return s_nullStream;
    }
    return std::cout;
}


