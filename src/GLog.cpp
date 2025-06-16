//
// Created by catog on 2025/6/16.
//

#include "../include/GLog.h"
#include <filesystem>
#include <iostream>
#include <fstream>
#include "AliCloudReport.h"

const int32_t GLog::LogLevelInfo{0};
const int32_t GLog::LogLevelError{1};
bool GLog::enable{false};
bool GLog::writeLogToFile{true};
std::string GLog::logFileName;

GLog::GLog() = default;

GLog::~GLog() = default;

void GLog::setEnable(const bool enable)
{
    GLog::enable = enable;
}

void GLog::setWriteLogToFile(const std::string &path)
{
    const auto now = std::chrono::system_clock::now() + std::chrono::hours(8);
    const auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d_%H");
    const auto fileName = path + "/" + ss.str() + ".log";

    if (!std::filesystem::is_directory(path))
    {
        std::filesystem::create_directory(path);
    }

    if (!std::filesystem::exists(fileName))
    {
        std::fstream fstream(fileName.c_str(), std::ios::out | std::ios::trunc);
        fstream.close();
    }

    writeLogToFile = true;
    if (auto stream = std::make_unique<std::ofstream>(fileName, std::ios::app); stream->is_open())
    {
        fileOstreamPtr = std::move(stream);
    }
}

std::ostream & GLog::log(const int32_t level)
{
    if (level == LogLevelError)
    {
        if (writeLogToFile)
        {
            return *fileOstreamPtr;
        }
        return std::cerr;
    }
    if (!enable)
    {
        return nullStream;
    }
    if (writeLogToFile)
    {
        return *fileOstreamPtr;
    }
    return std::cout;
}


