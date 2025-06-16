//
// Created by catog on 2025/6/16.
//

#ifndef GLOG_H
#define GLOG_H
#include <cstdint>
#include <iostream>

class GLog {
private:
    static bool enable;
    static bool writeLogToFile;
    static std::string logFileName;
    class NullStream final : public std::ostream {
    public:
        NullStream() : std::ostream(nullptr) {}
    };
    static inline NullStream nullStream{};
    static inline std::unique_ptr<std::ostream> fileOstreamPtr{nullptr};
public:
    GLog();
    ~GLog();
    const static int32_t LogLevelInfo;
    const static int32_t LogLevelError;

    static void setEnable(bool enable);
    static void setWriteLogToFile(const std::string &fileName);

    static std::ostream  & log(int32_t level = LogLevelInfo);

};



#endif //GLOG_H
