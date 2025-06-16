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
    class NullStream final : public std::ostream {
    public:
        NullStream() : std::ostream(nullptr) {}
    };
    static inline NullStream s_nullStream{};
public:
    GLog();
    ~GLog();
    const static int32_t LogLevelInfo;
    const static int32_t LogLevelError;

    static void setEnable(bool enable);
    static void setWriteLogToFile(bool writeLogToFile);

    static std::ostream  & log(int32_t level = LogLevelInfo);

};



#endif //GLOG_H
