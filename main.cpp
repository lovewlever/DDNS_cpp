#include "NetworkRequest.h"
#include "DDNSWorker.h"
#include "GetTheLocalIP.h"
#include "GLog.h"
#include "SSHOpenWRTGetIp.h"

// TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
int main()
{
    bool isTest{false};

    auto ddnsWorker = std::make_unique<DDNSWorker>();
    if (const auto i = ddnsWorker->readConfig(); i != 0)
    {
        std::cout << "Press Enter to exit...";
        std::cin.ignore();
        return i;
    }

    if (isTest)
    {
        // test
        std::thread t1{
            []()
            {
                GetTheLocalIP ip{};
                GLog::setEnable(true);
                GLog::setWriteLogToFile("log");
                while (true)
                {
                    SSHOpenWRTGetIp ssh{"", "", "", 22};
                    ssh.execRemoteCommand();
                    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                }
            }
        };
        t1.join();
    } else
    {
        std::thread thread{
            [worker = std::move(ddnsWorker)]()
            {
                worker->run();
            }
        };
        thread.join();
    }
    std::cout << "Press Enter to exit...";
    std::cin.ignore();
    return 0;
}

// TIP See CLion help at <a
// href="https://www.jetbrains.com/help/clion/">jetbrains.com/help/clion/</a>.
//  Also, you can try interactive lessons for CLion by selecting
//  'Help | Learn IDE Features' from the main menu.
