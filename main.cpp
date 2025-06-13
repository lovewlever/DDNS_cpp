#include "NetworkRequest.h"
#include "DDNSWorker.h"

// TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
int main()
{
    auto ddnsWorker = std::make_unique<DDNSWorker>();
    if (const auto i = ddnsWorker->readConfig(); i != 0)
    {
        return i;
    }
    std::thread thread{[worker = std::move(ddnsWorker)] ()
    {
        worker->run();
    }};
    thread.join();
    return 0;
}

// TIP See CLion help at <a
// href="https://www.jetbrains.com/help/clion/">jetbrains.com/help/clion/</a>.
//  Also, you can try interactive lessons for CLion by selecting
//  'Help | Learn IDE Features' from the main menu.