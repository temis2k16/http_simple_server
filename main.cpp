#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <thread>
#include <iostream>
#include <sstream>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <unordered_set>
#include <ctime>
#include "sha1.h"

#define PORT "8080"         // слушаем этот порт
#define THREADS_COUNT 5     // количество потоков

using namespace std;

mutex queue_mutex;          // мьютекс для изъятия задач из очереди
mutex map_mutex;            // мьютекс для обработки и вывода строк
condition_variable data_condition; // для изъятия задач только если они появляются в очереди

const string answer = "HTTP/1.1 200 OK\n"   // ответ сервера
                "Server: Hello\n"
                "Content-Length: 3\n"
                "Content-Type: text/plain\n"
                "\n"
                "OK"
                "\n";

struct ThreadData           // данные для потока, чтобы считать число хитов
{
    unordered_set<string> path_set{};
    unordered_set<string> agent_set{};
    int path_hitcount{0};
    int user_agent_hitcount{0};
};

queue<pair<string, string>> requests_queue;  // очередь запросов в формате <path, user_agent>
unordered_map<thread::id, unique_ptr<ThreadData>> thread_data_map; // таблица за записи данных для каждого потока


/**
 * @short Извлечение Path и User-Agent из http запроса
 * @param buffer сам запрос
 * @return <Path, User-Agent>
 */
pair<string,string> parseRequest(const string& buffer)
{
    string path;
    string user_agent;
    string tmp;
    stringstream ss(buffer);
    while (ss >> tmp)
    {
        if (tmp == "GET")
        {
            ss >> path;
            continue;
        }
        if (tmp == "User-Agent:")
        {
            getline(ss, user_agent);
            user_agent.pop_back(); // не нужен завершающий символ
            break;
        }
    }
    return make_pair(path, user_agent);
}


/**
 * @short обработка подключений на основе неблокирующих сокетов и функции select
 * @note когда запрос добавляется очередь вызывается notify_one()
 *
 */
void server()
{
    fd_set master;    // главный список файловых дескрипторов
    fd_set read_fds;  // для временной копии списка дескрипторов для функции select()
    int fdmax;        // максимальный номер дескриптора

    int listener;     // дескриптор слушающего сокета
    int newfd;        // новый дескриптор сокета от функции accept()
    struct sockaddr_storage remoteaddr; // адрес клиента
    socklen_t addrlen;

    char buf[BUFSIZ];    // буффер для запроса
    int nbytes;

    int yes = 1;        // для setsockopt() SO_REUSEADDR (переиспользование порта)
    int i, rv;

    struct addrinfo hints, *ai, *p;

    FD_ZERO(&master);
    FD_ZERO(&read_fds);

    // биндим сокет
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if ((rv = getaddrinfo(nullptr, PORT, &hints, &ai)) != 0)
    {
        fprintf(stderr, "selectserver: %s\n", gai_strerror(rv));
        exit(1);
    }

    for (p = ai; p != nullptr; p = p->ai_next)
    {
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener < 0)
        {
            continue;
        }

        // настройка переиспользования порта
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

        if (bind(listener, p->ai_addr, p->ai_addrlen) < 0)
        {
            close(listener);
            continue;
        }

        break;
    }

    // если не удалось забиндить сокет
    if (p == nullptr)
    {
        fprintf(stderr, "selectserver: failed to bind\n");
        exit(2);
    }
    freeaddrinfo(ai); // очищаем инфо о клиенте

    if (listen(listener, 0) == -1)
    {
        perror("listen");
        exit(3);
    }

    // добавляем слушающий сокет в главный список дескрипторов
    FD_SET(listener, &master);

    // запоминаем максимальный файловый дескриптор
    fdmax = listener;

    // главный цикл
    for (;;)
    {
        read_fds = master;
        if (select(fdmax + 1, &read_fds, nullptr, nullptr, nullptr) == -1)
        {
            perror("select");
            exit(4);
        }

        // цикл по существующим подключениям
        for (i = 0; i <= fdmax; i++)
        {
            if (FD_ISSET(i, &read_fds))
            { // новое подключение
                if (i == listener)
                {
                    // обработаем новые подключения
                    addrlen = sizeof remoteaddr;
                    newfd = accept(listener, (struct sockaddr *) &remoteaddr, &addrlen);

                    if (newfd == -1)
                    {
                        perror("accept");
                    }
                    else
                    {
                        FD_SET(newfd, &master); // добавить в главный список дескрипторов
                        if (newfd > fdmax)
                        {    // запомнить максимальный
                            fdmax = newfd;
                        }
                    }
                }
                else
                {
                    // обработаем сообщение от клиента
                    if ((nbytes = recv(i, buf, sizeof buf, 0)) <= 0)
                    {
                        // ошибка или подключение закрыто
                        if (nbytes == 0)
                        {
                            // подключение закрыто
                            printf("selectserver: socket %d hung up\n", i);
                        }
                        else
                        {
                            perror("recv");
                        }
                        close(i); // bye!
                        FD_CLR(i, &master); // удалить из главного списка дескрипторов
                    }
                    else
                    {
                        // получили сообщение, парсим его
                        auto const path_agent = parseRequest(buf);
                        {
                            // кладем результат в очередь
                            lock_guard<mutex> lg(queue_mutex);
                            requests_queue.push(path_agent);
                        }
                        // извещаем, что можно взять сообщение из очереди
                        data_condition.notify_one();
                        // отправляем ответ "ОК"
                        if (send(i, answer.c_str(), answer.size(), 0) == -1)
                        {
                            perror("send");
                        }
                    }
                } // END обработаем сообщение от клиента
            } // END новое подключение
        } // END цикл по существующим подключениям
    } // END главный цикл
}


/**
 * @short вывод инфы по обработанному запросу
 * @param path Путь страницы
 * @param user_agent содержимое заголовка User-Agent
 * @param path_hitcount количество хитов данного пути страницы в данном потоке
 * @param user_agent_hitcount количество хитов User-Agent в данном потоке
 */
void printRequestInfo(const string & path, const string & user_agent,
                      int path_hitcount, int user_agent_hitcount)
{
    time_t result = std::time(nullptr);
    string time = std::asctime(std::gmtime(&result));
    time.pop_back();
    string path_hash = sha1(path);
    string agent_hash = sha1(user_agent);

    lock_guard<mutex> maplock(map_mutex); // блокировка для std::cout

    cout << time;
    cout << "; thread_id: " << this_thread::get_id() ;
    cout << "; path: " << path ;
    cout << "; path_sha: " << path_hash;
    cout << "; path_hit: " << path_hitcount;
    cout << "; agent: " << user_agent;
    cout << "; agent_sha: " << agent_hash;
    cout << "; agent_hit: " << user_agent_hitcount << endl;
}


/**
 * @short обновление информации по hitcount для потоков
 * и вызов вывода строки
 * @param data <Path, User-Agent>
 */
void requestProcess(const pair<string, string>& data)
{
    thread::id id = this_thread::get_id();
    unique_lock<mutex> maplock(map_mutex);  // блокировка для обновления thread_data_map
    if (thread_data_map.count(id) == 0)
    {
        thread_data_map[id] = make_unique<ThreadData>();
    }

    auto &thread_data = thread_data_map[id];
    if (thread_data->path_set.count(data.first))
    {
        thread_data->path_hitcount++;
    }
    else
    {
        thread_data->path_set.insert(data.first);
        thread_data->path_hitcount = 1;
    }
    if (thread_data->agent_set.count(data.second))
    {
        thread_data->user_agent_hitcount++;
    }
    else
    {
        thread_data->agent_set.insert(data.second);
        thread_data->user_agent_hitcount = 1;
    }
    maplock.unlock();

    // вызываем вывод
    printRequestInfo(data.first, data.second, thread_data->path_hitcount, thread_data->user_agent_hitcount);
}


/**
 * @short изъятие реквеста из очереди в потоке
 */
void queueGetRequest()
{
    while (true)
    {
        unique_lock<mutex> ul(queue_mutex);
        // ожидаем оповещение о добавлении в очередь
        data_condition.wait(ul, []{return !requests_queue.empty();});
        auto request = requests_queue.front();
        requests_queue.pop();
        ul.unlock();
        requestProcess(request);
    }
}


int main()
{
    // запускаем обработку подключений
    thread server_thread(server);

    // запускаем обработку очереди
    vector<thread> queue_threads;
    for (int i = 0; i < THREADS_COUNT; i++)
    {
        thread queue_thread(queueGetRequest);
        queue_threads.push_back(std::move(queue_thread));
    }

    for (auto &qt : queue_threads)
        qt.join();
    server_thread.join();
}
