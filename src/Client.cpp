#include <thread>
#include "DTLSConnection.hpp"
#include <thread>
#include <atomic>

void ClientThread(std::shared_ptr<OpenSSLWrapper::DTLSConnection> connection, std::atomic<bool>& cancel) {

        // 绑定端口并开始监听连接
    if (!connection->connect("127.0.0.1", 4433)) {
        std::cout << "嘗試連線失敗" << std::endl;
        connection->disconnect();
        cancel.store(true);
        return;
    }


    std::string responseStr = "Hello, DTLS Server!";
    const char* response = responseStr.c_str();
    connection->send(response, responseStr.size());

    while(!cancel){
        char buffer[4096];
        int ret = connection->receive(buffer, sizeof(buffer));
        
        if(!connection->connected || ret <= 0){
            std::cout << "connection->connected : "<< connection->connected  << " ret: "<< ret << std::endl;
            OpenSSLWrapper::GetError(ret);
            break;
        }
        std::string str(buffer); 
        std::cout << "cancel : "<< cancel << " ret : "<< ret  << " 字串: "<< str << std::endl;
        connection->send(response, responseStr.size());
        std::this_thread::sleep_for(std::chrono::seconds(1));
    };
    cancel.store(false);
    std::cout << "迴圈結束關閉連線"<< std::endl;
}

void ClientLoop(std::shared_ptr<OpenSSLWrapper::DTLSConnection> connection, std::atomic<bool>& cancel) 
{   
    while(true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        if(cancel){
            cancel.store(false);
            connection->disconnect();
            connection = std::make_shared<OpenSSLWrapper::DTLSConnection>(OpenSSLWrapper::SocketType::Client, "./key/RootCA.crt");
            std::thread client(ClientThread, connection, std::ref(cancel));
            client.detach();
        }
    }
};

int main() {
    std::atomic<bool> cancel(true);
    auto connection = std::make_shared<OpenSSLWrapper::DTLSConnection>(OpenSSLWrapper::SocketType::Client, "./key/RootCA.crt");
    std::thread client(ClientLoop, connection, std::ref(cancel));
    client.detach();

    while(true){

        char in;
        std::cin >> in;

        if(in == 'c'){
            std::cout << "關" << std::endl;
            cancel.store(true);
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
