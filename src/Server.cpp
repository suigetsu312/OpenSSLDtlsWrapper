#include <thread>
#include "DTLSConnection.hpp"
#include <thread>
#include <atomic>

void ServerMessageThread(std::shared_ptr<OpenSSLWrapper::DTLSConnection> serverConnection, std::atomic<bool>& cancel);
void ServerAcceptThread(std::shared_ptr<OpenSSLWrapper::DTLSConnection> serverConnection, std::atomic<bool>& cancel){
    
    while(!cancel.load()){
        // 绑定端口并开始监听连接
        if(serverConnection->connected){
            continue;;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout <<"接收DTLS握手"<<std::endl;
        if (!serverConnection->connect("127.0.0.1", 4433)) {
            std::cout <<"接收連線失敗"<<std::endl;
            continue;
        }
        std::thread Server(ServerMessageThread, serverConnection, std::ref(cancel));
        Server.detach();
    }
}
void ServerMessageThread(std::shared_ptr<OpenSSLWrapper::DTLSConnection> serverConnection, std::atomic<bool>& cancel) {

    std::string responseStr = "Hello, DTLS Client! ";
    const char* response = responseStr.c_str();
    serverConnection->send(response, responseStr.size());

    while(!cancel.load()){
        char buffer[4096];
        int ret = serverConnection->receive(buffer, sizeof(buffer));
        if(!serverConnection->connected || ret <= 0){
            std::cout << "serverConnection->connected : "<< serverConnection->connected  << " ret: "<< ret << std::endl;
            OpenSSLWrapper::GetError(ret);
            break;
        }
        std::string str(buffer); 
        std::cout << "ret : "<< ret  << " 字串: "<< str << std::endl;
        serverConnection->send(response, responseStr.size());
        
    };
    std::cout << "關閉連線"<< std::endl;
    serverConnection->disconnect();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    cancel.store(false);
}
void ServerLoop(std::shared_ptr<OpenSSLWrapper::DTLSConnection> serverConnection, std::atomic<bool>& cancel){
    while(true)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if(cancel){
            cancel.store(false);
            std::thread client(ServerAcceptThread, serverConnection, std::ref(cancel));
            client.detach();
        }
    }

}
int main() {
    std::atomic<bool> cancel(true);
    auto connection = std::make_shared<OpenSSLWrapper::DTLSConnection>(OpenSSLWrapper::SocketType::Server, "./key/ServerCert.crt", "./key/ServerCert.pem");

    std::thread Server(ServerLoop, connection, std::ref(cancel));
    Server.detach();
    
    
    while(true){

        char in;
        std::cin >> in;

        if(in == 'c'){
            std::cout << "關" << std::endl;
            connection->disconnect();
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
