#include <thread>
#include "DTLSConnection.hpp"

void ServerThread() {
    OpenSSLWrapper::DTLSConnection serverConnection(OpenSSLWrapper::SocketType::Server, "./key/ServerCert.crt", "./key/ServerCert.pem");

    // 绑定端口并开始监听连接
    if (!serverConnection.connect("127.0.0.1", 4433)) {
        return;
        serverConnection.disconnect();
    }
    while(true){
        char buffer[1024];
        int ret = serverConnection.receive(buffer, sizeof(buffer));
        if (ret > 0) {
            std::string str(buffer);
            std::cout << "Received message: " << str << std::endl;

            const char* response = "Hello, DTLS Client!";
            serverConnection.send(response, strlen(response));
        }
        if(ret < 0){
            std::cout << "Received Failed" << std::endl;
        }
    };
    serverConnection.disconnect();
}

void ClientThread() {
    OpenSSLWrapper::DTLSConnection connection(OpenSSLWrapper::SocketType::Client, "./key/RootCA.crt");
        // 绑定端口并开始监听连接
    if (!connection.connect("127.0.0.1", 4433)) {
        connection.disconnect();
        return;
    }

    const char* response = "Hello, DTLS Server!";
    connection.send(response, strlen(response));
    while(true){
        char buffer[1024];
        int ret = connection.receive(buffer, sizeof(buffer));
        if (ret > 0) {
            std::string str(buffer);
            std::cout << "Received message: " << str << std::endl;
            connection.send(response, strlen(response));
        }
        if(ret < 0){
            std::cout << "Received Failed" << std::endl;
        }
    };
    connection.disconnect();
}

int main() {
    std::thread server(ServerThread);
    std::this_thread::sleep_for(std::chrono::seconds(1)); // Ensure server is up before starting client
    std::thread client(ClientThread);

    server.join();
    client.join();

    return 0;
}
