#include <thread>
#include "DTLSConnection.hpp"

void ServerThread() {
    OpenSSLWrapper::DTLSConnection serverConnection(OpenSSLWrapper::SocketType::Server);

    // 设置服务器证书和私钥
    if (!serverConnection.setCertificate("./certificate.pem", "./private.pem")) {
        std::cout << "Failed to set server certificate and key" << std::endl;
        return;
    }

    // 绑定端口并开始监听连接
    if (serverConnection.connect("127.0.0.1", 4433)) {
        char buffer[1024];
        if (serverConnection.receive(buffer, sizeof(buffer))) {
            std::cout << "Received message: " << buffer << std::endl;

            const char* response = "Hello, DTLS Client!";
            serverConnection.send(response, strlen(response));
        }
        serverConnection.disconnect();
    }
}

void ClientThread() {
    OpenSSLWrapper::DTLSConnection connection(OpenSSLWrapper::SocketType::Client);

    // 连接到服务器
    if (connection.connect("127.0.0.1", 4433)) {
        const char* message = "Hello, DTLS Server!";
        connection.send(message, strlen(message));

        char buffer[1024];
        if (connection.receive(buffer, sizeof(buffer))) {
            std::cout << "Received response: " << buffer << std::endl;
        }
        connection.disconnect();
    }
}

int main() {
    std::thread server(ServerThread);
    std::this_thread::sleep_for(std::chrono::seconds(1)); // Ensure server is up before starting client
    std::thread client(ClientThread);

    server.join();
    client.join();

    return 0;
}
