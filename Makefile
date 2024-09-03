# 指定编译器和编译选项
CXX = g++
CXXFLAGS = -std=c++17 -Wall -I./include -I/usr/local/include
LDFLAGS = -L/usr/local/lib -lssl -lcrypto

# 目标文件
TARGET = dtls_example
OBJECTS = main.o DTLSConnection.o SSLWrapper.o

# 默认规则
all: $(TARGET)

# 链接目标文件生成可执行文件
$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

# 编译 DTLSConnection.cpp
DTLSConnection.o: src/DTLSConnection.cpp include/DTLSConnection.hpp include/SocketType.hpp include/SSLWrapper.hpp
	$(CXX) $(CXXFLAGS) -c src/DTLSConnection.cpp -o DTLSConnection.o

# 编译 SSLWrapper.cpp
SSLWrapper.o: src/SSLWrapper.cpp include/SSLWrapper.hpp
	$(CXX) $(CXXFLAGS) -c src/SSLWrapper.cpp -o SSLWrapper.o

# 编译 main.cpp
main.o: src/main.cpp include/DTLSConnection.hpp include/SSLWrapper.hpp include/SocketType.hpp
	$(CXX) $(CXXFLAGS) -c src/main.cpp -o main.o

# 清理生成的文件
clean:
	rm -f $(TARGET) $(OBJECTS)
