#include <charconv>
#include <iostream>
#include <string_view>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #ifdef _MSC_VER
        #pragma comment(lib, "Ws2_32.lib")
    #endif
    using sock_t = SOCKET;
    constexpr sock_t BAD_SOCK = INVALID_SOCKET;
    inline void closeSock(sock_t s) { closesocket(s); }
    inline bool setNonBlocking(sock_t s) { u_long m = 1; return ioctlsocket(s, FIONBIO, &m) == 0; }
    inline bool connectInProgress() { return WSAGetLastError() == WSAEWOULDBLOCK; }
#else
    #include <arpa/inet.h>
    #include <cerrno>
    #include <fcntl.h>
    #include <netinet/in.h>
    #include <sys/select.h>
    #include <sys/socket.h>
    #include <unistd.h>
    using sock_t = int;
    constexpr sock_t BAD_SOCK = -1;
    inline void closeSock(sock_t s) { close(s); }
    inline bool setNonBlocking(sock_t s) {
        int f = fcntl(s, F_GETFL, 0);
        return f != -1 && fcntl(s, F_SETFL, f | O_NONBLOCK) != -1;
    }
    inline bool connectInProgress() { return errno == EINPROGRESS; }
#endif

namespace {

struct SocketSession {
    int result = 0;
#ifdef _WIN32
    WSADATA data{};
    SocketSession() : result(WSAStartup(MAKEWORD(2, 2), &data)) {}
    ~SocketSession() { if (result == 0) WSACleanup(); }
#else
    SocketSession() = default;
#endif
    SocketSession(const SocketSession&) = delete;
    SocketSession& operator=(const SocketSession&) = delete;
};

bool parseInt(std::string_view s, int& out) {
    int v = 0;
    const char* end = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(s.data(), end, v);
    if (s.empty() || ec != std::errc{} || ptr != end) return false;
    out = v;
    return true;
}

bool parsePorts(std::string_view s, int& lo, int& hi) {
    size_t dash = s.find('-');
    if (dash == std::string_view::npos) {
        if (!parseInt(s, lo)) return false;
        hi = lo;
    } else {
        if (!parseInt(s.substr(0, dash), lo)) return false;
        if (!parseInt(s.substr(dash + 1), hi)) return false;
    }
    return lo >= 1 && hi <= 65535 && lo <= hi;
}

void printUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " -ip <ip_address> -p <port|start-end> [-t <timeout_ms>]\n";
}

bool isPortOpen(const in_addr& addr, int port, int timeoutMs) {
    sock_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == BAD_SOCK) return false;

    if (!setNonBlocking(sock)) {
        closeSock(sock);
        return false;
    }

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(static_cast<unsigned short>(port));
    server.sin_addr = addr;

    bool open = false;
    int r = connect(sock, reinterpret_cast<sockaddr*>(&server), sizeof(server));

    if (r == 0) {
        open = true;
    } else if (connectInProgress()) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);

        timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;

        int sel = select(static_cast<int>(sock) + 1, nullptr, &wfds, nullptr, &tv);
        if (sel > 0 && FD_ISSET(sock, &wfds)) {
            int err = 0;
            socklen_t len = sizeof(err);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) == 0 && err == 0) {
                open = true;
            }
        }
    }

    closeSock(sock);
    return open;
}

}

int main(int argc, char* argv[]) {
    const char* prog = argc > 0 ? argv[0] : "scanner";
    const char* ipStr = nullptr;
    int lo = 0, hi = 0;
    bool havePorts = false;
    int timeoutMs = 500;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];

        if (arg == "-ip") {
            if (i + 1 >= argc) { std::cerr << "Error: -ip requires a value.\n"; return 1; }
            ipStr = argv[++i];
        } else if (arg == "-p") {
            if (i + 1 >= argc) { std::cerr << "Error: -p requires a value.\n"; return 1; }
            if (!parsePorts(argv[++i], lo, hi)) {
                std::cerr << "Error: Invalid port or range (1-65535).\n";
                return 1;
            }
            havePorts = true;
        } else if (arg == "-t") {
            if (i + 1 >= argc) { std::cerr << "Error: -t requires a value.\n"; return 1; }
            if (!parseInt(argv[++i], timeoutMs) || timeoutMs < 1) {
                std::cerr << "Error: Invalid timeout.\n";
                return 1;
            }
        } else {
            std::cerr << "Error: Unknown argument '" << arg << "'.\n";
            printUsage(prog);
            return 1;
        }
    }

    if (!ipStr || !havePorts) {
        printUsage(prog);
        return 1;
    }

    in_addr addr{};
    if (inet_pton(AF_INET, ipStr, &addr) != 1) {
        std::cerr << "Error: Invalid IPv4 address.\n";
        return 1;
    }

    SocketSession session;
    if (session.result != 0) {
        std::cerr << "Socket init failed: " << session.result << '\n';
        return 1;
    }

    std::cout << "Scanning " << ipStr << " ports " << lo << "-" << hi << "...\n";
    int found = 0;
    for (int port = lo; port <= hi; ++port) {
        if (isPortOpen(addr, port, timeoutMs)) {
            std::cout << "  " << port << " OPEN\n";
            ++found;
        }
    }
    std::cout << "Done. " << found << " open port(s).\n";

    return 0;
}