#include "TCPHandler.h"

SOCKET tcpSocket = INVALID_SOCKET;
USHORT tcpListen = 0;

static SRWLOCK tcpLock = SRWLOCK_INIT;
static unordered_map<USHORT, SOCKADDR_IN6> tcpContext;

bool TCPHandler::INIT()
{
	AcquireSRWLockExclusive(&tcpLock);

	if (tcpSocket != INVALID_SOCKET)
	{
		closesocket(tcpSocket);
		tcpSocket = INVALID_SOCKET;
	}

	auto client = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (client == INVALID_SOCKET)
	{
		ReleaseSRWLockExclusive(&tcpLock);
		printf("[Redirector][TCPHandler::INIT] Create socket failed: %d\n", WSAGetLastError());
		return false;
	}

	{
		int v6only = 0;
		if (setsockopt(client, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&v6only, sizeof(v6only)) == SOCKET_ERROR)
		{
			printf("[Redirector][TCPHandler::INIT] Set socket option failed: %d\n", WSAGetLastError());
			closesocket(client);
			ReleaseSRWLockExclusive(&tcpLock);
			return false;
		}
	}

	// Disable Nagle on listen socket
	int nodelay = 1;
	setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

	// Expand socket buffer sizes to 2MB
	int bufSize = 2 * 1024 * 1024;
	setsockopt(client, SOL_SOCKET, SO_RCVBUF, (char*)&bufSize, sizeof(bufSize));
	setsockopt(client, SOL_SOCKET, SO_SNDBUF, (char*)&bufSize, sizeof(bufSize));

	{
		SOCKADDR_IN6 addr;
		IN6ADDR_SETANY(&addr);

		if (bind(client, (PSOCKADDR)&addr, sizeof(SOCKADDR_IN6)) == SOCKET_ERROR)
		{
			printf("[Redirector][TCPHandler::INIT] Bind socket failed: %d\n", WSAGetLastError());
			closesocket(client);
			ReleaseSRWLockExclusive(&tcpLock);
			return false;
		}
	}
	
	if (listen(client, 1024) == SOCKET_ERROR)
	{
		printf("[Redirector][TCPHandler::INIT] Listen socket failed: %d\n", WSAGetLastError());
		closesocket(client);
		ReleaseSRWLockExclusive(&tcpLock);
		return false;
	}

	{
		SOCKADDR_IN6 addr;
		int addrLength = sizeof(SOCKADDR_IN6);
		if (getsockname(client, (PSOCKADDR)&addr, &addrLength) == SOCKET_ERROR)
		{
			printf("[Redirector][TCPHandler::INIT] Get listen address failed: %d\n", WSAGetLastError());
			closesocket(client);
			ReleaseSRWLockExclusive(&tcpLock);
			return false;
		}

		tcpListen = (addr.sin6_family == AF_INET6) ? addr.sin6_port : ((PSOCKADDR_IN)&addr)->sin_port;
	}

	tcpSocket = client;
	ReleaseSRWLockExclusive(&tcpLock);

	thread(TCPHandler::Accept).detach();
	return true;
}

void TCPHandler::FREE()
{
	AcquireSRWLockExclusive(&tcpLock);

	if (tcpSocket != INVALID_SOCKET)
	{
		closesocket(tcpSocket);
		tcpSocket = INVALID_SOCKET;
	}
	tcpListen = 0;

	tcpContext.clear();
	ReleaseSRWLockExclusive(&tcpLock);
}

void TCPHandler::CreateHandler(SOCKADDR_IN6 client, SOCKADDR_IN6 remote)
{
	auto id = (client.sin6_family == AF_INET) ? ((PSOCKADDR_IN)&client)->sin_port : client.sin6_port;

	AcquireSRWLockExclusive(&tcpLock);
	tcpContext[id] = remote;
	ReleaseSRWLockExclusive(&tcpLock);
}

void TCPHandler::DeleteHandler(SOCKADDR_IN6 client)
{
	auto id = (client.sin6_family == AF_INET) ? ((PSOCKADDR_IN)&client)->sin_port : client.sin6_port;

	AcquireSRWLockExclusive(&tcpLock);
	tcpContext.erase(id);
	ReleaseSRWLockExclusive(&tcpLock);
}

void TCPHandler::Accept()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

	while (tcpSocket != INVALID_SOCKET)
	{
		auto client = accept(tcpSocket, NULL, NULL);
		if (client == INVALID_SOCKET)
		{
			int lasterr = WSAGetLastError();
			if (lasterr == 10004)
				return;

			printf("[Redirector][TCPHandler::Accept] Accept client failed: %d\n", lasterr);
			return;
		}

		// Disable Nagle's algorithm immediately on client socket
		int nodelay = 1;
		setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

		// Expand client socket buffers to 2MB
		int bufSize = 2 * 1024 * 1024;
		setsockopt(client, SOL_SOCKET, SO_RCVBUF, (char*)&bufSize, sizeof(bufSize));
		setsockopt(client, SOL_SOCKET, SO_SNDBUF, (char*)&bufSize, sizeof(bufSize));

		thread(TCPHandler::Handle, client).detach();
	}
}

void TCPHandler::Handle(SOCKET client)
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

	USHORT id = 0;

	{
		SOCKADDR_IN6 addr;
		int addrLength = sizeof(SOCKADDR_IN6);

		if (getpeername(client, (PSOCKADDR)&addr, &addrLength) == SOCKET_ERROR)
		{
			closesocket(client);
			return;
		}

		id = (addr.sin6_family == AF_INET) ? ((PSOCKADDR_IN)&addr)->sin_port : addr.sin6_port;
	}

	SOCKADDR_IN6 target{};
	bool found = false;

	AcquireSRWLockShared(&tcpLock);
	auto it = tcpContext.find(id);
	if (it != tcpContext.end())
	{
		target = it->second;
		found = true;
	}
	ReleaseSRWLockShared(&tcpLock);

	if (!found)
	{
		closesocket(client);
		return;
	}

	auto remote = new SocksHelper::TCP();
	if (!remote->Connect(&target))
	{
		closesocket(client);
		delete remote;
		return;
	}

	thread sendThread(TCPHandler::Send, client, remote);
	TCPHandler::Read(client, remote);

	// Graceful shutdown to wake up sendThread immediately without UAF
	shutdown(client, SD_BOTH);
	if (remote->tcpSocket != INVALID_SOCKET)
		shutdown(remote->tcpSocket, SD_BOTH);

	if (sendThread.joinable())
		sendThread.join();

	closesocket(client);
	delete remote;
}

void TCPHandler::Read(SOCKET client, SocksHelper::PTCP remote)
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
	char buffer[65536];
	
	while (tcpSocket != INVALID_SOCKET)
	{
		int length = remote->Read(buffer, sizeof(buffer));
		if (length == 0 || length == SOCKET_ERROR)
		{
			shutdown(client, SD_BOTH);
			return;
		}

		if (send(client, buffer, length, 0) != length)
		{
			shutdown(client, SD_BOTH);
			return;
		}
	}
}

void TCPHandler::Send(SOCKET client, SocksHelper::PTCP remote)
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
	char buffer[65536];

	while (tcpSocket != INVALID_SOCKET)
	{
		int length = recv(client, buffer, sizeof(buffer), 0);
		if (length == 0 || length == SOCKET_ERROR)
		{
			if (remote->tcpSocket != INVALID_SOCKET)
				shutdown(remote->tcpSocket, SD_BOTH);
			return;
		}

		if (remote->Send(buffer, length) != length)
		{
			if (remote->tcpSocket != INVALID_SOCKET)
				shutdown(remote->tcpSocket, SD_BOTH);
			return;
		}
	}
}
