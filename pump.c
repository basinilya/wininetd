#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include "wininetd.h"

#if defined _POSIX_THREAD_SAFE_FUNCTIONS
# define FLOCKFILE flockfile
# define FUNLOCKFILE funlockfile 
#elif (defined _MSC_VER)
# define FLOCKFILE _lock_file
# define FUNLOCKFILE _unlock_file
#else
# define FLOCKFILE LockPointer
# define FUNLOCKFILE UnlockPointer
#endif

void __pWin32Error(DWORD eNum, const char* fmt, va_list args)
{
	char* msg;

	FLOCKFILE(stdout);

	winet_log(WINET_LOG_WARNING, "[%s] ", WINET_APPNAME);
	if (fmt) {
		_winet_log(WINET_LOG_WARNING, fmt, args);
  }

  if (0 == FormatMessageA( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
         NULL, eNum,
         MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
         (LPSTR )&msg, 0, NULL ))
  {
		(HLOCAL)msg = LocalAlloc(LMEM_FIXED, 30);
		if (!msg) return;
		sprintf(msg, "0x%08x (%d)", eNum, eNum);
  }
	winet_log(WINET_LOG_WARNING, ": %s\n", msg);

	FUNLOCKFILE(stdout);

	LocalFree((HLOCAL)msg);
}

void pWin32Error(char const *fmt, ...)
{
	va_list args;
	DWORD eNum = GetLastError();

	va_start(args, fmt);
	__pWin32Error(eNum, fmt, args);
	va_end(args);
}

void pWinsockError(char const *fmt, ...)
{
	va_list args;
	DWORD eNum = WSAGetLastError();

	va_start(args, fmt);
	__pWin32Error(eNum, fmt, args);
	va_end(args);
}

typedef struct pumpparam_t {
	SOCKET sock;
	HANDLE p2s_our;
	HANDLE s2p_our;
} pumpparam_t;

#define pref ((HANDLE)sock == hRead ? "s2p" : "p2s")

static
int pump_s2p(SOCKET sRead, HANDLE hWrite)
{
	char buf[2048], *p, *pend;
	int nr, nw;

	for(;;) {
		nr = recv(sRead, buf, sizeof(buf), 0);
		if (nr < 0) {
			pWinsockError("recv() failed");
			return -1;
		}
		if (nr == 0) break;
		pend = buf + nr;
		for(p = buf; p < pend; p += nw, nr -= nw) {
			if (!WriteFile(hWrite, p, nr, &nw, NULL)) {
				pWin32Error("WriteFile() failed");
				return -2;
			}
		}
	}
	return 0;
}

static
int pump_p2s(HANDLE hRead, SOCKET sWrite)
{
	char buf[2048], *p, *pend;
	int nr, nw;

	for(;;) {
		if (!ReadFile(hRead, buf, sizeof(buf), &nr, NULL)) {
			pWin32Error("ReadFile() failed");
			return -1;
		}
		if (nr == 0) break;
		pend = buf + nr;
		for(p = buf; p < pend; p += nw, nr -= nw) {
			nw = send(sWrite, p, nr, 0);
			if (nw <= 0) {
				pWin32Error("WriteFile() failed");
				return -2;
			}
		}
	}
	return 0;
}

static
DWORD WINAPI thr_p2s(LPVOID lpThreadParameter)
{
	int rc;
	pumpparam_t *pumpparam = (pumpparam_t *)lpThreadParameter;

	winet_log(WINET_LOG_MESSAGE, "[%s] p2s thread started\n", WINET_APPNAME);

	rc = pump_p2s(pumpparam->p2s_our, pumpparam->sock);
	if (rc != -2) {
		/* EOF or read error */
		if (SOCKET_ERROR == shutdown(pumpparam->sock, SD_SEND)) {
			pWinsockError("shutdown(SD_SEND) failed");
		} else {
			printf("shutdown(SD_SEND) ok\n");
		}
	}
	if (!CloseHandle(pumpparam->p2s_our)) {
		pWin32Error("CloseHandle() failed");
	}
	return 0;
}

static
DWORD WINAPI thr_s2p(LPVOID lpThreadParameter)
{
	int rc;
	DWORD tid;
	HANDLE hthr_p2s;
	pumpparam_t *pumpparam = (pumpparam_t *)lpThreadParameter;

	winet_log(WINET_LOG_MESSAGE, "[%s] s2p thread started\n", WINET_APPNAME);

	hthr_p2s = CreateThread(NULL, 0, thr_p2s, pumpparam, 0, &tid);
	if (!hthr_p2s) {
		pWin32Error("CreateThread() failed");
		return 1;
	}
	rc = pump_s2p(pumpparam->sock, pumpparam->s2p_our);
	if (rc == -2) {
		/* write error */
		if (SOCKET_ERROR == shutdown(pumpparam->sock, SD_RECEIVE)) {
			pWinsockError("shutdown() failed");
		} else {
			printf("shutdown(SD_RECEIVE) ok\n");
		}
	}
	if (!CloseHandle(pumpparam->s2p_our)) {
		pWin32Error("CloseHandle() failed");
	}

	WaitForSingleObject(hthr_p2s, INFINITE);
	CloseHandle(hthr_p2s);
	free(pumpparam);

	return 0;
}

int create_pump_handles(SOCKET sock, HANDLE *in, HANDLE *out, HANDLE *err)
{
	HANDLE s2p_their, p2s_their;
	HANDLE hthr_s2p;
	DWORD tid;
	pumpparam_t *pumpparam;

	pumpparam = (pumpparam_t*)malloc(sizeof(pumpparam_t));
	if (!pumpparam) {
		perror("malloc() failed");
		return -1;
	}
	if (!CreatePipe(&s2p_their, &pumpparam->s2p_our, NULL, 0)) {
		pWin32Error("CreatePipe() failed");
		goto err1;
	}
	if (!CreatePipe(&pumpparam->p2s_our, &p2s_their, NULL, 0)) {
		pWin32Error("CreatePipe() failed");
		goto err2;
	}

	if (!DuplicateHandle(GetCurrentProcess(), p2s_their, GetCurrentProcess(),
			     err, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
		pWin32Error("DuplicateHandle() failed");
		goto err3;
	}

	if (!DuplicateHandle(GetCurrentProcess(), p2s_their, GetCurrentProcess(),
			     out, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
		pWin32Error("DuplicateHandle() failed");
		goto err4;
	}

	CloseHandle(p2s_their);

	if (!DuplicateHandle(GetCurrentProcess(), s2p_their, GetCurrentProcess(),
			     in, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
		pWin32Error("DuplicateHandle() failed");
		goto err5;
	}

	CloseHandle(s2p_their);

	pumpparam->sock = sock;
	hthr_s2p = CreateThread(NULL, 0, thr_s2p, pumpparam, 0, &tid);
	if (!hthr_s2p) {
		pWin32Error("CreateThread() failed");
		goto err6;
	}
	CloseHandle(hthr_s2p);
	return 0;
err6:
	CloseHandle(*in);
err5:
	CloseHandle(*out);
err4:
	CloseHandle(*err);
err3:
	CloseHandle(p2s_their);
	CloseHandle(pumpparam->p2s_our);
err2:
	CloseHandle(pumpparam->s2p_our);
	CloseHandle(s2p_their);
err1:
	free(pumpparam);
	return -1;
}