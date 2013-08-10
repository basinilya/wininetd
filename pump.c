#include <winsock2.h>
#include <windows.h>
#include "wininetd.h"

void pWin32Error(const char *x);
#define pWinsockError pWin32Error

typedef struct pumpparam_t {
	SOCKET sock;
	HANDLE p2s_our;
	HANDLE s2p_our;
} pumpparam_t;

#define pref ((HANDLE)sock == hRead ? "s2p" : "p2s")

static
int pump(HANDLE hRead, HANDLE hWrite, SOCKET sock)
{
	char buf[2048], *p, *pend;
	DWORD nr, nw;

	winet_log(WINET_LOG_MESSAGE, "[%s] %s pump() started\n", WINET_APPNAME, pref);

	for(;;) {
		if (!ReadFile(hRead, buf, sizeof(buf), &nr, NULL)) {
			pWin32Error("ReadFile() failed");
			winet_log(WINET_LOG_ERROR, "[%s] %s ReadFile() failed\n", WINET_APPNAME, pref);
			return -1;
		}
		winet_log(WINET_LOG_MESSAGE, "[%s] %s got %d\n", WINET_APPNAME, pref, nr);
		if (nr == 0) break;
		pend = buf + nr;
		for(p = buf; p < pend; p += nw, nr -= nw) {
			winet_log(WINET_LOG_MESSAGE, "[%s] writing to %d\n", WINET_APPNAME, hWrite);
			if (!WriteFile(hWrite, p, nr, &nw, NULL)) {
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

	rc = pump(pumpparam->p2s_our, (HANDLE)pumpparam->sock, pumpparam->sock);
	if (rc != -2) {
		/* EOF or read error */
		if (SOCKET_ERROR == shutdown(pumpparam->sock, SD_SEND)) {
			pWinsockError("shutdown() failed");
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
	rc = pump((HANDLE)pumpparam->sock, pumpparam->s2p_our, pumpparam->sock);
	if (rc == -2) {
		/* write error */
		if (SOCKET_ERROR == shutdown(pumpparam->sock, SD_RECEIVE)) {
			pWinsockError("shutdown() failed");
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

static
SECURITY_ATTRIBUTES sa_inherit = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

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
	if (!CreatePipe(&s2p_their, &pumpparam->s2p_our, &sa_inherit, 0)) {
		pWin32Error("CreatePipe() failed");
		goto err1;
	}
	if (!CreatePipe(&pumpparam->p2s_our, &p2s_their, &sa_inherit, 0)) {
		pWin32Error("CreatePipe() failed");
		goto err2;
	}

	if (!DuplicateHandle(GetCurrentProcess(), p2s_their, GetCurrentProcess(),
			     err, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
		pWin32Error("DuplicateHandle() failed");
		goto err4;
	}
	///*aaa*/ { DWORD nb, dw; char buf[2048]; dw = ReadFile(pumpparam->p2s_our, buf, sizeof(buf), &nb, NULL); }

	pumpparam->sock = sock;
	if (1) {
	hthr_s2p = CreateThread(NULL, 0, thr_s2p, pumpparam, 0, &tid);
	if (!hthr_s2p) {
		pWin32Error("CreateThread() failed");
		goto err3;
	}
	CloseHandle(hthr_s2p);
	}
	*in = s2p_their;
	*out = p2s_their;
	return 0;
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