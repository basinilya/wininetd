/*
 *  WinInetd by Davide Libenzi ( Inetd-like daemon for Windows )
 *  Copyright 2013  Ilya Basin
 *  Copyright (C) 2003  Davide Libenzi
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Davide Libenzi <davidel@xmailserver.org>
 *
 */

#include <winsock2.h>
#include <windows.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <process.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "wininetd.h"



#define WINET_LOG_MESSAGE 1
#define WINET_LOG_WARNING 2
#define WINET_LOG_ERROR 3

#define MAX_PMAPS 128
#define CFGFILENAME "wininetd.conf"
#define ACCEPT_TIMEOUT 4
#define LSN_BKLOG 128



#define WINET_CHILD_FLAGS (CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW)

typedef struct s_portmap {
	SOCKET sock;
	int port;
	char *user;
	char *pass;
	char *cmdline;
} portmap_t;

typedef struct s_thread_data {
	portmap_t *pm;
	SOCKET asock;
	struct sockaddr_in saddr;
	HANDLE hPipeOurRead;
} thread_data_t;


static _TCHAR *winet_a2t(char const *str, _TCHAR *buf, int size);
static void winet_evtlog(char const *logmsg, long type);
static int winet_log(int level, char const *fmt, ...);
static int winet_load_cfg(char const *cfgfile);
static int winet_create_listeners(void);
static void winet_cleanup(void);
static char *winet_get_syserror(void);
static int winet_user_handle(portmap_t *pm, HANDLE *husr);
static _TCHAR *winet_inet_ntoa(struct in_addr addr, _TCHAR *buf, int size);
static LPVOID winet_prepare_env(portmap_t *pm, SOCKET asock, struct sockaddr_in *saddr);
unsigned int __stdcall winet_thread_proc(void *data);
static int winet_handle_client(portmap_t *pm, SOCKET asock, struct sockaddr_in *saddr);



#define CLIENT_IP _TEXT("CLIENT_IP")
#define CLIENT_PORT _TEXT("CLIENT_PORT")
static LPTCH envSnapshot;
static size_t envSnapshotNBytes;

static int npmaps = 0;
static portmap_t pmaps[MAX_PMAPS];
static int sk_timeout = -1;
static int linger_timeo = 60;
static int stopsvc;



static _TCHAR *winet_a2t(char const *str, _TCHAR *buf, int size) {

#ifdef _UNICODE
	MultiByteToWideChar(CP_ACP, 0, str, strlen(str), buf, size);
#else
	strncpy(buf, str, size);
#endif
	return buf;
}

static int _winet_log(int level, char const *emsg)
{
	printf("%s", emsg);

	if (level == WINET_LOG_ERROR)
		winet_evtlog(emsg, EVENTLOG_ERROR_TYPE);

	return 0;
}

static char *cleanstr(char *s)
{
	while(*s) {
		switch((int)*s){
			case 13:
			case 10:
			*s=' ';
			break;
		}
		s++;
	}
	return s;
}

static void __pWin32Error(int level, DWORD eNum, const char* fmt, va_list args)
{
	char emsg[1024];
	char *pend = emsg + sizeof(emsg);
	size_t count = sizeof(emsg);
	unsigned u;

	do {
		u = (unsigned)_snprintf(pend - count, count, "[%s] ", WINET_APPNAME);
		if (u >= count) break;
		count -= u;

		u = (unsigned)_vsnprintf(pend - count, count, fmt, args);
		if (u >= count) break;
		count -= u;

		u = (unsigned)_snprintf(pend - count, count, ": ");
		if (u >= count) break;
		count -= u;

		u = FormatMessageA( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
															NULL, eNum,
															MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
															pend - count, count, NULL );
		if (u == 0) {
			u = (unsigned)_snprintf(pend - count, count, "0x%08x (%d)", eNum, eNum);
		}
	} while(0);

	emsg[sizeof(emsg)-1] = '\0';
	pend = cleanstr(emsg);

	if (pend < emsg + sizeof(emsg)-1) {
		pend++;
		*pend = '\0';
	}
	pend[-1] = '\n';
	_winet_log(level, emsg);
}

void pWin32Error(char const *fmt, ...)
{
	va_list args;
	DWORD eNum = GetLastError();

	va_start(args, fmt);
	__pWin32Error(WINET_LOG_WARNING, eNum, fmt, args);
	va_end(args);
}

void pWinsockError(char const *fmt, ...)
{
	va_list args;
	DWORD eNum = WSAGetLastError();

	va_start(args, fmt);
	__pWin32Error(WINET_LOG_WARNING, eNum, fmt, args);
	va_end(args);
}

#ifdef _DEBUG
static void dbg_CloseHandle(const char *file, int line, HANDLE hObject) {
	if (!CloseHandle(hObject)) {
		pWin32Error("CloseHandle() failed at %s:%d", file, line);
	}
}
static void dbg_closesocket(const char *file, int line, SOCKET s) {
	if (closesocket(s) == SOCKET_ERROR) {
		pWinsockError("closesocket() failed at %s:%d", file, line);
	}
}
#define CloseHandle(hObject) dbg_CloseHandle(__FILE__, __LINE__, hObject)
#define closesocket(s) dbg_closesocket(__FILE__, __LINE__, s)
#endif /* _DEBUG */

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
		if (!ReadFile(hRead, buf, sizeof(buf), &nr, NULL) && GetLastError() != ERROR_BROKEN_PIPE) {
			pWin32Error("ReadFile() failed");
			return -1;
		}
		if (nr == 0) break;
		pend = buf + nr;
		for(p = buf; p < pend; p += nw, nr -= nw) {
			nw = send(sWrite, p, nr, 0);
			if (nw <= 0) {
				pWinsockError("send() failed");
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
	thread_data_t *thd = (thread_data_t *)lpThreadParameter;

	winet_log(WINET_LOG_MESSAGE, "[%s] p2s thread started\n", WINET_APPNAME);

	rc = pump_p2s(thd->hPipeOurRead, thd->asock);
	if (rc != -2) {
		/* EOF or read error */
		winet_log(WINET_LOG_MESSAGE, "[%s] p2s EOF from child\n", WINET_APPNAME);
		if (SOCKET_ERROR == shutdown(thd->asock, SD_SEND)) {
			pWinsockError("p2s shutdown(SD_SEND) failed");
		} else {
			winet_log(WINET_LOG_MESSAGE, "[%s] p2s sent EOF to client\n", WINET_APPNAME);
		}
	} else {
		winet_log(WINET_LOG_MESSAGE, "[%s] p2s write error to client\n", WINET_APPNAME);
	}
	CloseHandle(thd->hPipeOurRead);

	winet_log(WINET_LOG_MESSAGE, "[%s] p2s thread exit\n", WINET_APPNAME);

	return 0;
}

static void winet_evtlog(char const *logmsg, long type) {
	DWORD err;
	HANDLE hesrc;
	LPTSTR tmsg;
	_TCHAR lmsg[128];
	LPTSTR strs[2];
	_TCHAR wmsg[1024];

	winet_a2t(logmsg, wmsg, COUNTOF(wmsg));
	tmsg = wmsg;

	err = GetLastError();
	hesrc = RegisterEventSource(NULL, _TEXT(WINET_APPNAME));

	_stprintf(lmsg, _TEXT("%s error: 0x%08x"), _TEXT(WINET_APPNAME), err);
	strs[0] = lmsg;
	strs[1] = tmsg;

	if (hesrc != NULL) {
		ReportEvent(hesrc, (WORD) type, 0, 0, NULL, 2, 0, strs, NULL);

		DeregisterEventSource(hesrc);
	}
}


static int winet_log(int level, char const *fmt, ...) {
	va_list args;
	char emsg[1024];

	va_start(args, fmt);
	_vsnprintf(emsg, sizeof(emsg) - 1, fmt, args);
	va_end(args);

	return _winet_log(level, emsg);
}


static int winet_load_cfg(char const *cfgfile) {
	FILE *file;
	char *cmdline, *user, *pass;
	char cfgline[1024];

	if (!(file = fopen(cfgfile, "rt"))) {
		winet_log(WINET_LOG_ERROR, "[%s] unable to open config file: file='%s'\n",
			  WINET_APPNAME, cfgfile);
		return -1;
	}
	for (npmaps = 0; fgets(cfgline, sizeof(cfgline) - 1, file);) {
		cfgline[strlen(cfgline) - 1] = '\0';
		if (!isdigit(cfgline[0]))
			continue;
		pmaps[npmaps].port = atoi(cfgline);

		for (user = cfgline; isdigit(*user) || strchr(" \t", *user); user++);
		for (cmdline = user; *cmdline && !strchr(" \t", *cmdline); cmdline++);
		if (*cmdline) {
			*cmdline++ = '\0';
			for (; strchr(" \t", *cmdline); cmdline++);
			if (*cmdline) {
				if ((pass = strchr(user, ':')) != NULL)
					*pass++ = '\0';
				pmaps[npmaps].cmdline = strdup(cmdline);
				pmaps[npmaps].user = strdup(user);
				pmaps[npmaps].pass = pass ? strdup(pass): NULL;
				pmaps[npmaps].sock = -1;
				npmaps++;
			}
		}
	}

	fclose(file);

	if (!npmaps) {
		winet_log(WINET_LOG_ERROR, "[%s] empty config file: file='%s'\n",
			  WINET_APPNAME, cfgfile);
		return -1;
	}

	return 0;
}


static int winet_create_listeners(void) {
	int i, timeo;
	struct sockaddr_in saddr;
	struct linger ling;

	for (i = 0; i < npmaps; i++) {
		if ((pmaps[i].sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
			winet_log(WINET_LOG_ERROR, "[%s] unable to create socket\n",
				  WINET_APPNAME);
			return -1;
		}

		if (sk_timeout > 0) {
			timeo = sk_timeout * 1000;
			if (setsockopt(pmaps[i].sock, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeo, sizeof(timeo))) {
				winet_log(WINET_LOG_ERROR, "[%s] unable to set socket option: opt=SO_RCVTIMEO\n",
					  WINET_APPNAME);
				return -1;
			}
			timeo = sk_timeout * 1000;
			if (setsockopt(pmaps[i].sock, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeo, sizeof(timeo))) {
				winet_log(WINET_LOG_ERROR, "[%s] unable to set socket option: opt=SO_SNDTIMEO\n",
					  WINET_APPNAME);
				return -1;
			}
		}

		ling.l_onoff = 1;
		ling.l_linger = linger_timeo;
		if (setsockopt(pmaps[i].sock, SOL_SOCKET, SO_LINGER, (char *) &ling, sizeof(ling))) {
			winet_log(WINET_LOG_ERROR, "[%s] unable to set socket option: opt=SO_LINGER\n",
				  WINET_APPNAME);
			return -1;
		}

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_addr.S_un.S_addr = INADDR_ANY;
		saddr.sin_port = htons((short int) pmaps[i].port);
		saddr.sin_family = AF_INET;

		if (bind(pmaps[i].sock, (const struct sockaddr *) &saddr, sizeof(saddr))) {
			winet_log(WINET_LOG_ERROR, "[%s] unable to bind to port: port=%d\n",
				  WINET_APPNAME, pmaps[i].port);
			return -1;
		}

		listen(pmaps[i].sock, LSN_BKLOG);
	}

	return 0;
}


static void winet_cleanup(void) {
	int i;

	/* TODO: Looks like we don't wait for threads, that may use 'user','pass' or 'envSnapshot'  */

	FreeEnvironmentStrings(envSnapshot);

	for (i = 0; i < npmaps; i++) {
		closesocket(pmaps[i].sock);
		if (pmaps[i].user)
			free(pmaps[i].user);
		if (pmaps[i].pass)
			free(pmaps[i].pass);
	}
}


static char *winet_get_syserror(void) {
	int len;
	LPVOID msg;
	char *emsg;

	FormatMessage( 
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM | 
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &msg,
		0,
		NULL);

	emsg = strdup((char *) msg);

	LocalFree(msg);

	if ((len = strlen(emsg)) > 0)
		emsg[len - 1] = '\0';

	return emsg;
}


static int winet_user_handle(portmap_t *pm, HANDLE *husr) {
	HANDLE hlog;
	char *emsg;

	if (!LogonUserA(pm->user, ".", pm->pass, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &hlog)) {
		winet_log(WINET_LOG_ERROR, "[%s] unable to logon user: user='%s' pass='%s' err='%s'\n",
			  WINET_APPNAME, pm->user, pm->pass, emsg = winet_get_syserror());
		free(emsg);
		return -1;
	}
	if (!DuplicateTokenEx(hlog, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
			      TokenPrimary, husr)) {
		winet_log(WINET_LOG_ERROR, "[%s] unable duplicate token: err='%s'\n",
			  WINET_APPNAME, emsg = winet_get_syserror());
		free(emsg);
		CloseHandle(hlog);
		return -1;
	}
	CloseHandle(hlog);

	return 0;
}

static int winet_create_stdhandles(HANDLE *in, HANDLE *out, HANDLE *err, HANDLE *pPipeOurWrite, HANDLE *pPipeOurRead)
{
	HANDLE s2p_their, p2s_their;

	if (!CreatePipe(&s2p_their, pPipeOurWrite, NULL, 0)) {
		pWin32Error("CreatePipe() failed");
		return -1;
	}
	if (!CreatePipe(pPipeOurRead, &p2s_their, NULL, 0)) {
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

	return 0;
err5:
	CloseHandle(*out);
err4:
	CloseHandle(*err);
err3:
	CloseHandle(p2s_their);
	CloseHandle(*pPipeOurRead);
err2:
	CloseHandle(*pPipeOurWrite);
	CloseHandle(s2p_their);
	return -1;
}


static _TCHAR *winet_inet_ntoa(struct in_addr addr, _TCHAR *buf, int size) {
	char const *ip;

	ip = inet_ntoa(addr);

	return winet_a2t(ip, buf, size);
}

#define LONGEST_ADDR  _T("111.111.111.111")
#define LONGEST_PORT  _T("12345")

static LPVOID winet_prepare_env(portmap_t *pm, SOCKET asock, struct sockaddr_in *saddr) {
	LPTCH env;
	LPTSTR p;
	size_t newsize;

	newsize = envSnapshotNBytes
		+ sizeof( CLIENT_IP _T("=") LONGEST_ADDR _T("\0") CLIENT_PORT _T("=") LONGEST_PORT _T("\0") )
		;
	env = (LPTCH)malloc(newsize);
	if (!env) {
		winet_log(WINET_LOG_ERROR, "[%s] malloc() failed\n", WINET_APPNAME);
		return NULL;
	}
	memcpy(env, envSnapshot, envSnapshotNBytes);
	p = env + (envSnapshotNBytes/sizeof(TCHAR));

	_tcscpy(p, CLIENT_IP _T("="));
	p += COUNTOF(CLIENT_IP _T("="))-1;
	winet_inet_ntoa(saddr->sin_addr, p, COUNTOF(LONGEST_ADDR));
	p += _tcslen(p) + 1;

	_tcscpy(p, CLIENT_PORT _T("="));
	p += COUNTOF(CLIENT_PORT _T("="))-1;
	_stprintf(p, _TEXT("%d"), (int) ntohs(saddr->sin_port));
	p += _tcslen(p) + 1;

	*p = '\0';

	return env;
}


static int winet_serve_client(thread_data_t *thd) {
	portmap_t *pm = thd->pm;
	SOCKET asock = thd->asock;
	struct sockaddr_in *saddr = &thd->saddr;

	HANDLE hPipeOurWrite;
	HANDLE hthr_p2s = NULL;
	DWORD tid;
	int rc = -1;

	HANDLE husr;
	char *emsg;
	LPVOID env;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	memset(&si, 0, sizeof(si));

	if (winet_create_stdhandles(&si.hStdInput, &si.hStdOutput, &si.hStdError, &hPipeOurWrite, &thd->hPipeOurRead) < 0)
		return -1;

	hthr_p2s = CreateThread(NULL, 0, thr_p2s, thd, 0, &tid);
	if (!hthr_p2s) {
		pWin32Error("CreateThread() failed");
		CloseHandle(thd->hPipeOurRead);
		goto close_pipes_and_wait_thread;
	}

	/* now hPipeOurRead is owned by p2s thread */

	if (!(env = winet_prepare_env(pm, asock, saddr)))
		goto close_pipes_and_wait_thread;

	si.cb = sizeof(si);
	si.lpDesktop = "";
	si.dwFlags = STARTF_USESTDHANDLES;

	if (!pm->pass) {
		winet_log(WINET_LOG_MESSAGE, "[%s] socket %d\n", WINET_APPNAME, asock);
		if (!CreateProcessA(NULL, pm->cmdline, NULL, NULL, TRUE, WINET_CHILD_FLAGS, env, NULL, &si, &pi)) {
			winet_log(WINET_LOG_ERROR, "[%s] unable to create process: cmdln='%s' err='%s'\n",
				  WINET_APPNAME, pm->cmdline, emsg = winet_get_syserror());
			free(emsg);
			goto spawn_failed;
		}
		winet_log(WINET_LOG_MESSAGE, "[%s] process created: cmdln='%s'\n", WINET_APPNAME, pm->cmdline);
	} else {
		if (winet_user_handle(pm, &husr) < 0) goto spawn_failed;
		if (!ImpersonateLoggedOnUser(husr)) {
			winet_log(WINET_LOG_ERROR, "[%s] unable to impersonate user: user='%s' err='%s'\n",
				  WINET_APPNAME, pm->user, emsg = winet_get_syserror());
			free(emsg);
			CloseHandle(husr);
			goto spawn_failed;
		}
		if (!CreateProcessAsUserA(husr, NULL, pm->cmdline, NULL, NULL, TRUE, WINET_CHILD_FLAGS,
					  env, NULL, &si, &pi)) {
			winet_log(WINET_LOG_ERROR, "[%s] unable to create process as user: cmdln='%s' user='%s' err='%s'\n",
				  WINET_APPNAME, pm->cmdline, pm->user, emsg = winet_get_syserror());
			free(emsg);
			RevertToSelf();
			CloseHandle(husr);
			goto spawn_failed;
		}
		RevertToSelf();
		CloseHandle(husr);
		winet_log(WINET_LOG_MESSAGE, "[%s] process created: user='%s' cmdln='%s'\n", WINET_APPNAME, pm->user, pm->cmdline);
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	rc = 0;

spawn_failed:
	free(env);

close_pipes_and_wait_thread:
	/* Close our copies of std handles */
	CloseHandle(si.hStdError);
	CloseHandle(si.hStdOutput);
	CloseHandle(si.hStdInput);

	if (rc == 0) {
		if (pump_s2p(thd->asock, hPipeOurWrite) == -2) {
			/* write error */
			winet_log(WINET_LOG_MESSAGE, "[%s] s2p write error to child\n", WINET_APPNAME);
			if (SOCKET_ERROR == shutdown(thd->asock, SD_RECEIVE)) {
				pWinsockError("s2p shutdown(SD_RECEIVE) failed");
			} else {
				winet_log(WINET_LOG_MESSAGE, "[%s] s2p shutdown(SD_RECEIVE) ok\n", WINET_APPNAME);
			}
		} else {
			winet_log(WINET_LOG_MESSAGE, "[%s] s2p EOF from client\n", WINET_APPNAME);
		}
	}

	CloseHandle(hPipeOurWrite);
	winet_log(WINET_LOG_MESSAGE, "[%s] s2p sent EOF to child\n", WINET_APPNAME);

	if (hthr_p2s) {
		WaitForSingleObject(hthr_p2s, INFINITE);
		CloseHandle(hthr_p2s);
	}

	return rc;
}


unsigned int __stdcall winet_thread_proc(void *data) {
	thread_data_t *thd = (thread_data_t *) data;

	winet_serve_client(thd);

	closesocket(thd->asock);
	free(thd);
	return 0;
}


static int winet_handle_client(portmap_t *pm, SOCKET asock, struct sockaddr_in *saddr) {
	unsigned int thrid;
	HANDLE hthr;
	thread_data_t *thd;

	if (!(thd = (thread_data_t *) malloc(sizeof(thread_data_t))))
		return -1;

	thd->pm = pm;
	thd->asock = asock;
	thd->saddr = *saddr;

	if (!(hthr = (HANDLE) _beginthreadex(NULL, 0, winet_thread_proc, thd, 0, &thrid))) {
		free(thd);
		return -1;
	}
	CloseHandle(hthr);

	return 0;
}


int winet_stop_service(void) {

	stopsvc++;
	return 0;
}


int winet_main(int argc, char const **argv) {
	int i, selres, adrlen;
	SOCKET asock;
	char const *cfgfile = NULL;
	WSADATA WD;
	fd_set lsnset;
	struct timeval tmo;
	struct sockaddr_in saddr;
	char cfgpath[MAX_PATH];
	LPTSTR lpszVariable;
	int rc = 1;

	npmaps = 0;
	sk_timeout = -1;
	stopsvc = 0;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--cfgfile")) {
			if (++i < argc)
				cfgfile = argv[i];
		} else if (!strcmp(argv[i], "--timeout")) {
			if (++i < argc)
				sk_timeout = atoi(argv[i]);
		} else if (!strcmp(argv[i], "--linger-timeout")) {
			if (++i < argc)
				linger_timeo = atoi(argv[i]);
		}

	}
	if (!cfgfile) {
		i = (int) GetWindowsDirectoryA(cfgpath, sizeof(cfgpath) - sizeof(CFGFILENAME) - 1);
		if (cfgpath[i - 1] != '\\')
			strcat(cfgpath, "\\");
		strcat(cfgpath, CFGFILENAME);
		cfgfile = cfgpath;
	}

	if (WSAStartup(MAKEWORD(2, 0), &WD)) {
		winet_log(WINET_LOG_ERROR, "[%s] unable to initialize socket layer\n",
			  WINET_APPNAME);
		return 1;
	}

	if (winet_load_cfg(cfgfile) < 0 ||
	    winet_create_listeners() < 0) {
		WSACleanup();
		return 2;
	}

	/* init env */
	SetEnvironmentVariable(CLIENT_IP, NULL);
	SetEnvironmentVariable(CLIENT_PORT, NULL);
	if (!(envSnapshot = GetEnvironmentStrings())) {
		pWin32Error("GetEnvironmentStrings() failed");
		goto cleanup;
	}
	lpszVariable = envSnapshot;
	while (*lpszVariable)
	{
		lpszVariable += lstrlen(lpszVariable) + 1;
	}
	envSnapshotNBytes = (lpszVariable - envSnapshot)*sizeof(TCHAR);

	rc = 0;
	for (; !stopsvc;) {
		FD_ZERO(&lsnset);
		for (i = 0; i < npmaps; i++)
			FD_SET(pmaps[i].sock, &lsnset);

		tmo.tv_sec = ACCEPT_TIMEOUT;
		tmo.tv_usec = 0;
		if (!(selres = select(0, &lsnset, NULL, NULL, &tmo))) {

			continue;
		}
		if (selres < 0) {
			winet_log(WINET_LOG_WARNING, "[%s] select error\n", WINET_APPNAME);
			continue;
		}
		for (i = 0; i < npmaps; i++) {
			if (!FD_ISSET(pmaps[i].sock, &lsnset))
				continue;

			adrlen = sizeof(saddr);
			if ((asock = accept(pmaps[i].sock, (struct sockaddr *) &saddr,
					    &adrlen)) != INVALID_SOCKET) {
				if (winet_handle_client(&pmaps[i], asock, &saddr) < 0) {

					winet_log(WINET_LOG_ERROR, "[%s] unable to serve client: %s:%d\n",
						  WINET_APPNAME, inet_ntoa(saddr.sin_addr), (int) ntohs(saddr.sin_port));

					closesocket(asock);
				} else {

					winet_log(WINET_LOG_MESSAGE, "[%s] client served: %s:%d -> '%s'\n",
						  WINET_APPNAME, inet_ntoa(saddr.sin_addr), (int) ntohs(saddr.sin_port),
						  pmaps[i].cmdline);

				}
			}
		}
	}

cleanup:
	winet_cleanup();
	WSACleanup();

	return rc;
}

