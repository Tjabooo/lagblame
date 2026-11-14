// Test traffic for the VM test: a 64 Hz "game" client and an echo "server",
// each able to go quiet on cue, plus a SCHED_FIFO CPU hog.
//   udptest server PORT [PAUSE_AT_S PAUSE_MS]
//   udptest client PORT RATE SECS CPU [PAUSE_AT_S PAUSE_MS]
//   udptest hog CPU AT_S MS          (spins at SCHED_FIFO on CPU after AT_S)
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static double now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void pin(int cpu)
{
	cpu_set_t s;
	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	sched_setaffinity(0, sizeof(s), &s);
}

static void sleep_s(double s)
{
	struct timespec ts = { (time_t)s, (long)((s - (time_t)s) * 1e9) };
	nanosleep(&ts, NULL);
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return 2;
	if (!strcmp(argv[1], "hog")) {
		int cpu = atoi(argv[2]);
		double at = atof(argv[3]), ms = atof(argv[4]);
		struct sched_param p = { .sched_priority = 50 };
		pin(cpu);
		sleep_s(at);
		if (sched_setscheduler(0, SCHED_FIFO, &p))
			perror("sched_setscheduler");
		double end = now() + ms / 1000;
		while (now() < end)
			;
		return 0;
	}
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	char buf[256];
	if (!strcmp(argv[1], "server")) {
		a.sin_port = htons(atoi(argv[2]));
		double pause_at = argc > 4 ? atof(argv[3]) : -1, pause_ms = argc > 4 ? atof(argv[4]) : 0;
		bind(fd, (void *)&a, sizeof(a));
		double t0 = 0;
		for (;;) {
			struct sockaddr_in from;
			socklen_t fl = sizeof(from);
			ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (void *)&from, &fl);
			if (n <= 0)
				continue;
			if (!t0)
				t0 = now();
			double el = now() - t0;
			if (pause_at >= 0 && el >= pause_at && el < pause_at + pause_ms / 1000)
				continue; /* drop replies: the server went quiet */
			sendto(fd, buf, n, 0, (void *)&from, fl);
		}
	}
	/* client */
	a.sin_port = htons(atoi(argv[2]));
	double rate = atof(argv[3]), secs = atof(argv[4]);
	int cpu = atoi(argv[5]);
	double pause_at = argc > 7 ? atof(argv[6]) : -1, pause_ms = argc > 7 ? atof(argv[7]) : 0;
	pin(cpu);
	connect(fd, (void *)&a, sizeof(a));
	struct timeval tv = { 0, 1000 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	double t0 = now(), next = t0;
	int paused = 0;
	memset(buf, 'x', 120);
	while (now() - t0 < secs) {
		if (!paused && pause_at >= 0 && now() - t0 >= pause_at) {
			paused = 1;
			sleep_s(pause_ms / 1000); /* the "game" hitches: no CPU wait, just no sends */
			next = now();
		}
		send(fd, buf, 120, 0);
		next += 1 / rate;
		while (now() < next) {
			recv(fd, buf + 128, 128, 0);
		}
	}
	return 0;
}
