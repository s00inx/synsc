#define _GNU_SOURCE

#include "scanner.h"

#include <sys/epoll.h>
#include <sys/timerfd.h>

#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

port_info_t ports[PORT_COUNT];

// create timer fd and add to epoll interest list
int setup_timerfd(int epoll_fd) {
    int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);

    struct itimerspec ts = {
        .it_interval = {.tv_sec = 0, .tv_nsec = 20 * 1000000}, 
        .it_value = {.tv_sec = 0, .tv_nsec = 20 * 1000000}
    };
    timerfd_settime(timer_fd, 0, &ts, NULL);

    // epoll wakes up if timer is ready (for moving left bound of window)
    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.fd = timer_fd
    };

    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev);
    return timer_fd;
}

// run nonblocking scan
void run_scan(uint32_t daddr, int rx_fd, int tx_fd) {
    int epoll_fd = epoll_create1(0);

    if (epoll_fd < 0) {
        perror("failed to create epoll");
        return;
    }

    // EPOLLIN activates when rx_fd recv a packet (sock raw for all packets basically)
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = rx_fd};
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, rx_fd, &ev);
    int timer_fd = setup_timerfd(epoll_fd);

    // pointers for sliding window; 
    // next - right bound, last_unclosed - left bound, activep - window length
    int next_tosend = 1; int last_unclosed = 1; int activep = 0;
    
    // 40 bytes for tcp + ip headers
    int packet_len = get_plen();
    // buffers for recv and trasmit
    char *tx_buf = calloc(1, packet_len);
    char *rx_buf = malloc(1 << 16); // 2 bytes

    // struct for receiving epoll events
    struct epoll_event events[10];
    while (last_unclosed < PORT_COUNT) {
        // fill window with packets (until reaching MAX_WINDOW or next reaches right bound)
        while (activep < MAX_WINDOW && next_tosend < PORT_COUNT) {
            // build & send from tx.c
            buildp(tx_buf, daddr, next_tosend);
            send_packet(tx_fd, tx_buf, packet_len);

            ports[next_tosend].state = PORT_SENT;
            clock_gettime(CLOCK_MONOTONIC, &ports[next_tosend].sent_time);
            next_tosend++; activep++;
        }
        
        int nfds = epoll_wait(epoll_fd, events, 10, -1);
        for (int i = 0; i < nfds; ++i) {
            if (events[i].data.fd == rx_fd) {
                uint16_t rp = 0; // port which respont (fill in filter_packet func)
                int verdict = filter_packet(rx_buf, 1 << 16, rx_fd, daddr, SRC_PORT, &rp);

                // if filter_packet returned valid verdict
                if (verdict == PORT_CLOSED || verdict == PORT_OPEN) {
                    if (ports[rp].state == PORT_SENT) {
                    ports[rp].state = PORT_DONE; ports[rp].verdict = verdict;

                    activep--;
                    printf("port %-3d status: <%s>\n", rp, ports[rp].verdict == PORT_OPEN ? "OPEN" : "CLOSED");
                    fflush(stdout);
                    }
                }
        
            } else if (events[i].data.fd == timer_fd) {
                // reset timer (read 8 bytes)
                uint64_t rstt;
                read(timer_fd, &rstt, sizeof(rstt));

                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);

                for (int p = last_unclosed; p < next_tosend; p++) {
                    if (ports[p].state == PORT_SENT) {
                        // calculate packet timeout in ms
                        int32_t ms = (now.tv_sec - ports[p].sent_time.tv_sec) * 1000 + 
                                    (now.tv_nsec - ports[p].sent_time.tv_nsec) / 1000000;
                        // if timeout is reached -> port is filtered 
                        if (ms > TIMEOUT_MS) {
                            ports[p].state = PORT_DONE;
                            ports[p].verdict = PORT_FILTERED;
                            activep--;

                            printf("port %-3d status: <FILTERED>\n", p);
                            fflush(stdout);
                        }
                    }
                    // move left bound if it is done
                        if (p == last_unclosed && ports[p].state == PORT_DONE) {
                            last_unclosed++;
                        }
                }
            }
        }
    }

    free(rx_buf); free(tx_buf);
    close(epoll_fd); close(timer_fd);
}